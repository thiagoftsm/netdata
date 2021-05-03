// SPDX-License-Identifier: GPL-3.0-or-later

#include "ebpf.h"
#include "ebpf_swap.h"

static ebpf_data_t swap_data;
static struct bpf_link **probe_links = NULL;
static struct bpf_object *objects = NULL;

static char *swap_dimension_name[NETDATA_SWAP_END] = { "write", "read" };
static netdata_syscall_stat_t swap_aggregated_data[NETDATA_SWAP_END];
static netdata_publish_syscall_t swap_publish_aggregated[NETDATA_SWAP_END];

static netdata_idx_t swap_hash_values[NETDATA_SWAP_END];

netdata_publish_swap_t **swap_pid = NULL;
netdata_publish_swap_t *swap_vector = NULL;

static int read_thread_closed = 1;
static int *map_fd = NULL;

struct config swap_config = { .first_section = NULL,
    .last_section = NULL,
    .mutex = NETDATA_MUTEX_INITIALIZER,
    .index = { .avl_tree = { .root = NULL, .compar = appconfig_section_compare },
        .rwlock = AVL_LOCK_INITIALIZER } };

struct netdata_static_thread swap_threads = {"SWAP KERNEL",
                                                  NULL, NULL, 1, NULL,
                                                  NULL,  NULL};

/*****************************************************************
 *
 *  FUNCTIONS TO CLOSE THE THREAD
 *
 *****************************************************************/

/**
 * Clean swap strcuture
 */
void clean_swap_pid_structures() {
    struct pid_stat *pids = root_of_pids;
    while (pids) {
        freez(swap_pid[pids->pid]);

        pids = pids->next;
    }
}

/**
 * Clean up the main thread.
 *
 * @param ptr thread data.
 */
static void ebpf_swap_cleanup(void *ptr)
{
    ebpf_module_t *em = (ebpf_module_t *)ptr;
    if (!em->enabled)
        return;

    heartbeat_t hb;
    heartbeat_init(&hb);
    uint32_t tick = 2*USEC_PER_MS;
    while (!read_thread_closed) {
        usec_t dt = heartbeat_next(&hb, tick);
        UNUSED(dt);
    }

    ebpf_cleanup_publish_syscall(swap_publish_aggregated);

    freez(swap_vector);

    struct bpf_program *prog;
    size_t i = 0 ;
    bpf_object__for_each_program(prog, objects) {
        bpf_link__destroy(probe_links[i]);
        i++;
    }
    bpf_object__close(objects);
}

/**
 * Create apps charts
 *
 * Call ebpf_create_chart to create the charts on apps submenu.
 *
 * @param em a pointer to the structure with the default values.
 */
void ebpf_swap_create_apps_charts(struct ebpf_module *em, void *ptr)
{
    UNUSED(em);

    struct target *root = ptr;
    ebpf_create_charts_on_apps(NETDATA_MEM_SWAP_READ_CHART,
                               NULL,
                               EBPF_COMMON_DIMENSION_CALL,
                               NETDATA_SWAP_SUBMENU,
                               NETDATA_EBPF_CHART_TYPE_STACKED,
                               20191,
                               ebpf_algorithms[NETDATA_EBPF_INCREMENTAL_IDX],
                               root);

    ebpf_create_charts_on_apps(NETDATA_MEM_SWAP_WRITE_CHART,
                               NULL,
                               EBPF_COMMON_DIMENSION_CALL,
                               NETDATA_SWAP_SUBMENU,
                               NETDATA_EBPF_CHART_TYPE_STACKED,
                               20192,
                               ebpf_algorithms[NETDATA_EBPF_INCREMENTAL_IDX],
                               root);
}

/*****************************************************************
 *
 *  COLLECTOR THREAD
 *
 *****************************************************************/

/**
 * Read global counter
 *
 * Read the table with number of calls for all functions
 */
static void read_global_table()
{
    uint64_t stored;
    netdata_idx_t *val = swap_hash_values;
    int fd = map_fd[NETDATA_SWAP_GLOBAL_TABLE];

    uint32_t i, end = NETDATA_SWAP_END;
    for (i = NETDATA_KEY_SWAP_READPAGE_CALL; i < end; i++) {
        if (!bpf_map_lookup_elem(fd, &i, &stored)) {
            val[i] = stored;
        }
    }
}

/**
 * Apps Accumulator
 *
 * Sum all values read from kernel and store in the first address.
 *
 * @param out the vector with read values.
 */
static void swap_apps_accumulator(netdata_publish_swap_t *out)
{
    int i, end = (running_on_kernel >= NETDATA_KERNEL_V4_15) ? ebpf_nprocs : 1;
    netdata_publish_swap_t *total = &out[0];
    for (i = 1; i < end; i++) {
        netdata_publish_swap_t *w = &out[i];
        total->read += w->read;
        total->write += w->write;
    }
}

/**
 * Fill PID
 *
 * Fill PID structures
 *
 * @param current_pid pid that we are collecting data
 * @param out         values read from hash tables;
 */
static void swap_fill_pid(uint32_t current_pid, netdata_publish_swap_t *publish)
{
    netdata_publish_swap_t *curr = swap_pid[current_pid];
    if (!curr) {
        curr = callocz(1, sizeof(netdata_publish_swap_t));
        swap_pid[current_pid] = curr;
    }

    memcpy(curr, publish, sizeof(netdata_publish_swap_t));
}

/**
 * Read APPS table
 *
 * Read the apps table and store data inside the structure.
 */
static void read_apps_table()
{
    netdata_publish_swap_t *cv = swap_vector;
    uint32_t key;
    struct pid_stat *pids = root_of_pids;
    int fd = map_fd[NETDATA_PID_SWAP_TABLE];
    size_t length = sizeof(netdata_publish_swap_t)*ebpf_nprocs;
    while (pids) {
        key = pids->pid;

        if (bpf_map_lookup_elem(fd, &key, cv)) {
            pids = pids->next;
            continue;
        }

        swap_apps_accumulator(cv);

        swap_fill_pid(key, cv);

        // We are cleaning to avoid passing data read from one process to other.
        memset(cv, 0, length);

        pids = pids->next;
    }
}

/**
 * Socket read hash
 *
 * This is the thread callback.
 * This thread is necessary, because we cannot freeze the whole plugin to read the data on very busy socket.
 *
 * @param ptr It is a NULL value for this thread.
 *
 * @return It always returns NULL.
 */
void *ebpf_swap_read_hash(void *ptr)
{
    read_thread_closed = 0;

    heartbeat_t hb;
    heartbeat_init(&hb);

    ebpf_module_t *em = (ebpf_module_t *)ptr;
    usec_t step = NETDATA_MD_SLEEP_MS * em->update_time;
    int apps = em->apps_charts;
    while (!close_ebpf_plugin) {
        usec_t dt = heartbeat_next(&hb, step);
        (void)dt;

        read_global_table();

        if (apps)
            read_apps_table();
    }

    read_thread_closed = 1;
    return NULL;
}

/**
 * Send global
 *
 * Send global charts to Netdata
 */
static void swap_send_global()
{
    write_io_chart(NETDATA_MEM_SWAP_CHART, NETDATA_EBPF_SYSTEM_GROUP,
                   swap_publish_aggregated[NETDATA_KEY_SWAP_WRITEPAGE_CALL].dimension,
                   swap_hash_values[NETDATA_KEY_SWAP_WRITEPAGE_CALL],
                   swap_publish_aggregated[NETDATA_KEY_SWAP_READPAGE_CALL].dimension,
                   swap_hash_values[NETDATA_KEY_SWAP_READPAGE_CALL]);
}


/**
 * Sum values for pid
 *
 * @param root the structure with all available PIDs
 *
 * @param offset the address that we are reading
 *
 * @return it returns the sum of all PIDs
 */
long long ebpf_swap_sum_values_for_pids(struct pid_on_target *root, size_t offset)
{
    long long ret = 0;
    while (root) {
        int32_t pid = root->pid;
        netdata_publish_swap_t *w = swap_pid[pid];
        if (w) {
            ret += get_value_from_structure((char *)w, offset);
        }

        root = root->next;
    }

    return ret;
}

/**
 * Send data to Netdata calling auxiliar functions.
 *
 * @param root the target list.
*/
void ebpf_swap_send_apps_data(struct target *root)
{
    struct target *w;
    collected_number value;

    write_begin_chart(NETDATA_APPS_FAMILY, NETDATA_MEM_SWAP_READ_CHART);
    for (w = root; w; w = w->next) {
        if (unlikely(w->exposed && w->processes)) {
            value = (collected_number) ebpf_swap_sum_values_for_pids(w->root_pid, offsetof(netdata_publish_swap_t, read));
            write_chart_dimension(w->name, value);
        }
    }
    write_end_chart();

    write_begin_chart(NETDATA_APPS_FAMILY, NETDATA_MEM_SWAP_WRITE_CHART);
    for (w = root; w; w = w->next) {
        if (unlikely(w->exposed && w->processes)) {
            value = (collected_number) ebpf_swap_sum_values_for_pids(w->root_pid, offsetof(netdata_publish_swap_t, write));
            write_chart_dimension(w->name, value);
        }
    }
    write_end_chart();
}

/**
* Main loop for this collector.
*/
static void swap_collector(ebpf_module_t *em)
{
    swap_threads.thread = mallocz(sizeof(netdata_thread_t));
    swap_threads.start_routine = ebpf_swap_read_hash;

    map_fd = swap_data.map_fd;

    netdata_thread_create(swap_threads.thread, swap_threads.name, NETDATA_THREAD_OPTION_JOINABLE,
                          ebpf_swap_read_hash, em);

    int apps = em->apps_charts;
    while (!close_ebpf_plugin) {
        pthread_mutex_lock(&collect_data_mutex);
        pthread_cond_wait(&collect_data_cond_var, &collect_data_mutex);

        pthread_mutex_lock(&lock);

        swap_send_global();

        if (apps)
            ebpf_swap_send_apps_data(apps_groups_root_target);

        pthread_mutex_unlock(&lock);
        pthread_mutex_unlock(&collect_data_mutex);
    }
}

/*****************************************************************
 *
 *  MAIN THREAD
 *
 *****************************************************************/

/**
 * Create global charts
 *
 * Call ebpf_create_chart to create the charts for the collector.
 */
static void ebpf_create_swap_charts()
{
    ebpf_create_chart(NETDATA_EBPF_SYSTEM_GROUP, NETDATA_MEM_SWAP_CHART,
                      "Calls for swap internal functions.",
                      EBPF_COMMON_DIMENSION_CALL, NETDATA_SYSTEM_SWAP_SUBMENU,
                      NULL,
                      NETDATA_EBPF_CHART_TYPE_LINE,
                      202,
                      ebpf_create_global_dimension,
                      swap_publish_aggregated, NETDATA_SWAP_END);
}

/**
 * Allocate vectors used with this thread.
 *
 * We are not testing the return, because callocz does this and shutdown the software
 * case it was not possible to allocate.
 *
 * @param length is the length for the vectors used inside the collector.
 */
static void ebpf_swap_allocate_global_vectors()
{
    swap_pid = callocz((size_t)pid_max, sizeof(netdata_publish_swap_t *));
    swap_vector = callocz((size_t)ebpf_nprocs, sizeof(netdata_publish_swap_t));

    memset(swap_hash_values, 0, sizeof(swap_hash_values));
}

/**
 * SWAP thread
 *
 * Thread used to make swap thread
 *
 * @param ptr a pointer to `struct ebpf_module`
 *
 * @return It always return NULL
 */
void *ebpf_swap_thread(void *ptr)
{
    netdata_thread_cleanup_push(ebpf_swap_cleanup, ptr);

    ebpf_module_t *em = (ebpf_module_t *)ptr;
    fill_ebpf_data(&swap_data);

    ebpf_update_module(em, &swap_config, NETDATA_SWAP_CONFIG_FILE);

    if (!em->enabled)
        goto endswap;

    if (ebpf_update_kernel(&swap_data)) {
        pthread_mutex_unlock(&lock);
        goto endswap;
    }

    probe_links = ebpf_load_program(ebpf_plugin_dir, em, kernel_string, &objects, swap_data.map_fd);
    if (!probe_links) {
        pthread_mutex_unlock(&lock);
        goto endswap;
    }

    ebpf_swap_allocate_global_vectors();

    int algorithms[NETDATA_SWAP_END] = { NETDATA_EBPF_INCREMENTAL_IDX, NETDATA_EBPF_INCREMENTAL_IDX};
    ebpf_global_labels(swap_aggregated_data, swap_publish_aggregated, swap_dimension_name, swap_dimension_name,
                       algorithms, NETDATA_SWAP_END);

    pthread_mutex_lock(&lock);
    ebpf_create_swap_charts();
    pthread_mutex_unlock(&lock);

    swap_collector(em);

endswap:
    netdata_thread_cleanup_pop(1);
    return NULL;
}
