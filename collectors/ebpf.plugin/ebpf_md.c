
// SPDX-License-Identifier: GPL-3.0-or-later

#include "ebpf.h"
#include "ebpf_md.h"

static ebpf_local_maps_t md_maps[] = {{.name = "tbl_md", .internal_input = NETDATA_MD_END,
                                       .user_input = 0, .type = NETDATA_EBPF_MAP_STATIC,
                                       .map_fd = ND_EBPF_MAP_FD_NOT_INITIALIZED},
                                      {.name = NULL, .internal_input = 0, .user_input = 0,
                                       .type = NETDATA_EBPF_MAP_CONTROLLER,
                                       .map_fd = ND_EBPF_MAP_FD_NOT_INITIALIZED}};

static ebpf_data_t md_data;

static struct bpf_link **probe_links = NULL;
static struct bpf_object *objects = NULL;

struct config md_config = { .first_section = NULL,
    .last_section = NULL,
    .mutex = NETDATA_MUTEX_INITIALIZER,
    .index = { .avl_tree = { .root = NULL, .compar = appconfig_section_compare },
        .rwlock = AVL_LOCK_INITIALIZER } };

static char *md_dimension_name[NETDATA_MD_END] = { "flush" };
static netdata_syscall_stat_t md_aggregated_data[NETDATA_MD_END];
static netdata_publish_syscall_t md_publish_aggregated[NETDATA_MD_END];

struct netdata_static_thread md_threads = {"MD KERNEL",
                                              NULL, NULL, 1, NULL,
                                              NULL,  NULL};

static int read_thread_closed = 1;

static uint64_t chart_value = 0;
static uint64_t *md_values = NULL;

/*****************************************************************
 *
 *  FUNCTIONS TO CLOSE THE THREAD
 *
 *****************************************************************/

/**
 * Clean up the main thread.
 *
 * @param ptr thread data.
 */
static void ebpf_md_cleanup(void *ptr)
{
    ebpf_module_t *em = (ebpf_module_t *)ptr;
    if (!em->enabled)
        return;

    freez(md_values);
    freez(md_threads.thread);

    if (probe_links) {
        struct bpf_program *prog;
        size_t i = 0 ;
        bpf_object__for_each_program(prog, objects) {
            bpf_link__destroy(probe_links[i]);
            i++;
        }
        bpf_object__close(objects);
    }
}

/*****************************************************************
 *
 *  MAIN LOOP
 *
 *****************************************************************/

/**
 * Read global table
 *
 * Read the table with number of calls for all functions
 */
static void read_global_table()
{
    uint32_t idx;
    netdata_idx_t *stored = md_values;
    int fd = md_maps[NETDATA_KEY_MD_TABLE].map_fd;

    for (idx = NETDATA_KEY_MOUNT_CALL; idx < NETDATA_MOUNT_END; idx++) {
        if (!bpf_map_lookup_elem(fd, &idx, stored)) {
            int i;
            int end = ebpf_nprocs;
            netdata_idx_t total = 0;
            for (i = 0; i < end; i++)
                total += stored[i];

            chart_value = total;
        }
    }
}
/**
 * Mount read hash
 *
 * This is the thread callback.
 * This thread is necessary, because we cannot freeze the whole plugin to read the data.
 *
 * @param ptr It is a NULL value for this thread.
 *
 * @return It always returns NULL.
 */
void *ebpf_md_read_hash(void *ptr)
{
    read_thread_closed = 0;

    heartbeat_t hb;
    heartbeat_init(&hb);

    ebpf_module_t *em = (ebpf_module_t *)ptr;

    usec_t step = NETDATA_LATENCY_MD_SLEEP_MS * em->update_time;
    while (!close_ebpf_plugin) {
        usec_t dt = heartbeat_next(&hb, step);
        (void)dt;

        read_global_table();
    }
    read_thread_closed = 1;

    return NULL;
}

/**
 * Send data to Netdata calling auxiliar functions.
 *
 * @param em the structure with thread information
*/
static void ebpf_md_send_data()
{
    md_publish_aggregated[0].ncall = chart_value;

    write_count_chart(NETDATA_EBPF_MD_CALLS, NETDATA_EBPF_MDSTAT_FAMILY,
                      md_publish_aggregated, NETDATA_MD_END);
}

/**
* Main loop for this collector.
*/
static void md_collector(ebpf_module_t *em)
{
    md_threads.thread = mallocz(sizeof(netdata_thread_t));
    md_threads.start_routine = ebpf_md_read_hash;

    md_values = callocz((size_t)ebpf_nprocs, sizeof(netdata_idx_t));

    netdata_thread_create(md_threads.thread, md_threads.name, NETDATA_THREAD_OPTION_JOINABLE,
                          ebpf_md_read_hash, em);

    while (!close_ebpf_plugin) {
        pthread_mutex_lock(&collect_data_mutex);
        pthread_cond_wait(&collect_data_cond_var, &collect_data_mutex);

        pthread_mutex_lock(&lock);

        ebpf_md_send_data();

        pthread_mutex_unlock(&lock);
        pthread_mutex_unlock(&collect_data_mutex);
    }
}

/*****************************************************************
 *
 *  INITIALIZE THREAD
 *
 *****************************************************************/

/**
 * Create mount charts
 *
 * Call ebpf_create_chart to create the charts for the collector.
 */
static void ebpf_create_md_charts()
{
    ebpf_create_chart(NETDATA_EBPF_MDSTAT_FAMILY, NETDATA_EBPF_MD_CALLS,
                      "Calls to md_flush_request.",
                      EBPF_COMMON_DIMENSION_CALL, NETDATA_EBPF_MDSTAT_FAMILY,
                      NULL,
                      NETDATA_EBPF_CHART_TYPE_LINE,
                      NETDATA_CHART_PRIO_MDSTAT_EBPF,
                      ebpf_create_global_dimension,
                      md_publish_aggregated, NETDATA_EBPF_MOUNT_SYSCALL);
}

/*****************************************************************
 *
 *  MAIN THREAD
 *
 *****************************************************************/

/**
 * Directory Cache thread
 *
 * Thread used to make dcstat thread
 *
 * @param ptr a pointer to `struct ebpf_module`
 *
 * @return It always returns NULL
 */
void *ebpf_md_thread(void *ptr)
{
    netdata_thread_cleanup_push(ebpf_md_cleanup, ptr);

    ebpf_module_t *em = (ebpf_module_t *)ptr;
    em->maps = md_maps;
    fill_ebpf_data(&md_data);

    if (!em->enabled)
        goto endmd;

    probe_links = ebpf_load_program(ebpf_plugin_dir, em, kernel_string, &objects, md_data.map_fd);
    if (!probe_links) {
        goto endmd;
    }

    int algorithms[NETDATA_MD_END] = { NETDATA_EBPF_INCREMENTAL_IDX };

    ebpf_global_labels(md_aggregated_data, md_publish_aggregated, md_dimension_name, md_dimension_name,
                       algorithms, NETDATA_MD_END);

    pthread_mutex_lock(&lock);
    ebpf_create_md_charts();
    pthread_mutex_unlock(&lock);

    md_collector(em);

endmd:
    netdata_thread_cleanup_pop(1);
    return NULL;
}
