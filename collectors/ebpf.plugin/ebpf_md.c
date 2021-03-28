// SPDX-License-Identifier: GPL-3.0-or-later

#include "ebpf.h"
#include "ebpf_md.h"

static char *md_dimension_name[NETDATA_MD_END] = { "md_flush_request" };
static netdata_syscall_stat_t md_aggregated_data;
static netdata_publish_syscall_t md_publish_aggregated;

static ebpf_data_t md_data;
static struct bpf_link **probe_links = NULL;
static struct bpf_object *objects = NULL;

static netdata_idx_t md_hash_values[NETDATA_MD_END];

uint64_t *md_vector = NULL;

struct config md_config = { .first_section = NULL,
    .last_section = NULL,
    .mutex = NETDATA_MUTEX_INITIALIZER,
    .index = { .avl_tree = { .root = NULL, .compar = appconfig_section_compare },
        .rwlock = AVL_LOCK_INITIALIZER } };

static int read_thread_closed = 1;
static int *map_fd = NULL;

struct netdata_static_thread md_threads = {"MD KERNEL",
                                                  NULL, NULL, 1, NULL,
                                                  NULL,  NULL};

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

    ebpf_cleanup_publish_syscall(&md_publish_aggregated);

    freez(md_vector);

    struct bpf_program *prog;
    size_t i = 0 ;
    bpf_object__for_each_program(prog, objects) {
        bpf_link__destroy(probe_links[i]);
        i++;
    }
    bpf_object__close(objects);
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
    uint32_t idx;
    netdata_idx_t *val = md_hash_values;
    uint64_t *stored = md_vector;
    int fd = map_fd[NETDATA_MD_GLOBAL_TABLE];

    if (!bpf_map_lookup_elem(fd, &idx, &stored)) {
        uint64_t  total = 0;
        int i, end = (running_on_kernel >= NETDATA_KERNEL_V4_15) ? ebpf_nprocs : 1;
        for (i = 0; i < end; i++) {
            total += stored[i];
        }
        val[NETDATA_KEY_MD_CALL] = total;
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
void *ebpf_md_read_hash(void *ptr)
{
    read_thread_closed = 0;

    heartbeat_t hb;
    heartbeat_init(&hb);

    ebpf_module_t *em = (ebpf_module_t *)ptr;
    usec_t step = NETDATA_MD_SLEEP_MS * em->update_time;
    while (!close_ebpf_plugin) {
        usec_t dt = heartbeat_next(&hb, step);
        (void)dt;

        read_global_table();
    }

    read_thread_closed = 1;

    return NULL;
}

/**
 * Write charts
 *
 * Write the current information to publish the charts.
 *
 * @param family chart family
 * @param chart  chart id
 * @param dim    dimension name
 * @param v1     value.
 */
static inline void md_write_charts(char *family, char *chart, char *dim, long long v1)
{
    write_begin_chart(family, chart);

    write_chart_dimension(dim, v1);

    write_end_chart();
}

/**
 * Send global
 *
 * Send global charts to Netdata
 */
static void md_send_global()
{
    md_write_charts(NETDATA_EBPF_RAID_GROUP, NETDATA_MD_FLUSH_CHART,
                    md_dimension_name[NETDATA_KEY_MD_CALL], md_hash_values[NETDATA_KEY_MD_CALL]);
}

/**
* Main loop for this collector.
*/
static void md_collector(ebpf_module_t *em)
{
    md_threads.thread = mallocz(sizeof(netdata_thread_t));
    md_threads.start_routine = ebpf_md_read_hash;

    map_fd = md_data.map_fd;
    md_hash_values[NETDATA_KEY_MD_CALL] = 0;

    netdata_thread_create(md_threads.thread, md_threads.name, NETDATA_THREAD_OPTION_JOINABLE,
                          ebpf_md_read_hash, em);

    while (!close_ebpf_plugin) {
        pthread_mutex_lock(&collect_data_mutex);
        pthread_cond_wait(&collect_data_cond_var, &collect_data_mutex);

        pthread_mutex_lock(&lock);

        md_send_global();

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
 * Create global charts
 *
 * Call ebpf_create_chart to create the charts for the collector.
 */
static void ebpf_create_md_charts()
{
    ebpf_create_chart(NETDATA_EBPF_RAID_GROUP, NETDATA_MD_FLUSH_CHART,
                      "Calls per second for <code>md_flush_request()</code>.",
                      EBPF_COMMON_DIMENSION_CALL, NETDATA_FLUSH_SUBMENU,
                      NULL,
                      NETDATA_EBPF_CHART_TYPE_LINE,
                      21200,
                      ebpf_create_global_dimension,
                      &md_publish_aggregated, 1);
}

/*****************************************************************
 *
 *  MAIN THREAD
 *
 *****************************************************************/

/**
 * Allocate vectors used with this thread.
 *
 * We are not testing the return, because callocz does this and shutdown the software
 * case it was not possible to allocate.
 */
static void ebpf_md_allocate_global_vectors()
{
    md_vector = callocz((size_t)ebpf_nprocs, sizeof(uint64_t));
}

/**
 * Cachestat thread
 *
 * Thread used to make cachestat thread
 *
 * @param ptr a pointer to `struct ebpf_module`
 *
 * @return It always return NULL
 */
void *ebpf_md_thread(void *ptr)
{
    netdata_thread_cleanup_push(ebpf_md_cleanup, ptr);

    ebpf_module_t *em = (ebpf_module_t *)ptr;
    fill_ebpf_data(&md_data);

    ebpf_load_config_update_module(em, &md_config, NETDATA_MD_CONFIG_FILE);

    if (!em->enabled)
        goto endmd;

    if (ebpf_update_kernel(&md_data)) {
        pthread_mutex_unlock(&lock);
        goto endmd;
    }

    probe_links = ebpf_load_program(ebpf_plugin_dir, em, kernel_string, &objects, md_data.map_fd);
    if (!probe_links) {
        pthread_mutex_unlock(&lock);
        goto endmd;
    }

    ebpf_md_allocate_global_vectors();

    int algorithm = NETDATA_EBPF_INCREMENTAL_IDX;
    ebpf_global_labels(&md_aggregated_data, &md_publish_aggregated, md_dimension_name, md_dimension_name,
                       &algorithm, NETDATA_MD_END);

    pthread_mutex_lock(&lock);

    ebpf_create_md_charts();

    pthread_mutex_unlock(&lock);

    md_collector(em);

endmd:
    netdata_thread_cleanup_pop(1);
    return NULL;
}
