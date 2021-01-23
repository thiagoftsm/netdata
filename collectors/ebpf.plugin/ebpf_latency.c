// SPDX-License-Identifier: GPL-3.0-or-later

#include <sys/resource.h>

#include "ebpf.h"
#include "ebpf_latency.h"

static char *latency_counter_dimension_name[NETDATA_LATENCY_COUNTER] = { "runnable", "first", "end",
                                                                         "startIO", "completeIO" };
static char *latency_counter_id_names[NETDATA_LATENCY_COUNTER] = { "ttwu_do_wakeup", "wake_up_new_task",
                                                                   "finish_task_switch", "block_rq_issue",
                                                                   "block_rq_complete" };

static netdata_idx_t *latency_hash_values = NULL;

static ebpf_data_t latency_data;

static netdata_syscall_stat_t *latency_counter_aggregated_data = NULL;
static netdata_publish_syscall_t *latency_counter_publish_aggregated = NULL;

static char *latency_hist_dimensions[NETDATA_LATENCY_HIST_BINS] = { };
static netdata_syscall_stat_t *latency_hist_aggregated_data = NULL;
static netdata_publish_syscall_t *latency_hist_publish_aggregated = NULL;

static struct bpf_link **probe_links = NULL;
static struct bpf_object *objects = NULL;

static struct netdata_hist_per_core *schedule_core = NULL;

static int *map_fd = NULL;
static int read_thread_closed = 1;

/*****************************************************************
 *
 *  FUNCTIONS WITH THE MAIN LOOP
 *
 *****************************************************************/

/**
 * Read CPU table
 *
 * Read the table with number of calls for all functions
 */
static void read_cpu_table()
{
    uint64_t idx;
    netdata_idx_t *val = latency_hash_values;
    int fd = map_fd[NETDATA_LATENCY_CPU_STATS];

    int end = (running_on_kernel < NETDATA_KERNEL_V4_15) ? 1 : ebpf_nprocs;
    for (idx = 0; idx < NETDATA_LATENCY_HIST_BINS; idx++) {
        if (!bpf_map_lookup_elem(fd, &idx, val)) {
            int i;
            struct netdata_hist_per_core *sc = schedule_core;
            for (i = 0; i < end; i++) {
                sc[i].histogram[idx] = val[i];
            }
        }
    }
}

/**
 * Read global counter
 *
 * Read the table with number of calls for all functions
 */
static void read_global_table()
{
    uint64_t idx;
    netdata_idx_t *val = latency_hash_values;
    int fd = map_fd[NETDATA_LATENCY_GLOBAL_STATS];

    netdata_publish_syscall_t *lc ;
    for (idx = 0, lc = latency_counter_publish_aggregated; lc; idx++, lc = lc->next) {
        uint64_t total = 0;
        if (!bpf_map_lookup_elem(fd, &idx, val)) {
            int i;
            int end = (running_on_kernel < NETDATA_KERNEL_V4_15) ? 1 : ebpf_nprocs;
            for (i = 0; i < end; i++)
                total += val[i];
        }

        lc->ncall = total;
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
void *ebpf_latency_read_hash(void *ptr)
{
    heartbeat_t hb;
    ebpf_module_t *em = (ebpf_module_t *)ptr;

    read_thread_closed = 0;
    heartbeat_init(&hb);
    usec_t step = NETDATA_LATENCY_READ_SLEEP_MS;
    int apps = em->apps_charts;
    while (!close_ebpf_plugin) {
        usec_t dt = heartbeat_next(&hb, step);
        (void)dt;

        read_global_table();
        read_cpu_table();

        if(apps && !close_ebpf_plugin)
            (void)dt;
    }

    read_thread_closed = 1;
    return NULL;
}

struct netdata_static_thread latency_threads = {"LATENCY KERNEL",
                                                NULL, NULL, 1, NULL,
                                                NULL, ebpf_latency_read_hash };

/**
 * Call the necessary functions to create a chart.
 *
 *
 * @return It returns a variable tha maps the charts that did not have zero values.
 */
void write_histogram_chart(struct netdata_hist_per_core *values, uint32_t end)
{
    write_begin_chart(values->family, values->chart);
    uint32_t i;
    netdata_idx_t *hist = values->histogram;
    for (i = 0 ; i < end; i++) {
        write_chart_dimension(latency_hist_dimensions[i], hist[i]);
    }

    write_end_chart();
}

/**
 * Send CPU histogram charts
 *
 * Write the chart commands on Netdata pipe
 */
static void ebpf_send_cpu_histogram_charts()
{
    int i;
    int end = (running_on_kernel < NETDATA_KERNEL_V4_15) ? 1 : ebpf_nprocs;
    struct netdata_hist_per_core *sc = schedule_core;
    for (i = 0; i < end; i++) {
        write_histogram_chart(&sc[i], NETDATA_LATENCY_HIST_BINS);
    }
}

/**
 * Send data to Netdata calling auxiliar functions.
 *
 * @param em the structure with thread information
 */
static void ebpf_latency_send_global_data()
{
    write_count_chart(NETDATA_LATENCY_SCHEDULE_COUNT, NETDATA_EBPF_FAMILY,
                      latency_counter_publish_aggregated, 3);

    write_count_chart(NETDATA_LATENCY_IO_COUNT, NETDATA_EBPF_FAMILY,
                      &latency_counter_publish_aggregated[NETDATA_KEY_CALLS_BLOCK_RQ_ISSUE], 2);

    ebpf_send_cpu_histogram_charts();
}

/**
* Main loop for this collector.
*/
static void latency_collector(ebpf_module_t *em)
{
    latency_threads.thread = mallocz(sizeof(netdata_thread_t));

    netdata_thread_create(latency_threads.thread, latency_threads.name, NETDATA_THREAD_OPTION_JOINABLE,
                          ebpf_latency_read_hash, em);

    while (!close_ebpf_plugin) {
        pthread_mutex_lock(&collect_data_mutex);
        pthread_cond_wait(&collect_data_cond_var, &collect_data_mutex);

        pthread_mutex_lock(&lock);

        ebpf_latency_send_global_data();

        pthread_mutex_unlock(&lock);
        pthread_mutex_unlock(&collect_data_mutex);
    }
}


/*****************************************************************
 *
 *  FUNCTIONS TO CLOSE THE THREAD
 *
 *****************************************************************/

/**
 * Cleanup CPU vector
 *
 * Clean the duplicated string.
 */
void cleanup_cpu_list() {
    int i;
    int end = ebpf_nprocs;
    for (i = 0 ; i < end ; i++) {
        struct netdata_hist_per_core *sc = &schedule_core[i];
        freez(sc->family);
        freez(sc->chart);
    }

    freez(schedule_core);
}

/**
 * Clean up the main thread.
 *
 * @param ptr thread data.
 */
static void ebpf_latency_cleanup(void *ptr)
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

    freez(latency_counter_aggregated_data);
    ebpf_cleanup_publish_syscall(latency_counter_publish_aggregated);
    freez(latency_counter_publish_aggregated);

    freez(latency_hist_aggregated_data);
    ebpf_cleanup_publish_syscall(latency_hist_publish_aggregated);
    freez(latency_hist_publish_aggregated);

    freez(latency_data.map_fd);
    freez(latency_threads.thread);

    freez(latency_hash_values);

    cleanup_cpu_list();

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
 *  FUNCTIONS TO START THREAD
 *
 *****************************************************************/

/**
* Set local function pointers, this function will never be compiled with static libraries
*/
static void set_local_pointers()
{
    map_fd = latency_data.map_fd;
}

/**
 * Create CPU charts
 *
 * Create the cpu charts.
 */
static void ebpf_create_cpu_charts()
{
    char name[64];
    int i;
    int end = (running_on_kernel < NETDATA_KERNEL_V4_15) ? 1 : ebpf_nprocs;
    int order;
    struct netdata_hist_per_core *sc = schedule_core;
    for (i = 0, order = 21110; i < end; i++, order++) {
        snprintfz(name, 63, "cpu%d_schedule", i);
        sc[i].chart = strdupz(name);
        sc[i].family = strdupz(NETDATA_CPU_FAMILY);

        ebpf_create_chart(NETDATA_CPU_FAMILY,
                          name,
                          "Interval between a call for the either <code>ttwu_do_wakeup</code> or"
                          "<code>wake_up_new_task</code> and a call for the function <code>finish_task_switch</code>"
                          "in microseconds.",
                          EBPF_COMMON_DIMENSION_CALL,
                          NETDATA_LATENCY_CPU_SCHEDULER,
                          order,
                          ebpf_create_global_dimension,
                          latency_hist_publish_aggregated,
                          NETDATA_LATENCY_HIST_BINS);
    }
}

/**
 * Create global charts
 *
 * Call ebpf_create_chart to create the charts for the collector.
 */
static void ebpf_create_global_charts()
{
    ebpf_create_chart(NETDATA_EBPF_FAMILY, NETDATA_LATENCY_SCHEDULE_COUNT,
                      "Calls to internal function that schedule process.", EBPF_COMMON_DIMENSION_CALL,
                      NETDATA_LATENCY_SCHEDULER, 21100, ebpf_create_global_dimension,
                      latency_counter_publish_aggregated, 3);

    ebpf_create_chart(NETDATA_EBPF_FAMILY, NETDATA_LATENCY_IO_COUNT,
                      "Calls to internal function that writes data to disk.", EBPF_COMMON_DIMENSION_CALL,
                      NETDATA_LATENCY_BLOCK_IO, 21101, ebpf_create_global_dimension,
                      &latency_counter_publish_aggregated[NETDATA_KEY_CALLS_BLOCK_RQ_ISSUE], 2);

    ebpf_create_cpu_charts();
}

/**
 * Fill Histogram dimension
 *
 * Fill the histogram dimension with the specified ranges
 */
void ebpf_latency_fill_histogram_dimension()
{
    uint32_t now = 1, previous = 0;
    uint32_t selector;
    char range[64];
    for (selector = 0; selector < NETDATA_LATENCY_HIST_BINS; selector++) {
        snprintf(range, 63, "%u_%u", previous, now);
        latency_hist_dimensions[selector] = strdupz(range);
        previous = (now < 2)?now:now + 1;
        now <<= 1;
    }
}

/**
 * Allocate vectors used with this thread.
 *
 * We are not testing the return, because callocz does this and shutdown the software
 * case it was not possible to allocate.
 *
 * @param length is the length for the vectors used inside the collector.
 */
static void ebpf_latency_allocate_global_vectors(size_t length)
{
    latency_counter_aggregated_data = callocz(length, sizeof(netdata_syscall_stat_t));
    latency_counter_publish_aggregated = callocz(length, sizeof(netdata_publish_syscall_t));

    latency_hist_aggregated_data = callocz(NETDATA_LATENCY_HIST_BINS, sizeof(netdata_syscall_stat_t));
    latency_hist_publish_aggregated = callocz(NETDATA_LATENCY_HIST_BINS, sizeof(netdata_publish_syscall_t));

    latency_hash_values = callocz(ebpf_nprocs, sizeof(netdata_idx_t));

    ebpf_latency_fill_histogram_dimension();

    schedule_core = callocz(ebpf_nprocs,sizeof(struct netdata_hist_per_core));
}

/*****************************************************************
 *
 *  EBPF LATENCY THREAD
 *
 *****************************************************************/

/**
 * Process thread
 *
 * Thread used to generate process charts.
 *
 * @param ptr a pointer to `struct ebpf_module`
 *
 * @return It always return NULL
 */
void *ebpf_latency_thread(void *ptr)
{
    netdata_thread_cleanup_push(ebpf_latency_cleanup, ptr);

    ebpf_module_t *em = (ebpf_module_t *)ptr;
    fill_ebpf_data(&latency_data);

    if (!em->enabled)
        goto endlatency;

    pthread_mutex_lock(&lock);

    ebpf_latency_allocate_global_vectors(NETDATA_LATENCY_COUNTER);
    if (ebpf_update_kernel(&latency_data)) {
        pthread_mutex_unlock(&lock);
        goto endlatency;
    }

    set_local_pointers();
    probe_links = ebpf_load_program(ebpf_plugin_dir, em, kernel_string, &objects, latency_data.map_fd);
    if (!probe_links) {
        pthread_mutex_unlock(&lock);
        goto endlatency;
    }

    int algorithms[NETDATA_LATENCY_HIST_BINS] = {
                NETDATA_EBPF_INCREMENTAL_IDX, NETDATA_EBPF_INCREMENTAL_IDX, NETDATA_EBPF_INCREMENTAL_IDX,
                NETDATA_EBPF_INCREMENTAL_IDX, NETDATA_EBPF_INCREMENTAL_IDX, NETDATA_EBPF_INCREMENTAL_IDX,
                NETDATA_EBPF_INCREMENTAL_IDX, NETDATA_EBPF_INCREMENTAL_IDX, NETDATA_EBPF_INCREMENTAL_IDX,
                NETDATA_EBPF_INCREMENTAL_IDX, NETDATA_EBPF_INCREMENTAL_IDX, NETDATA_EBPF_INCREMENTAL_IDX,
                NETDATA_EBPF_INCREMENTAL_IDX, NETDATA_EBPF_INCREMENTAL_IDX, NETDATA_EBPF_INCREMENTAL_IDX,
                NETDATA_EBPF_INCREMENTAL_IDX
    };

    ebpf_global_labels(latency_counter_aggregated_data, latency_counter_publish_aggregated,
                       latency_counter_dimension_name, latency_counter_id_names,
                       algorithms, NETDATA_LATENCY_COUNTER);

    ebpf_global_labels(latency_hist_aggregated_data, latency_hist_publish_aggregated,
                       latency_hist_dimensions, latency_hist_dimensions,
                       algorithms, NETDATA_LATENCY_HIST_BINS);

    ebpf_create_global_charts();

    pthread_mutex_unlock(&lock);

    latency_collector(em);

endlatency:
    netdata_thread_cleanup_pop(1);
    return NULL;
}