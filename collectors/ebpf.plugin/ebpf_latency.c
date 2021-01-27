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

netdata_latency_disks_t *disk_list = NULL;

static int *map_fd = NULL;
static int read_thread_closed = 1;

avl_tree_lock disk_tree;

/*****************************************************************
 *
 *  FUNCTIONS WITH THE MAIN LOOP
 *
 *****************************************************************/

/**
 * Create Hard Disk charts
 *
 * @param w the structure with necessary information to create the chart
 *
 * Make Hard disk charts and fill chart name
 */
static void ebpf_create_hd_charts(netdata_latency_disks_t *w)
{
    char name[128];
    int order = 2021;
    char *family = w->family;
    snprintfz(name, 127, "latency_%s", family);
    w->chart = strdupz(name);

    ebpf_create_chart(name,
                      family,
                      "Interval between calls for function that starts IO and the function that ends the IO."
                      " Netdata is attaching to tracepoints.",
                      EBPF_COMMON_DIMENSION_CALL,
                      family,
                      order,
                      ebpf_create_global_dimension,
                      latency_hist_publish_aggregated,
                      NETDATA_LATENCY_HIST_BINS);
    w->flags |= NETDATA_DISK_CREATED;
    /*
    netdata_latency_disks_t *move = disk_list;
    while (move) {
        char *family = move->family;
        snprintfz(name, 127, "latency_%s", family);
        move->chart = strdupz(name);

        ebpf_create_chart(name,
                          family,
                          "Interval between calls for function that starts IO and the function that ends the IO."
                          " Netdata is attaching to tracepoints.",
                          EBPF_COMMON_DIMENSION_CALL,
                          family,
                          order,
                          ebpf_create_global_dimension,
                          latency_hist_publish_aggregated,
                          NETDATA_LATENCY_HIST_BINS);

        move = move->next;
    }
     */
}


/**
 * Read hard disk table
 *
 * Read the table with number of calls for all functions
 */
static void read_hard_disk_table()
{
    netdata_idx_t *values = latency_hash_values;
    int fd = map_fd[NETDATA_LATENCY_HD_STATS];
    block_key_t key = {};
    block_key_t next_key;
    netdata_latency_disks_t *ret = NULL;
    while (bpf_map_get_next_key(fd, &key, &next_key) == 0) {
        int test = bpf_map_lookup_elem(fd, &key, values);
        if (test < 0) {
            key = next_key;
            continue;
        }

        uint64_t total = 0;
        int i;
        int end = (running_on_kernel < NETDATA_KERNEL_V4_15) ? 1 : ebpf_nprocs;
        for (i = 0; i < end; i++)
            total += values[i];

        netdata_latency_disks_t find;
        find.major = netdata_decode_major_dev(key.dev);
        find.minor = netdata_decode_minor_dev(key.dev);

        if (ret) {
            if (find.major != ret->major && find.minor != ret->minor)
                ret = (netdata_latency_disks_t *) avl_search_lock(&disk_tree, (avl *)&find);
        } else
            ret = (netdata_latency_disks_t *) avl_search_lock(&disk_tree, (avl *)&find);

        if (ret){
            if (!(ret->flags & NETDATA_DISK_CREATED))
                ebpf_create_hd_charts(ret);

            ret->histogram[key.bin] = total;
            ret->flags |= NETDATA_DISK_PLOT;
        }
        key = next_key;
    }
}

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
        read_hard_disk_table();

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
 * Call the necessary functions to create a name.
 *
 *  @param family the name family
 *  @param name the name name
 *  @param histogram the histogram values
 *
 * @return It returns a variable tha maps the charts that did not have zero values.
 */
void write_histogram_chart(char *family, char *name, netdata_idx_t *histogram, uint32_t end)
{
    write_begin_chart(family, name);
    uint32_t i;
    for (i = 0 ; i < end; i++) {
        write_chart_dimension(latency_hist_dimensions[i], histogram[i]);
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
        write_histogram_chart(sc[i].family, sc[i].chart, sc[i].histogram, NETDATA_LATENCY_HIST_BINS);
    }
}

/**
 * Send HD histogram charts
 *
 * Write the chart commands on Netdata pipe
 */
static void ebpf_send_hd_histogram_charts() {
    netdata_latency_disks_t *move = disk_list;
    while (move) {
        if (move->flags & NETDATA_DISK_PLOT) {
            write_histogram_chart(move->chart, move->family, move->histogram, NETDATA_LATENCY_HIST_BINS);
        }
        move = move->next;
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

    // hard disk latency is created on the fly, so we dispatch any possbile chart creation
    fflush(stdout);
    ebpf_send_hd_histogram_charts();
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
 * Update listen table
 *
 * Update link list when it is necessary.
 *
 * @param name the disk name
 */
static void update_disk_table(char *name, int major, int minor)
{
    netdata_latency_disks_t *w;
    netdata_latency_disks_t *store = disk_list;
    if (likely(disk_list)) {
        netdata_latency_disks_t *move = disk_list;
        while (move) {
            if (!strcmp(name, move->family))
                return;

            store = move;
            move = move->next;
        }

        w = callocz(1, sizeof(netdata_latency_disks_t));
        strcpy(w->family, name);
        w->major = major;
        w->minor = minor;
        store->next = w;
    } else {
        disk_list = callocz(1, sizeof(netdata_latency_disks_t));
        strcpy(disk_list->family, name);
        disk_list->major = major;
        disk_list->minor = minor;

        w = disk_list;
    }

    // We are always inserting as new, because there is not repeated values inside /proc/partitions:w
    netdata_latency_disks_t *check;
    check = (netdata_latency_disks_t *) avl_insert_lock(&disk_tree, (avl *)w);
    if (check != w)
        error("Internal error, cannot insert the AVL tree.");

#ifdef NETDATA_INTERNAL_CHECKS
    info("The Latency is monitoring the hard disk %s (%d, %d)", name, major, minor);
#endif
}

/**
 * COmpare Major minor
 *
 * Compare either major values or minor values of hard disk.
 *
 * @param first
 * @param second
 * @return
 */
static inline int compare_major_minor(uint32_t first, uint32_t second) {
    if (first == second)
        return 0;
    if (first > second )
        return 1;

    return -1;
}

/**
 * Compare disks
 *
 * Compare major and minor values to add disks to tree.
 *
 * @param a pointer to netdata_latency_disks
 * @param b pointer to netdata_latency_disks
 *
 * @return It returns 0 case the values are equal, 1 case a is bigger than b and -1 case a is smaller than b.
*/
static int compare_disks(void *a, void *b)
{
    netdata_latency_disks_t *ptr1 = a;
    netdata_latency_disks_t *ptr2 = b;

    int major, minor;

    major = compare_major_minor(ptr1->major, ptr2->major);
    minor = compare_major_minor(ptr1->minor, ptr2->minor);

    if (major)
        return major;
    if (minor)
        return minor;

    return 0;
}

/**
 *  Read Local Ports
 *
 *  Parse /proc/partitions to get block disks used to measure latency.
 *
 *  @return It returns 0 on success and -1 otherwise
 */
static int read_local_disks()
{
    procfile *ff = procfile_open(NETDATA_LATENCY_PROC_PARTITIONS, " \t:", PROCFILE_FLAG_DEFAULT);
    if (!ff)
        return -1;

    ff = procfile_readall(ff);
    if (!ff)
        return -1;

    size_t lines = procfile_lines(ff), l;
    for(l = 2; l < lines ;l++) {
        size_t words = procfile_linewords(ff, l);
        // This is header or end of file
        if (unlikely(words < 4))
            continue;

        int major = (int)strtol(procfile_lineword(ff, l, 0), NULL, 10);
        // The main goal of this thread is to measure block devices, cosindering this any block device with major number
        // smaller than 7 according /proc/devices is not "important".
        if (major > 7) {
            int minor = (int)strtol(procfile_lineword(ff, l, 1), NULL, 10);
            update_disk_table(procfile_lineword(ff, l, 3), major, minor);
        }
    }

    procfile_close(ff);

    return 0;
}


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
 *  Allocate Histogram
 *
 *  Allocate histograms that measure the disk latencies
 */
static void ebpf_latency_allocate_io_histogram() {
    netdata_latency_disks_t *move = disk_list;
    while (move) {
        move->histogram = callocz(NETDATA_LATENCY_HIST_BINS, sizeof(uint64_t));

        move = move->next;
    }
}

/**
 * Fill Histogram dimension
 *
 * Fill the histogram dimension with the specified ranges
 */
static void ebpf_latency_fill_histogram_dimension()
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

    ebpf_latency_allocate_io_histogram();

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

    avl_init_lock(&disk_tree, compare_disks);

    if (read_local_disks()) {
        em->enabled = CONFIG_BOOLEAN_NO;
        goto endlatency;
    }

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