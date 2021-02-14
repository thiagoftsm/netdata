// SPDX-License-Identifier: GPL-3.0-or-later

#include <sys/resource.h>

#include "ebpf.h"
#include "ebpf_io_latency.h"

static char *latency_counter_dimension_name[NETDATA_LATENCY_COUNTER] = { "startIO", "read", "write", "read", "write" };
static char *latency_counter_id_names[NETDATA_LATENCY_COUNTER] = { "block_rq_issue", "block_rq_complete_read",
                                                                   "block_rq_complete_write", "read", "write" };

// /sys/block/sda/sda1/uevent
// /sys/block/sda/sda1/start

static ebpf_data_t io_latency_data;

static netdata_syscall_stat_t *latency_counter_aggregated_data = NULL;
static netdata_publish_syscall_t *latency_counter_publish_aggregated = NULL;

static char *latency_hist_dimensions[NETDATA_LATENCY_HIST_BINS] = { };
static netdata_syscall_stat_t *latency_hist_aggregated_data = NULL;
static netdata_publish_syscall_t *latency_hist_publish_aggregated = NULL;

static avl_tree_lock disk_tree;
netdata_latency_disks_t *disk_list = NULL;

static struct bpf_link **probe_links = NULL;
static struct bpf_object *objects = NULL;

static int *map_fd = NULL;

static int read_thread_closed = 1;
static netdata_idx_t *latency_hash_values = NULL;

char *tracepoint_block_type = { "block"} ;
char *tracepoint_block_issue = { "block_rq_issue" };
char *tracepoint_block_rq_complete = { "block_rq_complete" };

static int was_block_issue_enabled = 0;
static int was_block_rq_complete_enabled = 0;

/*****************************************************************
 *
 *  FUNCTIONS TO MANIPULATE HARD DISKS
 *
 *****************************************************************/

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

    if (ptr1->dev > ptr2->dev)
        return 1;
    if (ptr1->dev < ptr2->dev)
        return -1;

    return 0;
}

/**
 * Update listen table
 *
 * Update link list when it is necessary.
 *
 * @param name the disk name
 */
static void update_disk_table(char *name, int major, int minor)
{
    netdata_latency_disks_t find;
    netdata_latency_disks_t *w;

    uint32_t dev = netdata_new_encode_dev(major, minor);
    find.dev = dev;
    netdata_latency_disks_t *ret = (netdata_latency_disks_t *) avl_search_lock(&disk_tree, (avl *)&find);
    if (ret) // Disk is already present
        return;

    if (likely(disk_list)) {
        netdata_latency_disks_t *move = disk_list;
        netdata_latency_disks_t *update_next = disk_list;
        while (move) {
            if (dev == move->dev)
                return;

            update_next = move;
            move = move->next;
        }

        w = callocz(1, sizeof(netdata_latency_disks_t));
        strcpy(w->family, name);
        w->major = major;
        w->minor = minor;
        w->dev = netdata_new_encode_dev(major, minor);
        update_next->next = w;
    } else {
        disk_list = callocz(1, sizeof(netdata_latency_disks_t));
        strcpy(disk_list->family, name);
        disk_list->major = major;
        disk_list->minor = minor;
        disk_list->dev = netdata_new_encode_dev(major, minor);

        w = disk_list;
    }

    netdata_latency_disks_t *check;
    check = (netdata_latency_disks_t *) avl_insert_lock(&disk_tree, (avl *)w);
    if (check != w)
        error("Internal error, cannot insert the AVL tree.");

#ifdef NETDATA_INTERNAL_CHECKS
    info("The Latency is monitoring the hard disk %s (Major = %d, Minor = %d, Device = %u)", name, major, minor,w->dev);
#endif
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
        // The main goal of this thread is to measure block devices, so any block device with major number
        // smaller than 7 according /proc/devices is not "important".
        if (major > 7) {
            int minor = (int)strtol(procfile_lineword(ff, l, 1), NULL, 10);
            update_disk_table(procfile_lineword(ff, l, 3), major, minor);
        }
    }

    procfile_close(ff);

    return 0;
}


/*****************************************************************
 *
 *  FUNCTIONS TO PUBLISH CHARTS
 *
 *****************************************************************/


/**
 * Read hard disk table
 *
 * Read the table with number of calls for all functions
 */
static void read_hard_disk_tables(int table)
{
    netdata_idx_t *values = latency_hash_values;
    block_key_t key = {};
    block_key_t next_key;
    netdata_latency_disks_t *ret = NULL;
    int fd = map_fd[table];
    while (bpf_map_get_next_key(fd, &key, &next_key) == 0) {
        int test = bpf_map_lookup_elem(fd, &key, values);
        if (test < 0) {
            key = next_key;
            continue;
        }

        netdata_latency_disks_t find;
        find.dev = key.dev;

        if (ret) {
            if (find.dev != ret->dev)
                ret = (netdata_latency_disks_t *) avl_search_lock(&disk_tree, (avl *)&find);
        } else
            ret = (netdata_latency_disks_t *) avl_search_lock(&disk_tree, (avl *)&find);

        // Disk was inserted after we parse /proc/partitions
        if (!ret) {
            if (read_local_disks()) {
                key = next_key;
                continue;
            }

            ret = (netdata_latency_disks_t *) avl_search_lock(&disk_tree, (avl *)&find);
            if (!ret) {
                // We should never reach this point, but we are adding it to keep a safe code
                key = next_key;
                continue;
            }
        }

        uint64_t total = 0;
        int i;
        int end = (running_on_kernel < NETDATA_KERNEL_V4_15) ? 1 : ebpf_nprocs;
        for (i = 0; i < end; i++) {
            total += values[i];
        }

        switch (table) {
            case NETDATA_IO_LATENCY_READ_BYTES_HISTOGRAM: {
                ret->read_bytes = total;
                break;
            }
            case NETDATA_IO_LATENCY_READ_CALL_HISTOGRAM: {
                ret->histogram_read_calls[key.bin] = total;
                break;
            }
            case NETDATA_IO_LATENCY_WRITE_BYTES_HISTOGRAM: {
                ret->written_bytes = total;
                break;
            }
            case NETDATA_IO_LATENCY_WRITE_CALL_HISTOGRAM: {
                ret->histogram_write_calls[key.bin] = total;
                break;
            }
            default: {
                break;
            }
        }
        ret->flags |= NETDATA_DISK_PLOT;

        key = next_key;
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
    int fd = map_fd[NETDATA_IO_LATENCY_GLOBAL_STATS];

    netdata_publish_syscall_t *lc ;
    for (idx = 0, lc = latency_counter_publish_aggregated; lc; idx++, lc = lc->next) {
        uint64_t total = 0;
        if (!bpf_map_lookup_elem(fd, &idx, val)) {
            int i;
            int end = (running_on_kernel < NETDATA_KERNEL_V4_15) ? 1 : ebpf_nprocs;
            for (i = 0; i < end; i++)
                total += val[i];

            if (idx <= NETDATA_KEY_CALLS_BLOCK_RQ_COMPLETE_WRITE)
                lc->ncall = (long long)total;
            else {
                lc->ncall = (lc->pcall)?(long long)total - lc->pcall:0;
                lc->pcall = total;
            }
        } else
            lc->ncall = 0;
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
    UNUSED(ptr);

    read_thread_closed = 0;
    heartbeat_init(&hb);
    usec_t step = NETDATA_LATENCY_READ_SLEEP_MS;
    while (!close_ebpf_plugin) {
        usec_t dt = heartbeat_next(&hb, step);
        (void)dt;

        read_global_table();
        read_hard_disk_tables(NETDATA_IO_LATENCY_READ_BYTES_HISTOGRAM);
        read_hard_disk_tables(NETDATA_IO_LATENCY_READ_CALL_HISTOGRAM);
        read_hard_disk_tables(NETDATA_IO_LATENCY_WRITE_BYTES_HISTOGRAM);
        read_hard_disk_tables(NETDATA_IO_LATENCY_WRITE_CALL_HISTOGRAM);
    }

    read_thread_closed = 1;
    return NULL;
}

struct netdata_static_thread io_latency_threads = {"IO LATENCY KERNEL",
                                                NULL, NULL, 1, NULL,
                                                NULL, ebpf_latency_read_hash };

/**
 * Send data to Netdata calling auxiliar functions.
 *
 * @param em the structure with thread information
 */
static void ebpf_latency_send_global_data()
{
    write_count_chart(NETDATA_LATENCY_IOPS, NETDATA_EBPF_FAMILY,
                      latency_counter_publish_aggregated, 3);

    write_count_chart(NETDATA_LATENCY_BYTES, NETDATA_EBPF_FAMILY,
                      &latency_counter_publish_aggregated[NETDATA_KEY_BYTES_READ], 2);

    fflush(stdout);
}

/**
 * Write one histogram
 *
 * Write dimensions for only one histogram
 *
 * @param hist0  histogram values
 * @param end    number of bins that will be sent to Netdata.
 */
static inline void write_one_histogram(const netdata_idx_t *hist0, uint32_t end) {
    uint32_t i;
    for (i = 0 ; i < end; i++) {
        write_chart_dimension(latency_hist_dimensions[i], hist0[i]);
    }
}

/**
 * Write sum of histogram
 *
 * Write the sum of dimensions for two histogram
 *
 * @param hist0  histogram values
 * @param end    number of bins that will be sent to Netdata.
 */
static inline void write_sum_of_histograms(const netdata_idx_t *hist0, const netdata_idx_t *hist1, uint32_t end) {
    uint32_t i;
    for (i = 0 ; i < end; i++) {
        netdata_idx_t total = hist0[i] + hist1[i];
        write_chart_dimension(latency_hist_dimensions[i], total);
    }
}

/**
 * Call the necessary functions to create a name.
 *
 *  @param family family name
 *  @param name   chart name
 *  @param hist0  histogram values
 *  @param hist1  histogram values
 *  @param end    number of bins that will be sent to Netdata.
 *
 * @return It returns a variable tha maps the charts that did not have zero values.
 */
void write_histogram_chart(char *family, char *name, const netdata_idx_t *hist0, const netdata_idx_t *hist1, uint32_t end)
{
    write_begin_chart(family, name);

    if (!hist1)
        write_one_histogram(hist0, end);
    else
        write_sum_of_histograms(hist0, hist1, end);

    write_end_chart();
}

/**
 * Create Hard Disk charts
 *
 * @param w the structure with necessary information to create the chart
 *
 * Make Hard disk charts and fill chart name
 */
static void ebpf_create_hd_charts(netdata_latency_disks_t *w)
{
    static int order = 2021;
    char *family = w->family;
    w->chart = strdupz("disk_latency");

    ebpf_create_chart(w->chart, family, "Disk latency", EBPF_COMMON_DIMENSION_CALL,
                      family, "disk.latency", order,
                      ebpf_create_global_dimension, latency_hist_publish_aggregated, NETDATA_LATENCY_HIST_BINS);
    w->flags |= NETDATA_DISK_CREATED;
    order++;
}

/**
 * Send Hard disk data
 *
 * Send hard disk information to Netdata.
 */
static void ebpf_latency_send_hd_data()
{
    netdata_latency_disks_t *ld = disk_list;
    while (ld) {
        uint32_t flags = ld->flags;
        if (flags & NETDATA_DISK_PLOT)
        {
            if (!(flags & NETDATA_DISK_CREATED))
                ebpf_create_hd_charts(ld);

            write_histogram_chart(ld->chart, ld->family, ld->histogram_read_calls,
                                  ld->histogram_write_calls, NETDATA_LATENCY_HIST_BINS);
        }

        ld = ld->next;
    }
}

/**
* Main loop for this collector.
*/
static void latency_collector(ebpf_module_t *em)
{
    io_latency_threads.thread = mallocz(sizeof(netdata_thread_t));

    netdata_thread_create(
        io_latency_threads.thread, io_latency_threads.name, NETDATA_THREAD_OPTION_JOINABLE,
        ebpf_latency_read_hash, em);

    while (!close_ebpf_plugin) {
        pthread_mutex_lock(&collect_data_mutex);
        pthread_cond_wait(&collect_data_cond_var, &collect_data_mutex);

        pthread_mutex_lock(&lock);

        ebpf_latency_send_global_data();
        ebpf_latency_send_hd_data();

        pthread_mutex_unlock(&lock);
        pthread_mutex_unlock(&collect_data_mutex);
    }
}

/*****************************************************************
 *
 *  FUNCTIONS TO MAKE CHARTS
 *
 *****************************************************************/

/**
 * Create global charts
 *
 * Call ebpf_create_chart to create the charts for the collector.
 */
static inline void ebpf_create_global_charts()
{
    char *iops_title = {
        "Input and output operations per second. The dimension <code>startIO</code> counts the number of events that "
        "block the hard disks, while <code>write</code> and <code>read</code> describes the action."
    };

    char *rw_title = {
        "Bytes read and written per second."
    };

    ebpf_create_chart(NETDATA_EBPF_FAMILY, NETDATA_LATENCY_IOPS, iops_title,
                      EBPF_COMMON_DIMENSION_CALL, NETDATA_LATENCY_BLOCK_IO,
                      "''", 21101, ebpf_create_global_dimension,
                      latency_counter_publish_aggregated, 3);

    ebpf_create_chart(NETDATA_EBPF_FAMILY, NETDATA_LATENCY_BYTES, rw_title,
                      EBPF_COMMON_DIMENSION_KILOBYTES, NETDATA_LATENCY_BLOCK_IO,
                      "''", 21102, ebpf_create_global_dimension,
                      &latency_counter_publish_aggregated[NETDATA_KEY_BYTES_READ], 2);
}


/*****************************************************************
 *
 *  FUNCTIONS TO CLOSE THE THREAD
 *
 *****************************************************************/

static void ebpf_latency_disable_tracepoints()
{
    char *default_message = { "Cannot disable the tracepoint" };
    if (!was_block_issue_enabled) {
        if (ebpf_disable_tracing_values(tracepoint_block_type, tracepoint_block_issue))
            error("%s %s/%s.", default_message, tracepoint_block_type, tracepoint_block_issue);
    }

    if (!was_block_rq_complete_enabled) {
        if (ebpf_disable_tracing_values(tracepoint_block_type, tracepoint_block_rq_complete))
            error("%s %s/%s.", default_message, tracepoint_block_type, tracepoint_block_rq_complete);
    }
}

/**
 *  Cleanup Disk List
 *
 *  Cleanup the disk list
 */
static void ebpf_latency_cleanup_disk_list() {
    netdata_latency_disks_t *move = disk_list;
    while (move) {
        netdata_latency_disks_t *next = move->next;
        freez(move->chart);
        freez(move->histogram_read_calls);
        freez(move->histogram_write_calls);
        freez(move);

        move = next
            ;
    }
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

    freez(io_latency_data.map_fd);
    freez(io_latency_threads.thread);

    freez(latency_hash_values);

   ebpf_latency_cleanup_disk_list();

    struct bpf_program *prog;
    size_t i = 0 ;
    bpf_object__for_each_program(prog, objects) {
        bpf_link__destroy(probe_links[i]);
        i++;
    }
    bpf_object__close(objects);

    ebpf_latency_disable_tracepoints();
}

/*****************************************************************
 *
 *  EBPF START THREAD
 *
 *****************************************************************/

/**
 * Enable tracepoints
 *
 * Enable necessary tracepoints for thread.
 *
 * @return  It returns 0 on sucess and -1 otherwise
 */
static int ebpf_latency_enable_tracepoints()
{
    was_block_issue_enabled = ebpf_is_tracepoint_enabled(tracepoint_block_type, tracepoint_block_issue);
    if (was_block_issue_enabled == -1)
        return -1;
    else if (!was_block_issue_enabled) {
        if (ebpf_enable_tracing_values(tracepoint_block_type, tracepoint_block_issue))
            return -1;
    }

    was_block_rq_complete_enabled = ebpf_is_tracepoint_enabled(tracepoint_block_type, tracepoint_block_rq_complete);
    if (was_block_rq_complete_enabled == -1)
        return -1;
    else if (!was_block_rq_complete_enabled) {
        if (ebpf_enable_tracing_values(tracepoint_block_type, tracepoint_block_rq_complete))
            return -1;
    }

    return 0;
}

/**
* Set local function pointers, this function will never be compiled with static libraries
*/
static inline void set_local_pointers(int *algorithms)
{
    map_fd = io_latency_data.map_fd;

    int i;
    for (i = 0; i < NETDATA_LATENCY_HIST_BINS; i++) {
        algorithms[i] = NETDATA_EBPF_INCREMENTAL_IDX;
    }
}

/**
 * Fill Histogram dimension
 *
 * Fill the histogram dimension with the specified ranges
 */
static void ebpf_latency_fill_histogram_dimension()
{
    char *dimensions[] = { "us", "ms", "s"};
    int dim = 0;
    uint32_t level = 1000;
    uint32_t divisor = 1;
    uint32_t now = 1, previous = 0;
    uint32_t selector;
    char range[64];
    for (selector = 0; selector < NETDATA_LATENCY_HIST_BINS; selector++) {
        snprintf(range, 63, "%u->%u%s", previous/divisor, now/divisor, dimensions[dim]);
        latency_hist_dimensions[selector] = strdupz(range);
        previous = (now < 2)?now:now + 1;
        now <<= 1;

        if (previous > level) {
            divisor *= 1000;
            level *= 1000;

            if (dim != 2)
                dim++;
        }
    }
}

/**
 *  Allocate Histogram
 *
 *  Allocate histograms that measure the disk latencies
 */
static void ebpf_latency_allocate_io_histograms() {
    netdata_latency_disks_t *move = disk_list;
    while (move) {
        move->histogram_read_calls = callocz(NETDATA_LATENCY_HIST_BINS, sizeof(uint64_t));
        move->histogram_write_calls = callocz(NETDATA_LATENCY_HIST_BINS, sizeof(uint64_t));

        move = move->next;
    }

    ebpf_latency_fill_histogram_dimension();
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

    ebpf_latency_allocate_io_histograms();

    latency_hash_values = callocz(ebpf_nprocs, sizeof(netdata_idx_t));
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
void *ebpf_io_latency_thread(void *ptr)
{
    netdata_thread_cleanup_push(ebpf_latency_cleanup, ptr);

    int algorithms[NETDATA_LATENCY_HIST_BINS];

    ebpf_module_t *em = (ebpf_module_t *)ptr;
    fill_ebpf_data(&io_latency_data);

    if (!em->enabled)
        goto end_io_latency;

    if (ebpf_latency_enable_tracepoints()) {
        em->enabled = false;
        goto end_io_latency;
    }

    avl_init_lock(&disk_tree, compare_disks);

    if (read_local_disks()) {
        em->enabled = CONFIG_BOOLEAN_NO;
        goto end_io_latency;
    }

    pthread_mutex_lock(&lock);

    ebpf_latency_allocate_global_vectors(NETDATA_LATENCY_COUNTER);
    if (ebpf_update_kernel(&io_latency_data)) {
        pthread_mutex_unlock(&lock);
        goto end_io_latency;
    }

    set_local_pointers(algorithms);
    probe_links = ebpf_load_program(ebpf_plugin_dir, em, kernel_string, &objects, io_latency_data.map_fd);
    if (!probe_links) {
        pthread_mutex_unlock(&lock);
        goto end_io_latency;
    }

    algorithms[NETDATA_KEY_BYTES_READ] = algorithms[NETDATA_KEY_BYTES_WRITE] = NETDATA_EBPF_ABSOLUTE_IDX;
    ebpf_global_labels(latency_counter_aggregated_data, latency_counter_publish_aggregated,
                               latency_counter_dimension_name, latency_counter_id_names,
                               algorithms, NETDATA_LATENCY_COUNTER);

    algorithms[NETDATA_KEY_BYTES_READ] = algorithms[NETDATA_KEY_BYTES_WRITE] = NETDATA_EBPF_INCREMENTAL_IDX;
    ebpf_global_labels(latency_hist_aggregated_data, latency_hist_publish_aggregated,
                       latency_hist_dimensions, latency_hist_dimensions,
                       algorithms, NETDATA_LATENCY_HIST_BINS);

    ebpf_create_global_charts();

    pthread_mutex_unlock(&lock);

    latency_collector(em);

end_io_latency:
    netdata_thread_cleanup_pop(1);
    return NULL;
}