// SPDX-License-Identifier: GPL-3.0-or-later

#include "ebpf_filesystem.h"

ebpf_filesystem_partitions_t localfs[] = {
    {.filesystem = "ext4", .family = "EXT4", .partitions = 0, .objects = NULL, .probe_links = NULL},
    {.filesystem = NULL, .family = NULL, .partitions = 0, .objects = NULL, .probe_links = NULL}
};

char **dimensions = NULL;

static netdata_syscall_stat_t *filesystem_aggregated_data = NULL;
static netdata_publish_syscall_t *filesystem_publish_aggregated = NULL;

static int read_thread_closed = 1;
static netdata_idx_t *filesystem_hash_values = NULL;

/*****************************************************************
 *
 *  KERNEL THREAD
 *
 *****************************************************************/

static netdata_ebpf_histogram_t *select_hist(ebpf_filesystem_partitions_t *efp, uint32_t id)
{
    switch (id) {
        case NETDATA_KEY_CALLS_READ: {
            return &efp->hread;
        }
        case NETDATA_KEY_CALLS_WRITE: {
            return &efp->hwrite;
        }
        case NETDATA_KEY_CALLS_OPEN: {
            return &efp->hopen;
        }
        default: {
            return NULL;
        }
    }
}

/**
 * Read hard disk table
 *
 * @param table index for the hash table
 *
 * Read the table with number of calls for all functions
 */
static void read_filesystem_table(ebpf_filesystem_partitions_t *efp)
{
    netdata_idx_t *values = filesystem_hash_values;
    netdata_fs_hist_t key = {};
    netdata_fs_hist_t next_key;
    int fd = efp->kernel_info.map_fd[NETDATA_MAIN_TABLE];
    while (bpf_map_get_next_key(fd, &key, &next_key) == 0) {
        int test = bpf_map_lookup_elem(fd, &key, values);
        if (test < 0) {
            key = next_key;
            continue;
        }

        netdata_ebpf_histogram_t *w = select_hist(efp, key.hist_id);
        uint64_t total = 0;
        int i;
        int end = (running_on_kernel < NETDATA_KERNEL_V4_15) ? 1 : ebpf_nprocs;
        for (i = 0; i < end; i++) {
            total += values[i];
        }

        w->histogram[key.bin] = total;
        key = next_key;
    }
}

/**
 * Read hard disk table
 *
 * @param table index for the hash table
 *
 * Read the table with number of calls for all functions
 */
static void read_filesystem_tables()
{
    int i;
    for (i = 0; localfs[i].filesystem; i++) {
        ebpf_filesystem_partitions_t *efp = &localfs[i];
        if (efp->flags & NETDATA_FILESYSTEM_FLAG_HAS_PARTITION) {
            read_filesystem_table(efp);
        }
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
void *ebpf_filesystem_read_hash(void *ptr)
{
    read_thread_closed = 0;
    heartbeat_t hb;
    heartbeat_init(&hb);
    usec_t step = NETDATA_EXT4_READ_SLEEP_MS;
    while (!close_ebpf_plugin) {
        usec_t dt = heartbeat_next(&hb, step);
        (void)dt;

        read_filesystem_tables();
    }
    read_thread_closed = 1;
    return NULL;
}

/*****************************************************************
 *
 *  LOOP THREAD
 *
 *****************************************************************/

struct netdata_static_thread filesystem_threads = {"EBPF FS READ",
                                               NULL, NULL, 1, NULL,
                                               NULL, ebpf_filesystem_read_hash };

/**
 * Call the necessary functions to create a name.
 *
 *  @param family family name
 *  @param name   chart name
 *  @param hist0  histogram values
 *  @param end    number of bins that will be sent to Netdata.
 *
 * @return It returns a variable tha maps the charts that did not have zero values.
 */
static void write_histogram_chart(char *family, char *name, const netdata_idx_t *hist, uint32_t end)
{
    write_begin_chart(family, name);

    uint32_t i;
    for (i = 0; i < end; i++) {
        write_chart_dimension(dimensions[i], hist[i]);
    }

    write_end_chart();

    fflush(stdout);
}

/**
 * Send Hard disk data
 *
 * Send hard disk information to Netdata.
 */
static void ebpf_histogram_send_data()
{
    uint32_t i;
    for (i = 0; localfs[i].filesystem; i++) {
        ebpf_filesystem_partitions_t *efp = &localfs[i];
        if (efp->flags & NETDATA_FILESYSTEM_FLAG_HAS_PARTITION) {
            write_histogram_chart(NETDATA_EBPF_FAMILY, efp->hread.name,
                                  efp->hread.histogram, NETDATA_FILESYSTEM_MAX_BINS);

            write_histogram_chart(NETDATA_EBPF_FAMILY, efp->hwrite.name,
                                  efp->hwrite.histogram, NETDATA_FILESYSTEM_MAX_BINS);

            write_histogram_chart(NETDATA_EBPF_FAMILY, efp->hopen.name,
                                  efp->hopen.histogram, NETDATA_FILESYSTEM_MAX_BINS);
        }
    }
}

/**
 * Main loop for this collector.
 *
 */
static void filesystem_collector(usec_t step, ebpf_module_t *em)
{
    heartbeat_t hb;
    heartbeat_init(&hb);

    filesystem_threads.thread = mallocz(sizeof(netdata_thread_t));

    netdata_thread_create(filesystem_threads.thread, filesystem_threads.name,
                          NETDATA_THREAD_OPTION_JOINABLE, ebpf_filesystem_read_hash, em);

    while (!close_ebpf_plugin) {
        pthread_mutex_lock(&collect_data_mutex);
        pthread_cond_wait(&collect_data_cond_var, &collect_data_mutex);

        pthread_mutex_lock(&lock);

        ebpf_histogram_send_data();

        pthread_mutex_unlock(&collect_data_mutex);
        pthread_mutex_unlock(&lock);
    }
}

/*****************************************************************
 *
 *  CHART FUNCTIONS
 *
 *****************************************************************/

/**
* Create File Systems charts
*/
static void ebpf_create_fs_charts()
{
    static int order = 21200;
    char chart_name[64], title[256], family[64];
    int i;
    for (i = 0; localfs[i].filesystem; i++) {
        ebpf_filesystem_partitions_t *efp = &localfs[i];
        if (efp->flags & NETDATA_FILESYSTEM_FLAG_HAS_PARTITION) {
            snprintfz(title, 255, "%s latency for each read request.", efp->filesystem);
            snprintfz(family, 63, "%s latency", efp->family);
            snprintfz(chart_name, 63, "%s_read_latency", efp->filesystem);
            efp->hread.name = strdupz(chart_name);

            ebpf_create_chart(NETDATA_EBPF_FAMILY, efp->hread.name,
                              title,
                              EBPF_COMMON_DIMENSION_CALL, family,
                              NULL, EBPF_CHART_TYPE_STACKED, order, ebpf_create_global_dimension,
                              filesystem_publish_aggregated, NETDATA_FILESYSTEM_MAX_BINS);
            order++;

            snprintfz(title, 255, "%s latency for each write request.", efp->filesystem);
            snprintfz(chart_name, 63, "%s_write_latency", efp->filesystem);
            efp->hwrite.name = strdupz(chart_name);
            ebpf_create_chart(NETDATA_EBPF_FAMILY, efp->hwrite.name,
                              title,
                              EBPF_COMMON_DIMENSION_CALL, family,
                              NULL, EBPF_CHART_TYPE_STACKED, order, ebpf_create_global_dimension,
                              filesystem_publish_aggregated, NETDATA_FILESYSTEM_MAX_BINS);
            order++;

            snprintfz(title, 255, "%s latency for each open request.", efp->filesystem);
            snprintfz(chart_name, 63, "%s_open_latency", efp->filesystem);
            efp->hopen.name = strdupz(chart_name);
            ebpf_create_chart(NETDATA_EBPF_FAMILY, efp->hopen.name,
                              title,
                              EBPF_COMMON_DIMENSION_CALL, family,
                              NULL, EBPF_CHART_TYPE_STACKED, order, ebpf_create_global_dimension,
                              filesystem_publish_aggregated, NETDATA_FILESYSTEM_MAX_BINS);
            order++;

        }
    }
}

/*****************************************************************
 *
 *  CLEANUP FUNCTIONS
 *
 *****************************************************************/

void ebpf_filesystem_cleanup_ebpf_data()
{
    int i;
    for (i = 0; localfs[i].filesystem; i++) {
        ebpf_filesystem_partitions_t *efp = &localfs[i];
        if (efp->partitions) {
            freez(efp->kernel_info.map_fd);

            freez(efp->hread.name);
            freez(efp->hwrite.name);
            freez(efp->hopen.name);

            struct bpf_program *prog;
            struct bpf_link **probe_links = efp->probe_links;
            size_t j = 0 ;
            bpf_object__for_each_program(prog, efp->objects) {
                bpf_link__destroy(probe_links[j]);
                j++;
            }
            bpf_object__close(efp->objects);
        }
    }
}

/**
 * Clean up the main thread.
 *
 * @param ptr thread data.
 */
static void ebpf_filesystem_cleanup(void *ptr)
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

    freez(filesystem_aggregated_data);
    ebpf_cleanup_publish_syscall(filesystem_publish_aggregated);
    freez(filesystem_publish_aggregated);

    freez(filesystem_threads.thread);
    freez(filesystem_hash_values);

    ebpf_histogram_dimension_cleanup(dimensions, NETDATA_FILESYSTEM_MAX_BINS);
    ebpf_filesystem_cleanup_ebpf_data();
}

/*****************************************************************
 *
 *  EBPF FILESYSTEM THREAD
 *
 *****************************************************************/

static int read_local_partitions()
{
    char filename[FILENAME_MAX + 1];
    snprintfz(filename, FILENAME_MAX, "%s/proc/self/mountinfo", netdata_configured_host_prefix);
    procfile *ff = procfile_open(filename, " \t", PROCFILE_FLAG_DEFAULT);
    if(unlikely(!ff)) {
        snprintfz(filename, FILENAME_MAX, "%s/proc/1/mountinfo", netdata_configured_host_prefix);
        ff = procfile_open(filename, " \t", PROCFILE_FLAG_DEFAULT);
        if(unlikely(!ff)) return 0;
    }

    ff = procfile_readall(ff);
    if(unlikely(!ff))
        return 0;

    int count = 0;
    unsigned long l, i, lines = procfile_lines(ff);
    for(l = 0; l < lines ;l++) {
        char *fs = procfile_lineword(ff, l, 7);
        for (i = 0; localfs[i].filesystem; i++) {
            if (!strcmp(fs, localfs[i].filesystem)) {
                localfs[i].partitions++;
                count++;
                break;
            }
        }
    }
    procfile_close(ff);

    return count;
}

int ebpf_filesystem_initialize_ebpf_data(ebpf_module_t *em)
{
    int i;
    const char *save_name = em->thread_name;
    for (i = 0; localfs[i].filesystem; i++) {
        if (localfs[i].partitions) {
            ebpf_filesystem_partitions_t *efp = &localfs[i];
            ebpf_data_t *ed = &efp->kernel_info;
            fill_ebpf_data(ed);

            if (ebpf_update_kernel(ed)) {
                em->thread_name = save_name;
                return -1;
            }

            em->thread_name = efp->filesystem;
            efp->probe_links = ebpf_load_program(ebpf_plugin_dir, em, kernel_string,
                                                 &efp->objects, ed->map_fd);
            if (!efp->probe_links) {
                em->thread_name = save_name;
                return -1;
            }
            efp->flags |= NETDATA_FILESYSTEM_FLAG_HAS_PARTITION;
        }
    }
    em->thread_name = save_name;

    dimensions = ebpf_fill_histogram_dimension(NETDATA_FILESYSTEM_MAX_BINS);

    filesystem_aggregated_data = callocz(NETDATA_FILESYSTEM_MAX_BINS, sizeof(netdata_syscall_stat_t));
    filesystem_publish_aggregated = callocz(NETDATA_FILESYSTEM_MAX_BINS, sizeof(netdata_publish_syscall_t));

    filesystem_hash_values = callocz(ebpf_nprocs, sizeof(netdata_idx_t));

    return 0;
}

/**
 * Filesystem thread
 *
 * Thread used to generate socket charts.
 *
 * @param ptr a pointer to `struct ebpf_module`
 *
 * @return It always return NULL
 */
void *ebpf_filesystem_thread(void *ptr)
{
    netdata_thread_cleanup_push(ebpf_filesystem_cleanup, ptr);
    int algorithms[NETDATA_FILESYSTEM_MAX_BINS];

    ebpf_module_t *em = (ebpf_module_t *)ptr;
    if (!em->enabled)
        goto endfilesystem;

    if (!read_local_partitions()) {
        em->enabled = 0;
        info("Netdata cannot monitor the filesystems used on this host.");
        goto endfilesystem;
    }

    if (ebpf_filesystem_initialize_ebpf_data(em)) {
        goto endfilesystem;
    }

    pthread_mutex_lock(&lock);
    ebpf_set_dimension_algorithm(algorithms, NETDATA_FILESYSTEM_MAX_BINS, NETDATA_EBPF_INCREMENTAL_IDX);
    ebpf_global_labels(filesystem_aggregated_data, filesystem_publish_aggregated, dimensions, dimensions,
                algorithms,
        NETDATA_FILESYSTEM_MAX_BINS);

    ebpf_create_fs_charts();
    pthread_mutex_unlock(&lock);

    filesystem_collector((usec_t)(em->update_time * USEC_PER_SEC), em);

endfilesystem:
    netdata_thread_cleanup_pop(1);
    return NULL;
}