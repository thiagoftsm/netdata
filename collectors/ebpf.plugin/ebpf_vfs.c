// SPDX-License-Identifier: GPL-3.0-or-later

#include <sys/resource.h>

#include "ebpf.h"
#include "ebpf_vfs.h"

/*****************************************************************
 *
 *  GLOBAL VARIABLES
 *
 *****************************************************************/

static char *vfs_dimension_names[NETDATA_KEY_PUBLISH_VFS_END] = {  "delete",  "read",  "write" };
static char *vfs_id_names[NETDATA_KEY_PUBLISH_VFS_END] = { "vfs_unlink", "vfs_read", "vfs_write" };

static ebpf_data_t vfs_data;

static ebpf_local_maps_t vfs_maps[] = {{.name = "tbl_vfs_pid", .internal_input = ND_EBPF_DEFAULT_PID_SIZE,
                                               .user_input = 0},
                                           {.name = NULL, .internal_input = 0, .user_input = 0}};

struct config vfs_config = { .first_section = NULL,
    .last_section = NULL,
    .mutex = NETDATA_MUTEX_INITIALIZER,
    .index = { .avl_tree = { .root = NULL, .compar = appconfig_section_compare },
        .rwlock = AVL_LOCK_INITIALIZER } };

static netdata_idx_t *vfs_hash_values = NULL;
static netdata_syscall_stat_t vfs_aggregated_data[NETDATA_KEY_PUBLISH_PROCESS_END];
static netdata_publish_syscall_t vfs_publish_aggregated[NETDATA_KEY_PUBLISH_PROCESS_END];

netdata_publish_vfs_t **vfs_pid = NULL;
netdata_publish_vfs_t *vfs_vector = NULL;

static struct bpf_object *objects = NULL;
static struct bpf_link **probe_links = NULL;

static int *map_fd = NULL;

struct netdata_static_thread vfs_threads = {"VFS KERNEL",
                                               NULL, NULL, 1, NULL,
                                               NULL,  NULL};

static int read_thread_closed = 1;

/*
static char *status[] = { "process", "zombie" };



static int *map_fd = NULL;

*/

/*****************************************************************
 *
 *  PROCESS DATA AND SEND TO NETDATA
 *
 *****************************************************************/

/**
 * Sum values for pid
 *
 * @param root the structure with all available PIDs
 *
 * @param offset the address that we are reading
 *
 * @return it returns the sum of all PIDs
long long ebpf_vfs_sum_values_for_pids(struct pid_on_target *root, size_t offset)
{
    long long ret = 0;
    while (root) {
        int32_t pid = root->pid;
        ebpf_process_publish_apps_t *w = current_apps_data[pid];
        if (w) {
            ret += get_value_from_structure((char *)w, offset);
        }

        root = root->next;
    }

    return ret;
}
     */

/**
 * Remove process pid
 *
 * Remove from PID task table when task_release was called.
void ebpf_process_remove_pids()
{
    struct pid_stat *pids = root_of_pids;
    int pid_fd = map_fd[0];
    while (pids) {
        uint32_t pid = pids->pid;
        ebpf_process_stat_t *w = global_process_stats[pid];
        if (w) {
            if (w->removeme) {
                freez(w);
                global_process_stats[pid] = NULL;
                bpf_map_delete_elem(pid_fd, &pid);
            }
        }

        pids = pids->next;
    }
}
 */

/*****************************************************************
 *
 *  READ INFORMATION FROM KERNEL RING
 *
 *****************************************************************/

/*****************************************************************
 *
 *  FUNCTIONS TO CREATE CHARTS
 *
 *****************************************************************/

/**
 * Create IO chart
 *
 * @param family the chart family
 * @param name   the chart name
 * @param axis   the axis label
 * @param web    the group name used to attach the chart on dashboard
 * @param order  the order number of the specified chart
 * @param algorithm the algorithm used to make the charts.
 */
static void ebpf_create_io_chart(char *family, char *name, char *axis, char *web, int order, int algorithm)
{
    printf("CHART %s.%s '' 'Bytes written and read' '%s' '%s' '' line %d %d\n",
           family,
           name,
           axis,
           web,
           order,
           update_every);

    printf("DIMENSION %s %s %s 1 1\n",
           vfs_id_names[NETDATA_KEY_PUBLISH_VFS_READ],
           vfs_dimension_names[NETDATA_KEY_PUBLISH_VFS_READ],
           ebpf_algorithms[algorithm]);
    printf("DIMENSION %s %s %s 1 1\n",
           vfs_id_names[NETDATA_KEY_PUBLISH_VFS_WRITE],
           vfs_dimension_names[NETDATA_KEY_PUBLISH_VFS_WRITE],
           ebpf_algorithms[algorithm]);
}

/**
 * Create global charts
 *
 * Call ebpf_create_chart to create the charts for the collector.
 *
 * @param em a pointer to the structure with the default values.
 */
static void ebpf_create_global_charts(ebpf_module_t *em)
{
    ebpf_create_chart(NETDATA_FILESYSTEM_FAMILY,
                      NETDATA_VFS_FILE_CLEAN_COUNT,
                      "Remove files",
                      EBPF_COMMON_DIMENSION_CALL,
                      NETDATA_VFS_GROUP,
                      NULL,
                      NETDATA_EBPF_CHART_TYPE_LINE,
                      21000,
                      ebpf_create_global_dimension,
                      &vfs_publish_aggregated[NETDATA_KEY_PUBLISH_VFS_UNLINK],
                      1);

    ebpf_create_chart(NETDATA_FILESYSTEM_FAMILY,
                      NETDATA_VFS_FILE_IO_COUNT,
                      "Calls to IO",
                      EBPF_COMMON_DIMENSION_CALL,
                      NETDATA_VFS_GROUP,
                      NULL,
                      NETDATA_EBPF_CHART_TYPE_LINE,
                      21001,
                      ebpf_create_global_dimension,
                      &vfs_publish_aggregated[NETDATA_KEY_PUBLISH_VFS_READ],
                      2);

    ebpf_create_io_chart(NETDATA_FILESYSTEM_FAMILY,
                         NETDATA_VFS_IO_FILE_BYTES, EBPF_COMMON_DIMENSION_BYTES,
                         NETDATA_VFS_GROUP,
                         21002,
                         NETDATA_EBPF_INCREMENTAL_IDX);

    if (em->mode < MODE_ENTRY) {
        ebpf_create_chart(NETDATA_FILESYSTEM_FAMILY,
                          NETDATA_VFS_FILE_ERR_COUNT,
                          "Fails to write or read",
                          EBPF_COMMON_DIMENSION_CALL,
                          NETDATA_VFS_GROUP,
                          NULL,
                          NETDATA_EBPF_CHART_TYPE_LINE,
                          21003,
                          ebpf_create_global_dimension,
                          &vfs_publish_aggregated[NETDATA_KEY_PUBLISH_VFS_READ],
                          2);
    }
}

/**
 * Create process apps charts
 *
 * Call ebpf_create_chart to create the charts on apps submenu.
 *
 * @param em   a pointer to the structure with the default values.
 * @param ptr  a pointer for the targets.
 **/
void ebpf_vfs_create_apps_charts(struct ebpf_module *em, void *ptr)
{
    struct target *root = ptr;

    ebpf_create_charts_on_apps(NETDATA_SYSCALL_APPS_FILE_DELETED,
                               "Files deleted",
                               EBPF_COMMON_DIMENSION_CALL,
                               NETDATA_APPS_VFS_GROUP,
                               NETDATA_EBPF_CHART_TYPE_STACKED,
                               20065,
                               ebpf_algorithms[NETDATA_EBPF_INCREMENTAL_IDX],
                               root);

    ebpf_create_charts_on_apps(NETDATA_SYSCALL_APPS_VFS_WRITE_CALLS,
                               "Write to disk",
                               EBPF_COMMON_DIMENSION_CALL,
                               NETDATA_APPS_VFS_GROUP,
                               NETDATA_EBPF_CHART_TYPE_STACKED,
                               20066,
                               ebpf_algorithms[NETDATA_EBPF_INCREMENTAL_IDX],
                               apps_groups_root_target);

    if (em->mode < MODE_ENTRY) {
        ebpf_create_charts_on_apps(NETDATA_SYSCALL_APPS_VFS_WRITE_CALLS_ERROR,
                                   "Fails to write",
                                   EBPF_COMMON_DIMENSION_CALL,
                                   NETDATA_APPS_VFS_GROUP,
                                   NETDATA_EBPF_CHART_TYPE_STACKED,
                                   20067,
                                   ebpf_algorithms[NETDATA_EBPF_INCREMENTAL_IDX],
                                   root);
    }

    ebpf_create_charts_on_apps(NETDATA_SYSCALL_APPS_VFS_READ_CALLS,
                               "Read from disk",
                               EBPF_COMMON_DIMENSION_CALL,
                               NETDATA_APPS_VFS_GROUP,
                               NETDATA_EBPF_CHART_TYPE_STACKED,
                               20068,
                               ebpf_algorithms[NETDATA_EBPF_INCREMENTAL_IDX],
                               root);

    if (em->mode < MODE_ENTRY) {
        ebpf_create_charts_on_apps(NETDATA_SYSCALL_APPS_VFS_READ_CALLS_ERROR,
                                   "Fails to read",
                                   EBPF_COMMON_DIMENSION_CALL,
                                   NETDATA_APPS_VFS_GROUP,
                                   NETDATA_EBPF_CHART_TYPE_STACKED,
                                   20069,
                                   ebpf_algorithms[NETDATA_EBPF_INCREMENTAL_IDX],
                                   root);
    }

    ebpf_create_charts_on_apps(NETDATA_SYSCALL_APPS_VFS_WRITE_BYTES,
                               "Bytes written on disk", EBPF_COMMON_DIMENSION_BYTES,
                               NETDATA_APPS_VFS_GROUP,
                               NETDATA_EBPF_CHART_TYPE_STACKED,
                               20070,
                               ebpf_algorithms[NETDATA_EBPF_INCREMENTAL_IDX],
                               root);

    ebpf_create_charts_on_apps(NETDATA_SYSCALL_APPS_VFS_READ_BYTES,
                               "Bytes read from disk", EBPF_COMMON_DIMENSION_BYTES,
                               NETDATA_APPS_VFS_GROUP,
                               NETDATA_EBPF_CHART_TYPE_STACKED,
                               20071,
                               ebpf_algorithms[NETDATA_EBPF_INCREMENTAL_IDX],
                               root);
}

/*****************************************************************
 *
 *  FUNCTIONS WITH THE MAIN LOOP
 *
 *****************************************************************/

/**
 * Sum PIDs
 *
 * Sum values for all targets.
 *
 * @param swap output structure
 * @param root link list with structure to be used
 */
static void ebpf_vfs_sump_pids(netdata_publish_vfs_t *vfs, struct pid_on_target *root)
{
    uint32_t local_write_call = 0;
    uint32_t local_writev_call = 0;
    uint32_t local_read_call = 0;
    uint32_t local_readv_call = 0;
    uint32_t local_unlink_call = 0;

    uint64_t local_write_bytes = 0;
    uint64_t local_writev_bytes = 0;
    uint64_t local_read_bytes = 0;
    uint64_t local_readv_bytes = 0;

    uint32_t local_write_err = 0;
    uint32_t local_writev_err = 0;
    uint32_t local_read_err = 0;
    uint32_t local_readv_err = 0;
    uint32_t local_unlink_err = 0;

    while (root) {
        int32_t pid = root->pid;
        netdata_publish_vfs_t *w = vfs_pid[pid];
        if (w) {
            local_write_call += w->write_call;
            local_writev_call += w->writev_call;
            local_read_call += w->read_call;
            local_readv_call += w->readv_call;
            local_unlink_call += w->unlink_call;

            local_write_bytes += w->write_bytes;
            local_writev_bytes += w->writev_bytes;
            local_read_bytes += w->read_bytes;
            local_readv_bytes += w->readv_bytes;

            local_write_err += w->write_err;
            local_writev_err += w->writev_err;
            local_read_err += w->read_err;
            local_readv_err += w->readv_err;
            local_unlink_err += w->unlink_err;
        }
        root = root->next;
    }

    // These conditions were added, because we are using incremental algorithm
    vfs->write_call = (local_write_call >= vfs->write_call) ? local_write_call : vfs->write_call;
    vfs->writev_call = (local_writev_call >= vfs->writev_call) ? local_writev_call : vfs->writev_call;
    vfs->read_call = (local_read_call >= vfs->read_call) ? local_read_call : vfs->read_call;
    vfs->readv_call = (local_readv_call >= vfs->readv_call) ? local_readv_call : vfs->readv_call;
    vfs->unlink_call = (local_unlink_call >= vfs->unlink_call) ? local_unlink_call : vfs->unlink_call;

    vfs->write_bytes = (local_write_bytes >= vfs->write_bytes) ? local_write_bytes : vfs->write_bytes;
    vfs->writev_bytes = (local_writev_bytes >= vfs->writev_bytes) ? local_writev_bytes : vfs->writev_bytes;
    vfs->read_bytes = (local_read_bytes >= vfs->read_bytes) ? local_read_bytes : vfs->read_bytes;
    vfs->readv_bytes = (local_readv_bytes >= vfs->readv_bytes) ? local_readv_bytes : vfs->readv_bytes;

    vfs->write_err = (local_write_err >= vfs->write_err) ? local_write_err : vfs->write_err;
    vfs->writev_err = (local_writev_err >= vfs->writev_err) ? local_writev_err : vfs->writev_err;
    vfs->read_err = (local_read_err >= vfs->read_err) ? local_read_err : vfs->read_err;
    vfs->readv_err = (local_readv_err >= vfs->readv_err) ? local_readv_err : vfs->readv_err;
    vfs->unlink_err = (local_unlink_err >= vfs->unlink_err) ? local_unlink_err : vfs->unlink_err;
}

/**
 * Send data to Netdata calling auxiliar functions.
 *
 * @param em   the structure with thread information
 * @param root the target list.
 */
void ebpf_vfs_send_apps_data(ebpf_module_t *em, struct target *root)
{
    struct target *w;
    for (w = root; w; w = w->next) {
        if (unlikely(w->exposed && w->processes)) {
            ebpf_vfs_sump_pids(&w->vfs, w->root_pid);
        }
    }

    write_begin_chart(NETDATA_APPS_FAMILY, NETDATA_SYSCALL_APPS_FILE_DELETED);
    for (w = root; w; w = w->next) {
        if (unlikely(w->exposed && w->processes)) {
            write_chart_dimension(w->name, w->vfs.unlink_call);
        }
    }
    write_end_chart();

    write_begin_chart(NETDATA_APPS_FAMILY, NETDATA_SYSCALL_APPS_VFS_WRITE_CALLS);
    for (w = root; w; w = w->next) {
        if (unlikely(w->exposed && w->processes)) {
            write_chart_dimension(w->name, w->vfs.write_call + w->vfs.writev_call);
        }
    }
    write_end_chart();

    if (em->mode < MODE_ENTRY) {
        write_begin_chart(NETDATA_APPS_FAMILY, NETDATA_SYSCALL_APPS_VFS_WRITE_CALLS_ERROR);
        for (w = root; w; w = w->next) {
            if (unlikely(w->exposed && w->processes)) {
                write_chart_dimension(w->name, w->vfs.write_err + w->vfs.writev_err);
            }
        }
        write_end_chart();
    }

    write_begin_chart(NETDATA_APPS_FAMILY, NETDATA_SYSCALL_APPS_VFS_READ_CALLS);
    for (w = root; w; w = w->next) {
        if (unlikely(w->exposed && w->processes)) {
            write_chart_dimension(w->name, w->vfs.read_call + w->vfs.readv_call);
        }
    }
    write_end_chart();

    if (em->mode < MODE_ENTRY) {
        write_begin_chart(NETDATA_APPS_FAMILY, NETDATA_SYSCALL_APPS_VFS_READ_CALLS_ERROR);
        for (w = root; w; w = w->next) {
            if (unlikely(w->exposed && w->processes)) {
                write_chart_dimension(w->name, w->vfs.read_err + w->vfs.readv_err);
            }
        }
        write_end_chart();
    }

    write_begin_chart(NETDATA_APPS_FAMILY, NETDATA_SYSCALL_APPS_VFS_WRITE_BYTES);
    for (w = root; w; w = w->next) {
        if (unlikely(w->exposed && w->processes)) {
            write_chart_dimension(w->name, w->vfs.write_bytes + w->vfs.writev_bytes);
        }
    }
    write_end_chart();

    write_begin_chart(NETDATA_APPS_FAMILY, NETDATA_SYSCALL_APPS_VFS_READ_BYTES);
    for (w = root; w; w = w->next) {
        if (unlikely(w->exposed && w->processes)) {
            write_chart_dimension(w->name, w->vfs.read_bytes + w->vfs.readv_bytes);
        }
    }
    write_end_chart();
}


/**
 * Apps Accumulator
 *
 * Sum all values read from kernel and store in the first address.
 *
 * @param out the vector with read values.
 */
static void vfs_apps_accumulator(netdata_publish_vfs_t *out)
{
    int i, end = (running_on_kernel >= NETDATA_KERNEL_V4_15) ? ebpf_nprocs : 1;
    netdata_publish_vfs_t *total = &out[0];
    for (i = 1; i < end; i++) {
        netdata_publish_vfs_t *w = &out[i];

        total->write_call += w->write_call;
        total->writev_call += w->writev_call;
        total->read_call += w->read_call;
        total->readv_call += w->readv_call;
        total->unlink_call += w->unlink_call;

        total->write_bytes += w->write_bytes;
        total->writev_bytes += w->writev_bytes;
        total->read_bytes += w->read_bytes;
        total->readv_bytes += w->readv_bytes;

        total->write_err += w->write_err;
        total->writev_err += w->writev_err;
        total->read_err += w->read_err;
        total->readv_err += w->readv_err;
        total->unlink_err += w->unlink_err;
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
static void vfs_fill_pid(uint32_t current_pid, netdata_publish_vfs_t *publish)
{
    netdata_publish_vfs_t *curr = vfs_pid[current_pid];
    if (!curr) {
        curr = callocz(1, sizeof(netdata_publish_vfs_t));
        vfs_pid[current_pid] = curr;
    }

    memcpy(curr, &publish[0], sizeof(netdata_publish_vfs_t));
}

/**
 * Read the hash table and store data to allocated vectors.
 */
static void ebpf_vfs_read_apps()
{
    struct pid_stat *pids = root_of_pids;
    netdata_publish_vfs_t *vv = vfs_vector;
    int fd = map_fd[NETDATA_VFS_PID];
    size_t length = sizeof(netdata_publish_vfs_t) * ebpf_nprocs;
    while (pids) {
        uint32_t key = pids->pid;

        if (bpf_map_lookup_elem(fd, &key, vv)) {
            pids = pids->next;
            continue;
        }

        vfs_apps_accumulator(vv);

        vfs_fill_pid(key, vv);

        // We are cleaning to avoid passing data read from one process to other.
        memset(vv, 0, length);

        pids = pids->next;
    }
}

/**
 * Send data to Netdata calling auxiliar functions.
 *
 * @param em the structure with thread information
*/
static void ebpf_vfs_send_data(ebpf_module_t *em)
{
    netdata_publish_vfs_common_t pvc;

    pvc.write = -((long)vfs_publish_aggregated[NETDATA_KEY_PUBLISH_VFS_WRITE].nbyte);
    pvc.read = (long)vfs_publish_aggregated[NETDATA_KEY_PUBLISH_VFS_READ].nbyte;

    write_count_chart(NETDATA_VFS_FILE_CLEAN_COUNT, NETDATA_FILESYSTEM_FAMILY,
                      &vfs_publish_aggregated[NETDATA_KEY_PUBLISH_VFS_UNLINK], 1);

    write_count_chart(NETDATA_VFS_FILE_IO_COUNT, NETDATA_FILESYSTEM_FAMILY,
                      &vfs_publish_aggregated[NETDATA_KEY_PUBLISH_VFS_READ], 2);

    if (em->mode < MODE_ENTRY) {
        write_err_chart(NETDATA_VFS_FILE_ERR_COUNT, NETDATA_FILESYSTEM_FAMILY,
                        vfs_publish_aggregated, NETDATA_VFS_ERRORS);
    }

    write_io_chart(NETDATA_VFS_IO_FILE_BYTES, NETDATA_FILESYSTEM_FAMILY,
                   vfs_id_names[NETDATA_KEY_PUBLISH_VFS_WRITE], (long long) pvc.write,
                   vfs_id_names[NETDATA_KEY_PUBLISH_VFS_READ], (long long)pvc.read);
}


/**
 * Read the hash table and store data to allocated vectors.
 */
static void read_global_table()
{
    uint64_t idx;
    netdata_idx_t res[NETDATA_VFS_COUNTER];

    netdata_idx_t *val = vfs_hash_values;
    for (idx = 0; idx < NETDATA_VFS_COUNTER; idx++) {
        uint64_t total = 0;
        if (!bpf_map_lookup_elem(map_fd[NETDATA_VFS_ALL], &idx, val)) {
            int i;
            int end = (running_on_kernel < NETDATA_KERNEL_V4_15) ? 1 : ebpf_nprocs;
            for (i = 0; i < end; i++)
                total += val[i];
        }
        res[idx] = total;
        error("KILLME %lu", total);
    }

    vfs_aggregated_data[NETDATA_KEY_PUBLISH_VFS_UNLINK].call = res[NETDATA_KEY_CALLS_VFS_UNLINK];
    vfs_aggregated_data[NETDATA_KEY_PUBLISH_VFS_READ].call = res[NETDATA_KEY_CALLS_VFS_READ] + res[NETDATA_KEY_CALLS_VFS_READV];
    vfs_aggregated_data[NETDATA_KEY_PUBLISH_VFS_WRITE].call = res[NETDATA_KEY_CALLS_VFS_WRITE] + res[NETDATA_KEY_CALLS_VFS_WRITEV];

    vfs_aggregated_data[NETDATA_KEY_PUBLISH_VFS_UNLINK].ecall = res[NETDATA_KEY_ERROR_VFS_UNLINK];
    vfs_aggregated_data[NETDATA_KEY_PUBLISH_VFS_READ].ecall = res[NETDATA_KEY_ERROR_VFS_READ] + res[NETDATA_KEY_ERROR_VFS_READV];
    vfs_aggregated_data[NETDATA_KEY_PUBLISH_VFS_WRITE].ecall = res[NETDATA_KEY_ERROR_VFS_WRITE] + res[NETDATA_KEY_ERROR_VFS_WRITEV];

    vfs_aggregated_data[NETDATA_KEY_PUBLISH_VFS_WRITE].bytes = (uint64_t)res[NETDATA_KEY_BYTES_VFS_WRITE] +
                                       (uint64_t)res[NETDATA_KEY_BYTES_VFS_WRITEV];
    vfs_aggregated_data[NETDATA_KEY_PUBLISH_VFS_READ].bytes = (uint64_t)res[NETDATA_KEY_BYTES_VFS_READ] +
                                       (uint64_t)res[NETDATA_KEY_BYTES_VFS_READV];
}

/**
 * DCstat read hash
 *
 * This is the thread callback.
 * This thread is necessary, because we cannot freeze the whole plugin to read the data.
 *
 * @param ptr It is a NULL value for this thread.
 *
 * @return It always returns NULL.
 */
void *ebpf_vfs_read_hash(void *ptr)
{
    read_thread_closed = 0;

    heartbeat_t hb;
    heartbeat_init(&hb);

    ebpf_module_t *em = (ebpf_module_t *)ptr;

    usec_t step = NETDATA_LATENCY_VFS_SLEEP_MS * em->update_time;
    while (!close_ebpf_plugin) {
        usec_t dt = heartbeat_next(&hb, step);
        (void)dt;

        read_global_table();
    }

    read_thread_closed = 1;

    return NULL;
}

/**
 * Main loop for this collector.
 *
 * @param step the number of microseconds used with heart beat
 * @param em   the structure with thread information
 */
static void vfs_collector(ebpf_module_t *em)
{
    vfs_threads.thread = mallocz(sizeof(netdata_thread_t));
    vfs_threads.start_routine = ebpf_vfs_read_hash;

    map_fd = vfs_data.map_fd;

    netdata_thread_create(vfs_threads.thread, vfs_threads.name, NETDATA_THREAD_OPTION_JOINABLE,
                          ebpf_vfs_read_hash, em);

    int apps = em->apps_charts;
    while (!close_ebpf_plugin) {
        pthread_mutex_lock(&collect_data_mutex);
        pthread_cond_wait(&collect_data_cond_var, &collect_data_mutex);

        if (apps)
            ebpf_vfs_read_apps();

        pthread_mutex_lock(&lock);

        ebpf_vfs_send_data(em);
        fflush(stdout);

        if (apps)
            ebpf_vfs_send_apps_data(em, apps_groups_root_target);

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
 * Clean PID structures
 *
 * Clean the allocated structures.
 */
void clean_vfs_pid_structures() {
    struct pid_stat *pids = root_of_pids;
    while (pids) {
        freez(vfs_pid[pids->pid]);

        pids = pids->next;
    }
}

/**
* Clean up the main thread.
*
* @param ptr thread data.
**/
static void ebpf_vfs_cleanup(void *ptr)
{
    ebpf_module_t *em = (ebpf_module_t *)ptr;
    if (!em->enabled)
        return;

    heartbeat_t hb;
    heartbeat_init(&hb);
    uint32_t tick = 50 * USEC_PER_MS;
    while (!finalized_threads) {
        usec_t dt = heartbeat_next(&hb, tick);
        UNUSED(dt);
    }

    freez(vfs_data.map_fd);
    freez(vfs_hash_values);
    freez(vfs_vector);

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
 * Allocate vectors used with this thread.
 * We are not testing the return, because callocz does this and shutdown the software
 * case it was not possible to allocate.
 *
 *  @param length is the length for the vectors used inside the collector.
 */
static void ebpf_vfs_allocate_global_vectors()
{
    memset(vfs_aggregated_data, 0, sizeof(vfs_aggregated_data));
    memset(vfs_publish_aggregated, 0, sizeof(vfs_publish_aggregated));

    vfs_hash_values = callocz(ebpf_nprocs, sizeof(netdata_idx_t));
    vfs_vector = callocz(ebpf_nprocs, sizeof(netdata_publish_vfs_t));
    vfs_pid = callocz((size_t)pid_max, sizeof(netdata_publish_vfs_t *));
}

/*****************************************************************
 *
 *  EBPF PROCESS THREAD
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
void *ebpf_vfs_thread(void *ptr)
{
    netdata_thread_cleanup_push(ebpf_vfs_cleanup, ptr);

    ebpf_module_t *em = (ebpf_module_t *)ptr;
    em->maps = vfs_maps;
    fill_ebpf_data(&vfs_data);

    ebpf_update_module(em, &vfs_config, NETDATA_DIRECTORY_VFS_CONFIG_FILE);
    ebpf_update_pid_table(&vfs_maps[0], em);

    if (!em->enabled)
        goto endvfs;

    ebpf_vfs_allocate_global_vectors();

    probe_links = ebpf_load_program(ebpf_plugin_dir, em, kernel_string, &objects, vfs_data.map_fd);
    if (!probe_links) {
        goto endvfs;
    }

    int algorithms[NETDATA_KEY_PUBLISH_PROCESS_END] = {
        NETDATA_EBPF_INCREMENTAL_IDX, NETDATA_EBPF_INCREMENTAL_IDX,NETDATA_EBPF_INCREMENTAL_IDX };

    ebpf_global_labels(vfs_aggregated_data, vfs_publish_aggregated, vfs_dimension_names,
                       vfs_id_names, algorithms, NETDATA_KEY_PUBLISH_VFS_END);

    pthread_mutex_lock(&lock);
    ebpf_create_global_charts(em);
    pthread_mutex_unlock(&lock);

    vfs_collector(em);

endvfs:
    netdata_thread_cleanup_pop(1);
    return NULL;
}
