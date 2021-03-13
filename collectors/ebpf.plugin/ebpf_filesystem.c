// SPDX-License-Identifier: GPL-3.0-or-later

#include "ebpf_filesystem.h"

ebpf_filesystem_partitions_t localfs[] = {
    {.filesystem = "ext4", .family = "EXT4", .partitions = 0, .objects = NULL, .probe_links = NULL,
      .flags = NETDATA_FILESYSTEM_FLAG_NO_PARTITION},
    {.filesystem = "xfs", .family = "XFS", .partitions = 0, .objects = NULL, .probe_links = NULL,
      .flags = NETDATA_FILESYSTEM_FLAG_NO_PARTITION},
    {.filesystem = "nfs", .family = "NFS", .partitions = 0, .objects = NULL, .probe_links = NULL,
      .flags = NETDATA_FILESYSTEM_FLAG_NO_PARTITION},
    {.filesystem = NULL, .family = NULL, .partitions = 0, .objects = NULL, .probe_links = NULL,
      .flags = NETDATA_FILESYSTEM_FLAG_NO_PARTITION},
};

struct config fs_config = { .first_section = NULL,
    .last_section = NULL,
    .mutex = NETDATA_MUTEX_INITIALIZER,
    .index = { .avl_tree = { .root = NULL, .compar = appconfig_section_compare },
        .rwlock = AVL_LOCK_INITIALIZER } };

char **dimensions = NULL;

static netdata_syscall_stat_t *filesystem_aggregated_data = NULL;
static netdata_publish_syscall_t *filesystem_publish_aggregated = NULL;

static int read_thread_closed = 1;
static netdata_idx_t *filesystem_hash_values = NULL;

/**
 * Reset the partition counts
 */
static inline void ebpf_reset_partitions()
{
    int i;
    for (i = 0; localfs[i]; i++) {
        ebpf_filesystem_partitions_t *w = &localfs[i];
        w->partitions = 0;
        w->flags &= ~NETDATA_FILESYSTEM_FLAG_HAS_PARTITION;
    }
}

/**
 * Read Local partitions
 *
 * @return  the total of partitions that will be monitored
 */
static int ebpf_read_local_partitions()
{
    ebpf_reset_partitions();

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

/**
 * Initialize eBPF data
 *
 * @param em  main thread structure.
 *
 * @return it returns 0 on success and -1 otherwise.
 */
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

    if (!dimensions) {
        dimensions = ebpf_fill_histogram_dimension(NETDATA_FILESYSTEM_MAX_BINS);

        filesystem_aggregated_data = callocz(NETDATA_FILESYSTEM_MAX_BINS, sizeof(netdata_syscall_stat_t));
        filesystem_publish_aggregated = callocz(NETDATA_FILESYSTEM_MAX_BINS, sizeof(netdata_publish_syscall_t));

        filesystem_hash_values = callocz(ebpf_nprocs, sizeof(netdata_idx_t));
    }

    return 0;
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

    ebpf_module_t *em = (ebpf_module_t *)ptr;
    ebpf_load_config_update_module(em, &fs_config, NETDATA_FILESYSTEM_CONFIG_FILE);

    if (!em->enabled)
        goto endfilesystem;

    if (!ebpf_read_local_partitions()) {
        em->enabled = 0;
        info("Netdata cannot monitor the filesystems used on this host.");
        goto endfilesystem;
    }

    if (ebpf_filesystem_initialize_ebpf_data(em)) {
        goto endfilesystem;
    }

endfilesystem:
    netdata_thread_cleanup_pop(1);
    return NULL;
}
