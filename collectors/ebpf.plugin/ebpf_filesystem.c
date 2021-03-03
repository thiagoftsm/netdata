// SPDX-License-Identifier: GPL-3.0-or-later

#include "ebpf_filesystem.h"

ebpf_filesystem_partitions_t localfs[] = {
    {.filesystem = "ext4", .partitions = 0, .objects = NULL, .probe_links = NULL},
    {.filesystem = NULL, .partitions = 0, .objects = NULL, .probe_links = NULL}
};

char **dimensions = NULL;

static netdata_syscall_stat_t *filesystem_aggregated_data = NULL;
static netdata_publish_syscall_t *filesystem_publish_aggregated = NULL;

/*****************************************************************
 *
 *  CLEANUP FUNCTIONS
 *
 *****************************************************************/

void ebpf_filesystem_cleanup_ebpf_data()
{
    int i;
    for (i = 0; localfs[i].filesystem; i++) {
        if (localfs[i].partitions) {
            freez(localfs[i].kernel_info.map_fd);

            struct bpf_program *prog;
            ebpf_filesystem_partitions_t *efp = &localfs[i];
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

    freez(filesystem_aggregated_data);
    ebpf_cleanup_publish_syscall(filesystem_publish_aggregated);
    freez(filesystem_publish_aggregated);

    ebpf_histogram_dimension_cleanup(dimensions, NETDATA_EXT4_MAX_BINS);
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
        }
    }
    em->thread_name = save_name;

    dimensions = ebpf_fill_histogram_dimension(NETDATA_EXT4_MAX_BINS);
    filesystem_aggregated_data = callocz(NETDATA_EXT4_MAX_BINS, sizeof(netdata_syscall_stat_t));
    filesystem_publish_aggregated = callocz(NETDATA_EXT4_MAX_BINS, sizeof(netdata_publish_syscall_t));

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
    int algorithms[NETDATA_EXT4_MAX_BINS];

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
    ebpf_set_dimension_algorithm(algorithms, NETDATA_EXT4_MAX_BINS, NETDATA_EBPF_INCREMENTAL_IDX);
    ebpf_global_labels(filesystem_aggregated_data, filesystem_publish_aggregated, dimensions, dimensions,
                algorithms, NETDATA_EXT4_MAX_BINS);

    pthread_mutex_unlock(&lock);

endfilesystem:
    netdata_thread_cleanup_pop(1);
    return NULL;
}