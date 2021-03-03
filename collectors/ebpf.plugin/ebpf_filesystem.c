// SPDX-License-Identifier: GPL-3.0-or-later

#include "ebpf.h"
#include "ebpf_filesystem.h"

static ebpf_data_t io_latency_data;
ebpf_filesystem_partitions_t localfs[] = {
    {.filesystem = "ext4", .partitions = 0},
    {.filesystem = NULL, .partitions = 0}
};

/*****************************************************************
 *
 *  COMMON FUNCTIONS
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
        error("KILLME %s", fs);
        for (i = 0; localfs[i].filesystem; i++) {
            if (!strcmp(fs, localfs[i].filesystem)) {
                localfs[i].partitions++;
                count++;
                break;
            }
        }
    }

    return count;
}

/*****************************************************************
 *
 *  CLEANUP FUNCTIONS
 *
 *****************************************************************/

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

/*****************************************************************
 *
 *  EBPF FILESYSTEM THREAD
 *
 *****************************************************************/

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
    if (!em->enabled)
        goto endfilesystem;

    fill_ebpf_data(&io_latency_data);
    if (!read_local_partitions()) {
        em->enabled = 0;
        info("Netdata cannot monitor the filesystems used on this host.");
        goto endfilesystem;
    }

endfilesystem:
    netdata_thread_cleanup_pop(1);
    return NULL;
}