// SPDX-License-Identifier: GPL-3.0-or-later

#include "ebpf_filesystem.h"

ebpf_filesystem_partitions_t localfs[] = {
    {.filesystem = "ext4", .family = "EXT4", .partitions = 0, .objects = NULL, .probe_links = NULL},
    {.filesystem = "xfs", .family = "XFS", .partitions = 0, .objects = NULL, .probe_links = NULL},
    {.filesystem = "nfs", .family = "NFS", .partitions = 0, .objects = NULL, .probe_links = NULL},
    {.filesystem = NULL, .family = NULL, .partitions = 0, .objects = NULL, .probe_links = NULL}
};

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

    endfilesystem:
    netdata_thread_cleanup_pop(1);
    return NULL;
}
