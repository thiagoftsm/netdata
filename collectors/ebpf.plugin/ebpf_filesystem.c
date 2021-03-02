// SPDX-License-Identifier: GPL-3.0-or-later

#include "ebpf.h"
#include "ebpf_filesystem.h"

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

endfilesystem:
    netdata_thread_cleanup_pop(1);
    return NULL;
}