// SPDX-License-Identifier: GPL-3.0-or-later

#include <sys/resource.h>

#include "ebpf.h"
#include "ebpf_latency.h"

/*****************************************************************
 *
 *  FUNCTIONS TO CLOSE THE THREAD
 *
 *****************************************************************/

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

    netdata_thread_cleanup_pop(1);
    return NULL;
}