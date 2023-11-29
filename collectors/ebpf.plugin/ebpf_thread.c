// SPDX-License-Identifier: GPL-3.0-or-later

#include "ebpf.h"
#include "ebpf_thread.h"

struct config thread_config = { .first_section = NULL,
    .last_section = NULL,
    .mutex = NETDATA_MUTEX_INITIALIZER,
    .index = { .avl_tree = { .root = NULL, .compar = appconfig_section_compare },
        .rwlock = AVL_LOCK_INITIALIZER } };

netdata_ebpf_targets_t thread_targets[] = { {.name = "malloc", .mode = EBPF_LOAD_PROBE},
                                          {.name = "malloc", .mode = EBPF_LOAD_RETPROBE},
                                          {.name = "free", .mode = EBPF_LOAD_PROBE},
                                          {.name = "calloc", .mode = EBPF_LOAD_PROBE},
                                          {.name = "calloc", .mode = EBPF_LOAD_RETPROBE},
                                          {.name = "realloc", .mode = EBPF_LOAD_PROBE},
                                          {.name = "realloc", .mode = EBPF_LOAD_RETPROBE},
                                          {.name = "mmap", .mode = EBPF_LOAD_PROBE},
                                          {.name = "mmap", .mode = EBPF_LOAD_RETPROBE},
                                          {.name = "munmap", .mode = EBPF_LOAD_PROBE},
                                          {.name = "posix_memalign", .mode = EBPF_LOAD_PROBE},
                                          {.name = "posix_memalign", .mode = EBPF_LOAD_RETPROBE},
                                          {.name = "memalign", .mode = EBPF_LOAD_PROBE},
                                          {.name = "memalign", .mode = EBPF_LOAD_RETPROBE},
                                          {.name = "sprintf", .mode = EBPF_LOAD_RETPROBE},
                                          {.name = "sprintf", .mode = EBPF_LOAD_RETPROBE},
                                          {.name = "snprintf", .mode = EBPF_LOAD_RETPROBE},
                                          {.name = "snprintf", .mode = EBPF_LOAD_RETPROBE},
                                          {.name = "vfprintf", .mode = EBPF_LOAD_RETPROBE},
                                          {.name = "vfprintf", .mode = EBPF_LOAD_RETPROBE},
                                          {.name = "memcpy", .mode = EBPF_LOAD_RETPROBE},
                                          {.name = "memcpy", .mode = EBPF_LOAD_RETPROBE},
                                          {.name = "release_task", .mode = EBPF_LOAD_TRAMPOLINE},
                                          {.name = NULL, .mode = EBPF_LOAD_TRAMPOLINE}};

/**
 * Cachestat exit.
 *
 * Cancel child and exit.
 *
 * @param ptr thread data.
 */
static void ebpf_thread_exit(void *ptr)
{
    (void)ptr;
}

/**
 * Cachestat thread
 *
 * Thread used to make cachestat thread
 *
 * @param ptr a pointer to `struct ebpf_module`
 *
 * @return It always return NULL
 */
void *ebpf_thread_monitoring(void *ptr)
{
    netdata_thread_cleanup_push(ebpf_thread_exit, ptr);

    netdata_thread_cleanup_pop(1);
    return NULL;
}
