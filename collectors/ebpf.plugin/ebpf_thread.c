// SPDX-License-Identifier: GPL-3.0-or-later

#include "ebpf.h"
#include "ebpf_thread.h"

ebpf_local_maps_t thread_maps[] = {{.name = "bug_sizes", .internal_input = NETDATA_EBPF_BUGS_COMMON_LIMIT,
                                       .user_input = 0, .type = NETDATA_EBPF_MAP_STATIC,
                                       .map_fd = ND_EBPF_MAP_FD_NOT_INITIALIZED,
#ifdef LIBBPF_MAJOR_VERSION
                                       .map_type = BPF_MAP_TYPE_PERCPU_HASH
#endif
                                      },
                                      {.name = "bugs_ctrl", .internal_input = NETDATA_CONTROLLER_END,
                                       .user_input = 0,
                                       .type = NETDATA_EBPF_MAP_CONTROLLER,
                                       .map_fd = ND_EBPF_MAP_FD_NOT_INITIALIZED,
#ifdef LIBBPF_MAJOR_VERSION
                                        .map_type = BPF_MAP_TYPE_PERCPU_ARRAY
#endif
                                      },
                                      {.name = "bug_stat", .internal_input = ND_EBPF_DEFAULT_PID_SIZE,
                                       .user_input = 0,
                                       .type = NETDATA_EBPF_MAP_RESIZABLE | NETDATA_EBPF_MAP_PID,
                                       .map_fd = ND_EBPF_MAP_FD_NOT_INITIALIZED,
#ifdef LIBBPF_MAJOR_VERSION
                                        .map_type = BPF_MAP_TYPE_PERCPU_HASH
#endif
                                       },
                                      {.name = "bug_addr", .internal_input = ND_EBPF_DEFAULT_PID_SIZE,
                                       .user_input = 0,
                                       .type = NETDATA_EBPF_MAP_RESIZABLE | NETDATA_EBPF_MAP_PID,
                                       .map_fd = ND_EBPF_MAP_FD_NOT_INITIALIZED,
#ifdef LIBBPF_MAJOR_VERSION
                                       .map_type = BPF_MAP_TYPE_PERCPU_HASH
#endif
                                      },
                                      {.name = "bugs_memptrs", .internal_input = NETDATA_EBPF_BUGS_COMMON_LIMIT,
                                       .user_input = 0,
                                       .type = NETDATA_EBPF_MAP_STATIC,
                                       .map_fd = ND_EBPF_MAP_FD_NOT_INITIALIZED,
#ifdef LIBBPF_MAJOR_VERSION
                                       .map_type = BPF_MAP_TYPE_PERCPU_HASH
#endif
                                       },
                                      {.name = "bugs_overflow", .internal_input = NETDATA_EBPF_BUGS_COMMON_LIMIT,
                                       .user_input = 0,
                                       .type = NETDATA_EBPF_MAP_STATIC,
                                       .map_fd = ND_EBPF_MAP_FD_NOT_INITIALIZED,
#ifdef LIBBPF_MAJOR_VERSION
                                        .map_type = BPF_MAP_TYPE_PERCPU_HASH
#endif
                                      },
                                      {.name = NULL, .internal_input = 0, .user_input = 0,
                                        .type = NETDATA_EBPF_MAP_CONTROLLER,
                                        .map_fd = ND_EBPF_MAP_FD_NOT_INITIALIZED,
}};

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

const char *libc_path = NULL;
const char *app_name = NULL;
static uint32_t monitor_pid = 0;

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
 * Parse table size options
 *
 * @param cfg configuration options read from user file.
 */
void ebpf_parse_thread_opt(struct config *cfg)
{
    libc_path = appconfig_get(cfg,
                             EBPF_GLOBAL_SECTION,
                             NETDATA_EBPF_C_LIBRARY_OPT_PATH,
                             NETDATA_EBPF_C_LIBRARY_PATH);

    app_name = appconfig_get(cfg,
                              EBPF_GLOBAL_SECTION, NETDATA_EBPF_C_MONITOR_APP,
                              NULL);

    monitor_pid = (uint32_t)appconfig_get_number(cfg,
                               EBPF_GLOBAL_SECTION,
                               NETDATA_EBPF_C_PID_SELECT,
                               monitor_pid);

    if (app_name) {
        monitor_pid =  ebpf_find_pid(app_name);
    }

    if (!monitor_pid) {
        monitor_pid = getppid();
    }

#ifdef NETDATA_DEV_MODE
    collector_info("It was found the PID %u for process name %s", monitor_pid, app_name);
#endif
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

    ebpf_module_t *em = (ebpf_module_t *)ptr;
    em->maps = thread_maps;

    ebpf_parse_thread_opt(&thread_config);

    netdata_thread_cleanup_pop(1);
    return NULL;
}
