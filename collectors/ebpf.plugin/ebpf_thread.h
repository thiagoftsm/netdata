#ifndef _NETDATA_EBPF_THREAD_H_
# define _NETDATA_EBPF_THREAD_H_ 1

#define NETDATA_EBPF_PID_THREAD_ARAL_TABLE_NAME "ebpf_pid_bug"

#ifdef LIBBPF_MAJOR_VERSION
#include "includes/bugs_memleak.skel.h"
#include "includes/bugs_overflow.skel.h"
#endif

#define NETDATA_BUG_SUBMENU "thread"
#define NETDATA_EBPF_MODULE_NAME_BUG "thread"

enum ebpf_bugs_table {
    NETDATA_BUGS_SIZES,
    NETDATA_BUGS_CTRL,
    NETDATA_BUGS_STAT,
    NETDATA_BUGS_ADDR,
    NETDATA_BUGS_MEMPTRS,
    NETDATA_BUGS_OVERFLOW
};

typedef struct ebpf_mem_stat {
    uint32_t tgid;
    uint32_t uid;
    uint32_t gid;
    char name[TASK_COMM_LEN];

    uint64_t size_allocated;
    uint64_t size_released;

    uint64_t str_copy_entry;

    uint32_t oom;
    uint32_t safe_functions;
    uint32_t unsafe_functions;
    uint64_t signal;

    uint32_t alloc;
    uint32_t released;

    uint32_t stopped;
} ebpf_mem_stat_t;

typedef struct ebpf_mem_publish_stat {
    uint32_t leak;
    uint32_t published;

    ebpf_mem_stat_t data;
} ebpf_mem_publish_stat_t;

#define NETDATA_EBPF_BUGS_COMMON_LIMIT 1024

#define NETDATA_EBPF_THREAD_CONFIG_FILE "thread.conf"

#define NETDATA_EBPF_C_LIBRARY_OPT_PATH "libc path"

#define NETDATA_EBPF_C_MONITOR_APP "monitor app"

#define NETDATA_EBPF_C_PID_SELECT "monitor pid"

#define NETDATA_EBPF_KILL_PID "kill parent pid"

#define __ATTACH_UPROBE(skel, binary_path, pid, sym_name, prog_name, is_retprobe)   \
    do {                                                                       \
        LIBBPF_OPTS(bpf_uprobe_opts, uprobe_opts, .func_name = #sym_name,        \
        .retprobe = is_retprobe);                                    \
        skel->links.prog_name = bpf_program__attach_uprobe_opts(                 \
        skel->progs.prog_name, pid, binary_path, 0, &uprobe_opts);       \
    } while (false)

#define __CHECK_PROGRAM(skel, prog_name)               \
    do {                                               \
        if (!skel->links.prog_name) {                    \
            perror("no program attached for " #prog_name); \
            return -errno;                                 \
        }                                                \
    } while (false)

#define __ATTACH_UPROBE_CHECKED(skel, binary_path, pid, sym_name, prog_name,     \
                                is_retprobe)                                \
    do {                                                                    \
        __ATTACH_UPROBE(skel, binary_path, pid, sym_name, prog_name, is_retprobe); \
        __CHECK_PROGRAM(skel, prog_name);                                     \
    } while (false)

#define ATTACH_UPROBE_CHECKED(skel, binary_path, pid, sym_name, prog_name)     \
    __ATTACH_UPROBE_CHECKED(skel, binary_path, pid,  sym_name, prog_name, false)

#define ATTACH_URETPROBE_CHECKED(skel, binary_path, pid, sym_name, prog_name)  \
    __ATTACH_UPROBE_CHECKED(skel, binary_path, pid, sym_name, prog_name, true)


extern void *ebpf_thread_monitoring(void *ptr);
extern struct config thread_config;
extern netdata_ebpf_targets_t thread_targets[];
extern void ebpf_thread_create_apps_charts(struct ebpf_module *em, void *ptr);

#endif
