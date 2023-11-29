#ifndef _NETDATA_EBPF_THREAD_H_
# define _NETDATA_EBPF_THREAD_H_ 1

#define NETDATA_EBPF_BUGS_COMMON_LIMIT 1024

#define NETDATA_EBPF_THREAD_CONFIG_FILE "thread.conf"

#define NETDATA_EBPF_C_LIBRARY_OPT_PATH "libc path"
#define NETDATA_EBPF_C_LIBRARY_PATH "/lib64/libc.so.6"

#define NETDATA_EBPF_C_MONITOR_APP "monitor app"

#define NETDATA_EBPF_C_PID_SELECT "monitor pid"

extern void *ebpf_thread_monitoring(void *ptr);
extern struct config thread_config;
extern netdata_ebpf_targets_t thread_targets[];

#endif
