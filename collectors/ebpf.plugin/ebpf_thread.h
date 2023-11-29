#ifndef _NETDATA_EBPF_THREAD_H_
# define _NETDATA_EBPF_THREAD_H_ 1

extern void *ebpf_thread_monitoring(void *ptr);
extern struct config thread_config;
extern netdata_ebpf_targets_t thread_targets[];

#endif
