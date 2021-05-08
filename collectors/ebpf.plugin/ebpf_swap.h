// SPDX-License-Identifier: GPL-3.0-or-later

#ifndef NETDATA_EBPF_SWAP_H
#define NETDATA_EBPF_SWAP_H 1

// configuration file
#define NETDATA_SWAP_CONFIG_FILE "swap.conf"

// charts
#define NETDATA_MEM_SWAP_CHART "swapcalls"
#define NETDATA_MEM_SWAP_READ_CHART "swap_read_call"
#define NETDATA_MEM_SWAP_WRITE_CHART "swap_write_call"

#define NETDATA_SWAP_SUBMENU "swap (eBPF)"

enum swap_tables {
    NETDATA_PID_SWAP_TABLE,
    NETDATA_SWAP_GLOBAL_TABLE
};

typedef struct netdata_publish_swap {
    uint64_t read;
    uint64_t write;
}netdata_publish_swap_t;

enum swap_counters {
    NETDATA_KEY_SWAP_READPAGE_CALL,
    NETDATA_KEY_SWAP_WRITEPAGE_CALL,

    // Keep this as last and don't skip numbers as it is used as element counter
    NETDATA_SWAP_END
};

extern void *ebpf_swap_thread(void *ptr);
extern void ebpf_swap_create_apps_charts(struct ebpf_module *em, void *ptr);
extern void clean_swap_pid_structures();

#endif