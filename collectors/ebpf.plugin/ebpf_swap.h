// SPDX-License-Identifier: GPL-3.0-or-later

#ifndef NETDATA_EBPF_SWAP_H
#define NETDATA_EBPF_SWAP_H 1

// configuration file
#define NETDATA_SWAP_CONFIG_FILE "swap.conf"

typedef struct netdata_publish_swap {
    uint64_t calls;
}netdata_publish_swap_t;

enum swap_counters {
    NETDATA_KEY_SWAP_PAGE_CALL,

    // Keep this as last and don't skip numbers as it is used as element counter
    NETDATA_SWAP_END
};

extern void *ebpf_swap_thread(void *ptr);
extern void ebpf_swap_create_apps_charts(struct ebpf_module *em, void *ptr);

#endif