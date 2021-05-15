// SPDX-License-Identifier: GPL-3.0-or-later

#ifndef NETDATA_EBPF_FILESYSTEM_H
#define NETDATA_EBPF_FILESYSTEM_H 1

#include "ebpf.h"

#define NETDATA_FILESYSTEM_MAX_BINS 32UL
#define NETDATA_FILESYSTEM_READ_SLEEP_MS 600000ULL


#define NETDATA_FILESYSTEM_CONFIG_FILE "filesystem.conf"
#define NETDATA_FILESYSTEM_CONFIG_NAME "filesystem"

#define NETDATA_FS_MAX_DIST_NAME 64

enum netdata_filesystem_flags {
    NETDATA_FILESYSTEM_FLAG_NO_PARTITION = 0,
    NETDATA_FILESYSTEM_FLAG_HAS_PARTITION = 1,
    NETDATA_FILESYSTEM_FLAG_CHART_CREATED = 2,
    NETDATA_FILESYSTEM_FILL_ADDRESS_TABLE = 4
};

enum netdata_filesystem_table {
    NETDATA_MAIN_FS_TABLE,
    NETDATA_ADDR_FS_TABLE
};

typedef struct netdata_fs_hist {
    uint32_t hist_id;
    uint32_t bin;
} netdata_fs_hist_t;

enum filesystem_counters {
    NETDATA_KEY_CALLS_READ,
    NETDATA_KEY_CALLS_WRITE,
    NETDATA_KEY_CALLS_OPEN,
    NETDATA_KEY_CALLS_SYNC,

    NETDATA_FS_END
};

typedef struct netdata_ebpf_histogram {
    char *name;
    uint64_t histogram[NETDATA_FILESYSTEM_MAX_BINS];
} netdata_ebpf_histogram_t;

typedef struct ebpf_filesystem_addresses {
    char *function;
    uint32_t hash;
    // We use long as address, because it matches system length
    unsigned long addr;
}ebpf_filesystem_addresses_t;

typedef struct ebpf_filesystem_partitions {
    char *filesystem;
    char *family;
    uint32_t partitions;
    struct bpf_object *objects;
    struct bpf_link **probe_links;

    netdata_ebpf_histogram_t hread;
    netdata_ebpf_histogram_t hwrite;
    netdata_ebpf_histogram_t hopen;
    netdata_ebpf_histogram_t hsync;

    uint32_t flags;
    uint32_t enabled;

    ebpf_data_t kernel_info;
    ebpf_filesystem_addresses_t addresses;
}ebpf_filesystem_partitions_t;

extern void *ebpf_filesystem_thread(void *ptr);
extern struct config fs_config;

#endif
