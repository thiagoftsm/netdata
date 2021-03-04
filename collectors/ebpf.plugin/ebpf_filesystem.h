// SPDX-License-Identifier: GPL-3.0-or-later

#ifndef NETDATA_EBPF_FILESYSTEM_H
#define NETDATA_EBPF_FILESYSTEM_H 1

#include "ebpf.h"

#define NETDATA_FILESYSTEM_MAX_BINS 32UL
#define NETDATA_EXT4_READ_SLEEP_MS 600000ULL

#define NETDATA_MAIN_TABLE 0ULL

typedef struct netdata_ext4_hist {
    uint32_t hist_id;
    uint32_t bin;
} netdata_ext4_hist_t;

enum ext4_counters {
    NETDATA_KEY_CALLS_READ,
    NETDATA_KEY_CALLS_WRITE,
    NETDATA_KEY_CALLS_OPEN,
    NETDATA_KEY_CALLS_SYNC,

    NETDATA_EXT4_END
};

enum netdata_filesystem_flags {
    NETDATA_FILESYSTEM_FLAG_HAS_PARTITION = 1,
    NETDATA_FILESYSTEM_FLAG_CHART_CREATED = 2
};

typedef struct netdata_ebpf_histogram {
    char *name;
    uint64_t histogram[NETDATA_FILESYSTEM_MAX_BINS];
} netdata_ebpf_histogram_t;

typedef struct ebpf_filesystem_partitions {
    char *filesystem;
    uint32_t partitions;
    struct bpf_object *objects;
    struct bpf_link **probe_links;

    netdata_ebpf_histogram_t hread;
    netdata_ebpf_histogram_t hwrite;
    netdata_ebpf_histogram_t hopen;

    uint32_t flags;

    ebpf_data_t kernel_info;
}ebpf_filesystem_partitions_t;

extern void *ebpf_filesystem_thread(void *ptr);

#endif  /* NETDATA_EBPF_FILESYSTEM_H */
