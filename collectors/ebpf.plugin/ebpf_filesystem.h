// SPDX-License-Identifier: GPL-3.0-or-later

#ifndef NETDATA_EBPF_FILESYSTEM_H
#define NETDATA_EBPF_FILESYSTEM_H 1

#include "ebpf.h"

#define NETDATA_FILESYSTEM_MAX_BINS 32UL
#define NETDATA_FILESYSTEM_READ_SLEEP_MS 600000ULL

#define NETDATA_MAIN_TABLE 0ULL

typedef struct netdata_ebpf_histogram {
    char *name;
    uint64_t histogram[NETDATA_FILESYSTEM_MAX_BINS];
} netdata_ebpf_histogram_t;

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

    ebpf_data_t kernel_info;
}ebpf_filesystem_partitions_t;

extern void *ebpf_filesystem_thread(void *ptr);

#endif
