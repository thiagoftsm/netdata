// SPDX-License-Identifier: GPL-3.0-or-later

#ifndef NETDATA_EBPF_FILESYSTEM_H
#define NETDATA_EBPF_FILESYSTEM_H 1

#include "ebpf.h"

#define NETDATA_EXT4_MAX_BINS 32UL

enum netdata_filesystem_flags {
    NETDATA_FILESYSTEM_FLAG_HAS_PARTITION = 1,
    NETDATA_FILESYSTEM_FLAG_CHART_CREATED = 2
};

typedef struct ebpf_filesystem_partitions {
    char *filesystem;
    char *chart_name;
    uint32_t partitions;
    struct bpf_object *objects;
    struct bpf_link **probe_links;

    uint32_t flags;

    ebpf_data_t kernel_info;
}ebpf_filesystem_partitions_t;

extern void *ebpf_filesystem_thread(void *ptr);

#endif  /* NETDATA_EBPF_FILESYSTEM_H */
