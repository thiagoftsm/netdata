// SPDX-License-Identifier: GPL-3.0-or-later

#ifndef NETDATA_EBPF_DISK_H
#define NETDATA_EBPF_DISK_H 1

#include "libnetdata/avl/avl.h"

// Decode function extracted from: https://elixir.bootlin.com/linux/v5.10.8/source/include/linux/kdev_t.h#L7
#define MINORBITS       20
#define MKDEV(ma,mi)    (((ma) << MINORBITS) | (mi))

enum netdata_latency_disks_flags {
    NETDATA_DISK_CREATED = 1,
    NETDATA_DISK_PLOT = 2,
    NETDATA_DISK_HAS_EFI = 4,
    NETDATA_DISK_EFI_CHART_CREATED = 8,
    NETDATA_DISK_EFI_RECREATE_CHART = 16
};

/*
 * The definition (DISK_NAME_LEN) has been a stable value since Kernel 3.0,
 * I decided to bring it as internal definition, to avoid include linux/genhd.h.
 */
#define NETDATA_DISK_NAME_LEN 32
typedef struct netdata_ebpf_disks {
    // Search
    avl_t avl;
    uint32_t dev;
    uint32_t major;
    uint32_t minor;
    uint32_t bootsector_key;
    uint64_t start; // start sector
    uint64_t end;   // end sector

    // Print information
    char family[NETDATA_DISK_NAME_LEN];
    char *boot_chart;

    uint32_t flags;

    struct netdata_ebpf_disks *main;
    struct netdata_ebpf_disks *boot_partition;
    struct netdata_ebpf_disks *next;
} netdata_ebpf_disks_t;

extern struct config disk_config;

extern void *ebpf_disk_thread(void *ptr);

#endif /* NETDATA_EBPF_DISK_H */
