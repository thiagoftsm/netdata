// SPDX-License-Identifier: GPL-3.0-or-later

#ifndef NETDATA_EBPF_IO_LATENCY_H
#define NETDATA_EBPF_IO_LATENCY_H 1

// Proc file
#define NETDATA_LATENCY_PROC_PARTITIONS "/proc/partitions"

// Global defintions
#define NETDATA_LATENCY_READ_SLEEP_MS 700000ULL
#define NETDATA_LATENCY_HIST_BINS 32

// Global chart name
#define NETDATA_LATENCY_IO_COUNT "latency_io_counter"
#define NETDATA_LATENCY_BLOCK_IO "Block IO"

enum io_latency_counters {
    NETDATA_KEY_CALLS_BLOCK_RQ_ISSUE,
    NETDATA_KEY_CALLS_BLOCK_RQ_COMPLETE_WRITE,
    NETDATA_KEY_CALLS_BLOCK_RQ_COMPLETE_READ,

    NETDATA_LATENCY_COUNTER
};

enum io_latency_tables {
    NETDATA_IO_LATENCY_READ_HISTOGRAM,
    NETDATA_IO_LATENCY_WRITE_HISTOGRAM,
    NETDATA_IO_LATENCY_GLOBAL_STATS
};

/*
 * The definition (DISK_NAME_LEN) has been a stable value since Kernel 3.0,
 * I decided to bring it as internal definition, to avoid include linux/genhd.h.
 */
#define NETDATA_DISK_NAME_LEN 32
typedef struct netdata_latency_disks {
    // Search
    avl avl;
    uint32_t major;
    uint32_t minor;

    // Print information
    char family[NETDATA_DISK_NAME_LEN];
    char *chart;
    uint64_t *histogram;
    uint32_t flags;
    struct netdata_latency_disks *next;
} netdata_latency_disks_t;

extern void *ebpf_io_latency_thread(void *ptr);

#endif
