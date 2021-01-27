// SPDX-License-Identifier: GPL-3.0-or-later

#ifndef NETDATA_EBPF_LATENCY_H
#define NETDATA_EBPF_LATENCY_H 1

// Proc file
#define NETDATA_LATENCY_PROC_PARTITIONS "/proc/partitions"

// Global chart name
#define NETDATA_LATENCY_SCHEDULE_COUNT "latency_schedule_counter"
#define NETDATA_LATENCY_IO_COUNT "latency_io_counter"
#define NETDATA_LATENCY_SCHEDULER "Scheduler"
#define NETDATA_LATENCY_BLOCK_IO "Block IO"

#define NETDATA_LATENCY_CPU_SCHEDULER "scheduler"
#define NETDATA_LATENCY_HD "latency"

#define NETDATA_LATENCY_READ_SLEEP_MS 700000ULL
#define NETDATA_LATENCY_HIST_BINS 16

enum latency_tables {
    NETDATA_LATENCY_CPU_STATS,
    NETDATA_LATENCY_HD_STATS,
    NETDATA_LATENCY_PID_STATS,
    NETDATA_LATENCY_GLOBAL_STATS,

    NETDATA_LATENCY_END
};

enum latency_counters {
    NETDATA_KEY_TRY_TO_WAKE_UP,
    NETDATA_KEY_WAKE_UP,
    NETDATA_KEY_FINISH_TASK_SWITCH,
    NETDATA_KEY_CALLS_BLOCK_RQ_ISSUE,
    NETDATA_KEY_CALLS_BLOCK_RQ_COMPLETE,

    NETDATA_LATENCY_COUNTER
};

struct netdata_hist_per_core {
    uint32_t core;
    char *chart;
    char *family;
    uint64_t histogram[NETDATA_LATENCY_HIST_BINS];
};

typedef struct block_key {
    uint32_t bin;
    uint32_t dev;
} block_key_t;

enum netdata_latency_disks_flags {
    NETDATA_DISK_CREATED = 1,
    NETDATA_DISK_PLOT = 2,
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

// Decode function extracted from: https://elixir.bootlin.com/linux/v5.10.8/source/include/linux/kdev_t.h#L46
static inline uint32_t netdata_decode_major_dev(uint32_t dev)
{
    return ((dev & 0xfff00) >> 8);
}

static inline uint32_t netdata_decode_minor_dev(uint32_t dev)
{
    return ((dev & 0xff) | ((dev >> 12) & 0xfff00));
}

extern void *ebpf_latency_thread(void *ptr);

#endif