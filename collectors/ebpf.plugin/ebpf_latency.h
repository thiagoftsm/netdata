// SPDX-License-Identifier: GPL-3.0-or-later

#ifndef NETDATA_EBPF_LATENCY_H
#define NETDATA_EBPF_LATENCY_H 1

// Global chart name
#define NETDATA_LATENCY_SCHEDULE_COUNT "latency_schedule_counter"
#define NETDATA_LATENCY_IO_COUNT "latency_io_counter"
#define NETDATA_LATENCY_SCHEDULER "Scheduler"
#define NETDATA_LATENCY_BLOCK_IO "Block IO"

#define NETDATA_LATENCY_CPU_SCHEDULER "scheduler"

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

extern void *ebpf_latency_thread(void *ptr);

#endif