// SPDX-License-Identifier: GPL-3.0-or-later

#ifndef NETDATA_EBPF_DCSTAT_H
#define NETDATA_EBPF_DCSTAT_H 1

// charts
#define NETDATA_DC_HIT_CHART "dc_hit_ratio"
#define NETDATA_DC_REFERENCE_CHART "dc_reference"
#define NETDATA_DC_SLOW_CHART "dc_slow"
#define NETDATA_DC_MISS_CHART "dc_miss"

#define NETDATA_DIRECTORY_CACHE_SUBMENU "directory cache"

#define NETDATA_LATENCY_CACHESTAT_SLEEP_MS 600000ULL

// configuration file
#define NETDATA_CACHESTAT_CONFIG_FILE "cachestat.conf"


// variables
enum directory_cache_counters {
    NETDATA_KEY_DC_REFERENCE,
    NETDATA_KEY_DC_SLOW,
    NETDATA_KEY_DC_MISS,

    // Keep this as last and don't skip numbers as it is used as element counter
    NETDATA_DIRECTORY_CACHE_END
};

enum directory_cache_indexes {
    NETDATA_DCSTAT_IDX_RATIO,
    NETDATA_DCSTAT_IDX_REFERENCE,
    NETDATA_DCSTAT_IDX_SLOW,
    NETDATA_DCSTAT_IDX_MISS
};

enum directory_cache_tables {
    NETDATA_DCSTAT_GLOBAL_STATS,
    NETDATA_DCSTAT_PID_STATS
};

typedef struct netdata_publish_dcstat_pid {
    uint64_t reference;
    uint64_t slow;
    uint64_t miss;
} netdata_dcstat_pid_t;

typedef struct netdata_publish_dcstat {
    long long ratio;
    long long refernce;
    long long slow;
    long long miss;

    netdata_dcstat_pid_t current;
    netdata_dcstat_pid_t prev;
} netdata_publish_dcstat_t;

extern void *ebpf_cachestat_thread(void *ptr);

#endif // NETDATA_EBPF_DCSTAT_H
