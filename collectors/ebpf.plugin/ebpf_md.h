// SPDX-License-Identifier: GPL-3.0-or-later

#ifndef NETDATA_EBPF_MD_H
#define NETDATA_EBPF_MD_H 1

#define NETDATA_LATENCY_MD_SLEEP_MS 900000ULL

enum md_counters {
    NETDATA_KEY_MD_CALL,

    // Keep this as last and don't skip numbers as it is used as element counter
    NETDATA_MD_END
};

enum md_tables {
    NETDATA_KEY_MD_TABLE
};

#define NETDATA_EBPF_MD_CALLS "call"

extern struct config md_config;

extern void *ebpf_md_thread(void *ptr);

#endif