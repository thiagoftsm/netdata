// SPDX-License-Identifier: GPL-3.0-or-later

#ifndef NETDATA_EBPF_MD_H
#define NETDATA_EBPF_MD_H 1

// configuration file
#define NETDATA_MD_CONFIG_FILE "md.conf"

#define NETDATA_FLUSH_SUBMENU "flush (eBPF)"

// charts
#define NETDATA_MD_FLUSH_CHART "md_flush"

#define NETDATA_MD_SLEEP_MS 850000ULL

#define NETDATA_MD_GLOBAL_TABLE 0ULL

enum md_counters {
    NETDATA_KEY_MD_CALL,

    // Keep this as last and don't skip numbers as it is used as element counter
    NETDATA_MD_END
};

extern void *ebpf_md_thread(void *ptr);

#endif /* NETDATA_EBPF_MD_H */