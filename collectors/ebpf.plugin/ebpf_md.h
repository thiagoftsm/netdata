// SPDX-License-Identifier: GPL-3.0-or-later

#ifndef NETDATA_EBPF_MD_H
#define NETDATA_EBPF_MD_H 1

// configuration file
#define NETDATA_MD_CONFIG_FILE "md.conf"

extern void *ebpf_md_thread(void *ptr);

#endif /* NETDATA_EBPF_MD_H */