// SPDX-License-Identifier: GPL-3.0-or-later

#ifndef NETDATA_EBPF_FILESYSTEM_H
#define NETDATA_EBPF_FILESYSTEM_H 1

extern void *ebpf_filesystem_thread(void *ptr);
extern void ebpf_filesystem_create_apps_charts(struct ebpf_module *em, void *ptr);

#endif  /* NETDATA_EBPF_FILESYSTEM_H */
