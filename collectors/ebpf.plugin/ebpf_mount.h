// SPDX-License-Identifier: GPL-3.0-or-later

#ifndef NETDATA_EBPF_MOUNT_H
#define NETDATA_EBPF_MOUNT_H 1

extern struct config mount_config;

extern void *ebpf_mount_thread(void *ptr);

#endif
