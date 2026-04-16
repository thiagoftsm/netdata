// SPDX-License-Identifier: GPL-3.0-or-later

#ifndef NETDATA_WINDOWS_API_H
#define NETDATA_WINDOWS_API_H

#if defined(OS_WINDOWS)

#include <stddef.h>
#include <stdint.h>

#define NETDATA_WIN_ADAPTER_NAME_MAX 1024
#define NETDATA_WIN_MAC_ADDRESS_MAX 96
#define NETDATA_WIN_IP_ADDRESS_MAX 64
#define NETDATA_WIN_ADDRESS_FAMILY_MAX 8

enum netdata_windows_oper_status {
    NETDATA_WIN_OPER_STATUS_UNKNOWN = 0,
    NETDATA_WIN_OPER_STATUS_UP,
    NETDATA_WIN_OPER_STATUS_DOWN,
    NETDATA_WIN_OPER_STATUS_TESTING,
    NETDATA_WIN_OPER_STATUS_DORMANT,
    NETDATA_WIN_OPER_STATUS_NOT_PRESENT,
    NETDATA_WIN_OPER_STATUS_LOWER_LAYER_DOWN,
    NETDATA_WIN_OPER_STATUS_MAX
};

struct netdata_windows_network_adapter_address {
    char address[NETDATA_WIN_IP_ADDRESS_MAX];
    char family[NETDATA_WIN_ADDRESS_FAMILY_MAX];
};

struct netdata_windows_network_adapter {
    char nic_name[NETDATA_WIN_ADAPTER_NAME_MAX];
    char friendly_name[NETDATA_WIN_ADAPTER_NAME_MAX];
    char mac_address[NETDATA_WIN_MAC_ADDRESS_MAX];
    enum netdata_windows_oper_status oper_status;
    struct netdata_windows_network_adapter_address *addresses;
    size_t addresses_count;
};

char *netdata_win_local_interface();
char *netdata_win_local_ip();
int netdata_windows_get_network_adapters(struct netdata_windows_network_adapter **adapters, size_t *count);
void netdata_windows_free_network_adapters(struct netdata_windows_network_adapter *adapters, size_t count);

#endif

#endif //NETDATA_WINDOWS_API_H
