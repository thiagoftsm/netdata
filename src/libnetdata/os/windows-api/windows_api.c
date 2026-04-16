// SPDX-License-Identifier: GPL-3.0-or-later

#include "windows_api.h"

#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <winsock2.h>
#include <ws2tcpip.h>
#include <iphlpapi.h>

struct netdata_windows_ip_labels {
    char *local_iface;
    char *ipaddr;
    bool initialized;
} default_ip = {
    .local_iface = NULL,
    .ipaddr = NULL,
    .initialized = false
};

static void netdata_windows_copy_wide_string(char *dst, size_t dst_size, const wchar_t *src)
{
    if (!dst || !dst_size) {
        return;
    }

    dst[0] = '\0';

    if (!src) {
        return;
    }

    size_t copied = wcstombs(dst, src, dst_size - 1);
    if (copied == (size_t)-1) {
        dst[0] = '\0';
        return;
    }

    dst[copied] = '\0';
}

static void netdata_windows_convert_adapter_name(char *dst, size_t dst_size, const wchar_t *description)
{
    netdata_windows_copy_wide_string(dst, dst_size, description);

    for (char *p = dst; *p; p++) {
        switch (*p) {
            case '(':
                *p = '[';
                break;

            case ')':
                *p = ']';
                break;

            case '#':
                *p = '_';
                break;

            default:
                break;
        }
    }
}

static enum netdata_windows_oper_status netdata_windows_map_oper_status(IF_OPER_STATUS status)
{
    switch (status) {
        case IfOperStatusUp:
            return NETDATA_WIN_OPER_STATUS_UP;

        case IfOperStatusDown:
            return NETDATA_WIN_OPER_STATUS_DOWN;

        case IfOperStatusTesting:
            return NETDATA_WIN_OPER_STATUS_TESTING;

        case IfOperStatusDormant:
            return NETDATA_WIN_OPER_STATUS_DORMANT;

        case IfOperStatusNotPresent:
            return NETDATA_WIN_OPER_STATUS_NOT_PRESENT;

        case IfOperStatusLowerLayerDown:
            return NETDATA_WIN_OPER_STATUS_LOWER_LAYER_DOWN;

        case IfOperStatusUnknown:
        default:
            return NETDATA_WIN_OPER_STATUS_UNKNOWN;
    }
}

static bool netdata_windows_ipv4_is_global_unicast(const struct sockaddr_in *sa)
{
    if (!sa) {
        return false;
    }

    uint32_t addr = ntohl(sa->sin_addr.s_addr);

    if (!addr || addr == 0xffffffffU) {
        return false;
    }

    if ((addr & 0xff000000U) == 0x7f000000U) {
        return false;
    }

    if ((addr & 0xffff0000U) == 0xa9fe0000U) {
        return false;
    }

    if ((addr & 0xf0000000U) == 0xe0000000U) {
        return false;
    }

    return true;
}

static bool netdata_windows_ipv6_is_global_unicast(const struct sockaddr_in6 *sa)
{
    if (!sa) {
        return false;
    }

    const unsigned char *addr = sa->sin6_addr.s6_addr;
    static const unsigned char ipv6_zero[16] = {0};

    if (!memcmp(addr, ipv6_zero, sizeof(ipv6_zero))) {
        return false;
    }

    static const unsigned char ipv6_loopback[16] = {0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1};
    if (!memcmp(addr, ipv6_loopback, sizeof(ipv6_loopback))) {
        return false;
    }

    if (addr[0] == 0xff) {
        return false;
    }

    if (addr[0] == 0xfe && (addr[1] & 0xc0) == 0x80) {
        return false;
    }

    return true;
}

static bool netdata_windows_sockaddr_to_ip(
    const SOCKADDR *sa,
    char *dst,
    size_t dst_size,
    char *family,
    size_t family_size)
{
    if (!sa || !dst || !dst_size || !family || !family_size) {
        return false;
    }

    switch (sa->sa_family) {
        case AF_INET: {
            const struct sockaddr_in *sa4 = (const struct sockaddr_in *)sa;
            if (!netdata_windows_ipv4_is_global_unicast(sa4)) {
                return false;
            }

            if (!inet_ntop(AF_INET, &sa4->sin_addr, dst, (DWORD)dst_size)) {
                return false;
            }

            snprintf(family, family_size, "%s", "ipv4");
            return true;
        }

        case AF_INET6: {
            const struct sockaddr_in6 *sa6 = (const struct sockaddr_in6 *)sa;
            if (!netdata_windows_ipv6_is_global_unicast(sa6)) {
                return false;
            }

            if (!inet_ntop(AF_INET6, &sa6->sin6_addr, dst, (DWORD)dst_size)) {
                return false;
            }

            snprintf(family, family_size, "%s", "ipv6");
            return true;
        }

        default:
            return false;
    }
}

static bool netdata_windows_append_adapter_address(
    struct netdata_windows_network_adapter *adapter,
    const char *family,
    const char *address)
{
    if (!adapter || !family || !address || !*family || !*address) {
        return false;
    }

    for (size_t i = 0; i < adapter->addresses_count; i++) {
        if (!strcmp(adapter->addresses[i].family, family) && !strcmp(adapter->addresses[i].address, address)) {
            return true;
        }
    }

    size_t new_count = adapter->addresses_count + 1;
    void *tmp = realloc(adapter->addresses, new_count * sizeof(*adapter->addresses));
    if (!tmp) {
        return false;
    }

    adapter->addresses = tmp;
    snprintf(
        adapter->addresses[adapter->addresses_count].family,
        sizeof(adapter->addresses[adapter->addresses_count].family),
        "%s",
        family);
    snprintf(
        adapter->addresses[adapter->addresses_count].address,
        sizeof(adapter->addresses[adapter->addresses_count].address),
        "%s",
        address);
    adapter->addresses_count = new_count;

    return true;
}

static void netdata_windows_format_mac_address(
    char *dst,
    size_t dst_size,
    const unsigned char *address,
    ULONG address_length)
{
    if (!dst || !dst_size) {
        return;
    }

    dst[0] = '\0';

    if (!address || !address_length) {
        return;
    }

    size_t offset = 0;
    for (ULONG i = 0; i < address_length; i++) {
        int written = snprintf(dst + offset, dst_size - offset, "%s%02X", i ? ":" : "", address[i]);
        if (written < 0 || (size_t)written >= dst_size - offset) {
            dst[0] = '\0';
            return;
        }

        offset += (size_t)written;
    }
}

static void netdata_windows_free_network_adapters_internal(
    struct netdata_windows_network_adapter *adapters,
    size_t count)
{
    if (!adapters) {
        return;
    }

    for (size_t i = 0; i < count; i++) {
        free(adapters[i].addresses);
    }

    free(adapters);
}

int netdata_fill_default_ip()
{
    if (default_ip.initialized)
        return 0;

    default_ip.initialized = true;

    MIB_IPFORWARDROW route;
    DWORD dest = 0;
    if (GetBestRoute(dest, 0, &route) != NO_ERROR) {
        return -1;
    }

    DWORD ifIndex = route.dwForwardIfIndex;

    ULONG bufLen = 15000;
    PIP_ADAPTER_ADDRESSES adapters = (PIP_ADAPTER_ADDRESSES)malloc(bufLen);
    if (!adapters) {
        return 1;
    }

    int ret = GetAdaptersAddresses(AF_INET, GAA_FLAG_INCLUDE_PREFIX, NULL, adapters, &bufLen);
    if (ret != NO_ERROR) {
        goto end_ip_detection;
    }

    PIP_ADAPTER_ADDRESSES aa = adapters;
    while (aa) {
        if (aa->IfIndex == ifIndex) {
            char iface[1024];
            size_t required_size = wcstombs(NULL , aa->FriendlyName, 0) + 1;
            wcstombs(iface, aa->FriendlyName, required_size);
            default_ip.local_iface = strdup(iface);

            PIP_ADAPTER_UNICAST_ADDRESS ua = aa->FirstUnicastAddress;
            while (ua) {
                if (ua->Address.lpSockaddr->sa_family == AF_INET) {
                    char ipstr[INET_ADDRSTRLEN];
                    struct sockaddr_in *sa_in = (struct sockaddr_in *)ua->Address.lpSockaddr;
                    inet_ntop(AF_INET, &(sa_in->sin_addr), ipstr, sizeof(ipstr));
                    default_ip.ipaddr = strdup(ipstr);
                    goto end_ip_detection;
                }
                ua = ua->Next;
            }
            break;
        }
        aa = aa->Next;
    }

    ret = NO_ERROR;
end_ip_detection:
    free(adapters);
    return ret;
}

char *netdata_win_local_interface()
{
    if (!default_ip.initialized)
        netdata_fill_default_ip();

    return default_ip.local_iface;
}

char *netdata_win_local_ip()
{
    if (!default_ip.initialized)
        netdata_fill_default_ip();

    return default_ip.ipaddr;
}

int netdata_windows_get_network_adapters(struct netdata_windows_network_adapter **adapters, size_t *count)
{
    if (!adapters || !count) {
        return -1;
    }

    *adapters = NULL;
    *count = 0;

    ULONG bufLen = 15000;
    PIP_ADAPTER_ADDRESSES raw = NULL;
    DWORD ret = ERROR_SUCCESS;

    for (;;) {
        raw = malloc(bufLen);
        if (!raw) {
            return -1;
        }

        const ULONG flags = GAA_FLAG_SKIP_MULTICAST | GAA_FLAG_SKIP_DNS_SERVER;
        ret = GetAdaptersAddresses(AF_UNSPEC, flags, NULL, raw, &bufLen);
        if (ret == ERROR_SUCCESS) {
            break;
        }

        free(raw);
        raw = NULL;

        if (ret != ERROR_BUFFER_OVERFLOW) {
            return -1;
        }
    }

    size_t adapter_count = 0;
    for (PIP_ADAPTER_ADDRESSES aa = raw; aa; aa = aa->Next) {
        adapter_count++;
    }

    if (!adapter_count) {
        free(raw);
        return 0;
    }

    struct netdata_windows_network_adapter *result = calloc(adapter_count, sizeof(*result));
    if (!result) {
        free(raw);
        return -1;
    }

    size_t idx = 0;
    for (PIP_ADAPTER_ADDRESSES aa = raw; aa; aa = aa->Next, idx++) {
        struct netdata_windows_network_adapter *adapter = &result[idx];

        netdata_windows_convert_adapter_name(adapter->nic_name, sizeof(adapter->nic_name), aa->Description);
        netdata_windows_copy_wide_string(adapter->friendly_name, sizeof(adapter->friendly_name), aa->FriendlyName);
        netdata_windows_format_mac_address(
            adapter->mac_address,
            sizeof(adapter->mac_address),
            aa->PhysicalAddress,
            aa->PhysicalAddressLength);
        adapter->oper_status = netdata_windows_map_oper_status(aa->OperStatus);

        for (PIP_ADAPTER_UNICAST_ADDRESS ua = aa->FirstUnicastAddress; ua; ua = ua->Next) {
            char address[NETDATA_WIN_IP_ADDRESS_MAX];
            char family[NETDATA_WIN_ADDRESS_FAMILY_MAX];

            if (netdata_windows_sockaddr_to_ip(
                    ua->Address.lpSockaddr,
                    address,
                    sizeof(address),
                    family,
                    sizeof(family)) &&
                !netdata_windows_append_adapter_address(adapter, family, address)) {
                netdata_windows_free_network_adapters_internal(result, adapter_count);
                free(raw);
                return -1;
            }
        }

        for (PIP_ADAPTER_ANYCAST_ADDRESS xa = aa->FirstAnycastAddress; xa; xa = xa->Next) {
            char address[NETDATA_WIN_IP_ADDRESS_MAX];
            char family[NETDATA_WIN_ADDRESS_FAMILY_MAX];

            if (netdata_windows_sockaddr_to_ip(
                    xa->Address.lpSockaddr,
                    address,
                    sizeof(address),
                    family,
                    sizeof(family)) &&
                !netdata_windows_append_adapter_address(adapter, family, address)) {
                netdata_windows_free_network_adapters_internal(result, adapter_count);
                free(raw);
                return -1;
            }
        }
    }

    free(raw);

    *adapters = result;
    *count = adapter_count;
    return 0;
}

void netdata_windows_free_network_adapters(struct netdata_windows_network_adapter *adapters, size_t count)
{
    netdata_windows_free_network_adapters_internal(adapters, count);
}
