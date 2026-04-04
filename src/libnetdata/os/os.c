// SPDX-License-Identifier: GPL-3.0-or-later

#include "../libnetdata.h"

// ----------------------------------------------------------------------------
// system functions
// to retrieve settings of the system

unsigned int system_hz = 100;
void os_get_system_HZ(void) {
    long ticks;

    if ((ticks = sysconf(_SC_CLK_TCK)) <= 0) {
        netdata_log_error("Cannot get system clock ticks");
        ticks = 100;
    }

    system_hz = (unsigned int) ticks;
}

// =====================================================================================================================
// os_type

#if defined(OS_LINUX)
const char *os_type = "linux";
#endif

#if defined(OS_FREEBSD)
const char *os_type = "freebsd";
#endif

#if defined(OS_MACOS)
const char *os_type = "macos";
#endif

#if defined(OS_WINDOWS)
const char *os_type = "windows";

char *os_translate_path(char *dst, const char *src, size_t dst_size) {
    if (!dst || !dst_size)
        return dst;

    if (!src) {
        dst[0] = '\0';
        return dst;
    }

    size_t i;
    for (i = 0; src[i] && i < dst_size - 1; i++)
        dst[i] = (src[i] == '/') ? '\\' : src[i];

    dst[i] = '\0';
    return dst;
}

char *os_translate_windows_to_msys_path(const char *src) {
    if (!src)
        return strdupz("");

    // Keep already POSIX-style paths unchanged.
    if (src[0] == '/')
        return strdupz(src);

    char converted_path[PATH_MAX];
    if (cygwin_conv_path(CCP_WIN_A_TO_POSIX, src, converted_path, sizeof(converted_path)) == 0) {
        return strdupz(converted_path);
    }

    size_t i = 0;
    size_t j = 0;

    if (isalpha((unsigned char)src[0]) && src[1] == ':') {
        converted_path[j++] = '/';
        if (j < sizeof(converted_path) - 1)
            converted_path[j++] = (char)tolower((unsigned char)src[0]);

        i = 2;
        if ((src[i] == '\\' || src[i] == '/') && j < sizeof(converted_path) - 1)
            converted_path[j++] = '/';
    }
    else if ((src[0] == '\\' && src[1] == '\\') || (src[0] == '/' && src[1] == '/')) {
        converted_path[j++] = '/';
        if (j < sizeof(converted_path) - 1)
            converted_path[j++] = '/';
        i = 2;
    }

    for (; src[i] && j < sizeof(converted_path) - 1; i++)
        converted_path[j++] = (src[i] == '\\') ? '/' : src[i];

    converted_path[j] = '\0';
    return strdupz(converted_path);
}
#endif
