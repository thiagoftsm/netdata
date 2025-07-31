// SPDX-License-Identifier: GPL-3.0-or-later

#include "windows_plugin.h"
#include "windows-internals.h"

#define _COMMON_PLUGIN_NAME "windows.plugin"
#define _COMMON_PLUGIN_MODULE_NAME "GetCPUFreq"
#include "../common-contexts/common-contexts.h"

int do_GetCPUFreq(int update_every, usec_t dt __maybe_unused)
{
    return 0;
}
