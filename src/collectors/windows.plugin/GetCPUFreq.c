// SPDX-License-Identifier: GPL-3.0-or-later

#include "windows_plugin.h"
#include "windows-internals.h"

#define _COMMON_PLUGIN_NAME "windows.plugin"
#define _COMMON_PLUGIN_MODULE_NAME "GetCPUFreq"
#include "../common-contexts/common-contexts.h"

collected_number *frequencies;
static ND_THREAD *cpu_freq_thread_collection = NULL;
static size_t local_cpus;

/**
 * The QueryPerformanceFrequency does not give us expected results
 * https://learn.microsoft.com/en-us/windows/win32/api/profileapi/nf-profileapi-queryperformancefrequency
 *
 * Perflib (Processor Information) gives almost static data.
 *
 * We opt to use the same approach used by LibreHardwareMonitor, that is compaitble with average value shown in windows tools
 * https://github.com/LibreHardwareMonitor/LibreHardwareMonitor/blob/master/LibreHardwareMonitorLib/Hardware/Cpu/GenericCpu.cs#L145
 */

static void netdata_freq_collection(void *ptr __maybe_unused)
{
    heartbeat_t hb;
    heartbeat_init(&hb, USEC_PER_SEC);
    int update_every = (frequencies[0] < 2) ? UPDATE_EVERY_MIN: frequencies[0] - 1;
    frequencies[0] = 0;

    while (service_running(SERVICE_COLLECTORS)) {
        (void) heartbeat_next(&hb);

        if (unlikely(!service_running(SERVICE_COLLECTORS)))
            break;
    }
}

static int initialize(int update_every)
{
    local_cpus = os_get_system_cpus();
    frequencies = mallocz(local_cpus * sizeof(collected_number));

    frequencies[0] = update_every;

    cpu_freq_thread_collection =
        nd_thread_create("nd_cpu_freq", NETDATA_THREAD_OPTION_DEFAULT, netdata_freq_collection, NULL);
}

int do_GetCPUFreq(int update_every, usec_t dt __maybe_unused)
{
    static bool initialized = false;

    if (unlikely(!initialized)) {
        if (initialize(update_every))
            return -1;

        initialized = true;
        return 0;
    }

    return 0;
}

void do_CPUFreq_cleanup()
{
    if (nd_thread_join(cpu_freq_thread_collection))
        nd_log_daemon(NDLP_ERR, "Failed to join cpu frequency.");
}
