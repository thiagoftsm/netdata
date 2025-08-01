// SPDX-License-Identifier: GPL-3.0-or-later

#include "windows_plugin.h"
#include "windows-internals.h"

#define _COMMON_PLUGIN_NAME "windows.plugin"
#define _COMMON_PLUGIN_MODULE_NAME "GetCPUFreq"
#include "../common-contexts/common-contexts.h"

#define NETDATA_LOCAL_CPU_ID_LENGTH 16
struct netdata_win_cpu_freq {
    RRDDIM *rd_cpu_frequency;
    char cpu_freq_id[NETDATA_LOCAL_CPU_ID_LENGTH];

    collected_number freq;
};

struct netdata_win_cpu_freq *frequencies;
static ND_THREAD *cpu_freq_thread_collection = NULL;
static size_t local_cpus = 0;

/**
 * The QueryPerformanceFrequency does not give us expected results
 * https://learn.microsoft.com/en-us/windows/win32/api/profileapi/nf-profileapi-queryperformancefrequency
 *
 * Perflib (Processor Information) gives almost static data.
 *
 * We opt to use the same approach used by LibreHardwareMonitor, that is compaitble with average value shown in windows tools
 * https://github.com/LibreHardwareMonitor/LibreHardwareMonitor/blob/master/LibreHardwareMonitorLib/Hardware/Cpu/GenericCpu.cs#L145
 */

static collected_number estimate_cpu_frequency_mhz(int cpu)
{
    LARGE_INTEGER freq, start, end;
    volatile unsigned long long i;
    double elapsed_seconds;
    unsigned long long iterations;

    HANDLE thread = GetCurrentThread();
    DWORD_PTR previous_affinity = SetThreadAffinityMask(thread, 1ULL << cpu);
    if (previous_affinity == 0) {
        return 0;
    }

    if (!QueryPerformanceFrequency(&freq))
        return 0;

    QueryPerformanceCounter(&start);

    do {
        for (i = 0, iterations = 0; i < 100000; ++i) {
            iterations++;
        }
        QueryPerformanceCounter(&end);
        elapsed_seconds = (double)(end.QuadPart - start.QuadPart) / freq.QuadPart;
    } while (elapsed_seconds < 0.1);

    SetThreadAffinityMask(thread, previous_affinity);

    iterations /= (elapsed_seconds * NSEC_PER_MSEC);
    return (collected_number ) (iterations) ;
}

static inline void netdata_collect_local_frequency()
{
    for (size_t i =0; i < local_cpus; i++) {
        frequencies[i].freq = estimate_cpu_frequency_mhz(i);
    }
}

static void netdata_freq_collection(void *ptr __maybe_unused)
{
    heartbeat_t hb;
    heartbeat_init(&hb, USEC_PER_SEC);
    int update_every = (frequencies[0].freq < 2) ? UPDATE_EVERY_MIN: frequencies[0].freq - 1;

    while (service_running(SERVICE_COLLECTORS)) {
        (void) heartbeat_next(&hb);

        if (unlikely(!service_running(SERVICE_COLLECTORS)))
            break;

        netdata_collect_local_frequency();
    }
}

static int initialize(int update_every)
{
    local_cpus = os_get_system_cpus();
    frequencies = mallocz(local_cpus * sizeof(struct netdata_win_cpu_freq));

    frequencies[0].freq = update_every;
    for (size_t i = 0; i < local_cpus; i++) {
        snprintfz(frequencies[i].cpu_freq_id, NETDATA_LOCAL_CPU_ID_LENGTH, "cpu%d", i);
    }

    cpu_freq_thread_collection =
        nd_thread_create("nd_cpu_freq", NETDATA_THREAD_OPTION_DEFAULT, netdata_freq_collection, NULL);
}

static void netdata_cpu_freq(int update_every)
{
    RRDSET *cpufreq = common_cpu_cpufreq(update_every);

    for (size_t i = 0; i < local_cpus; i++) {
        struct netdata_win_cpu_freq *ptr = &frequencies[i];
        if (!ptr->rd_cpu_frequency)
            ptr->rd_cpu_frequency = rrddim_add(cpufreq, ptr->cpu_freq_id, NULL, 1, 1, RRD_ALGORITHM_ABSOLUTE);

        rrddim_set_by_pointer(cpufreq, ptr->rd_cpu_frequency, ptr->freq);
    }
    rrdset_done(cpufreq);
}

int do_GetCPUFreq(int update_every, usec_t dt __maybe_unused)
{
    static bool initialized = false;

    if (unlikely(!initialized)) {
        if (initialize(update_every))
            return -1;

        netdata_collect_local_frequency();
        initialized = true;
    }

    netdata_cpu_freq(update_every);
    return 0;
}

void do_CPUFreq_cleanup()
{
    if (nd_thread_join(cpu_freq_thread_collection))
        nd_log_daemon(NDLP_ERR, "Failed to join cpu frequency.");
}
