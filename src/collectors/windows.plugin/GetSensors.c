// SPDX-License-Identifier: GPL-3.0-or-later

#include "windows_plugin.h"
#include "windows-internals.h"

#define _COMMON_PLUGIN_NAME "windows.plugin"
#define _COMMON_PLUGIN_MODULE_NAME "GetSensors"
#include "../common-contexts/common-contexts.h"

#define INITGUID
#include <windows.h>
#include <initguid.h>

#include <sensorsapi.h>
#include <sensors.h>

ISensorManager *hSensorManager = NULL;

int netdata_sensor_initialize_management()
{
    HRESULT hr = CoInitializeEx(NULL, COINIT_MULTITHREADED);
    if (FAILED(hr)) {
        nd_log(
                NDLS_COLLECTORS,
                NDLP_ERROR,
                "Cannot initialize COM interface.");
        return -1;
    }

    hr = CoCreateInstance(
        &CLSID_SensorManager, NULL, CLSCTX_INPROC_SERVER, &IID_ISensorManager, (void **)&hSensorManager);
    if (hr != S_OK || !hSensorManager) {
        nd_log(
                NDLS_COLLECTORS,
                NDLP_ERROR,
                "Cannot create Sensor Manager.");
        CoUninitialize();
        return -1;
    }

    return 0;
}

int do_GetSensors(int update_every, usec_t dt __maybe_unused)
{
    static bool initialized = false;

    if (unlikely(!initialized)) {
        initialized = true;
        if (netdata_sensor_initialize_management())
            return -1;
    }
    return 0;
}
