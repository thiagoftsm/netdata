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

struct sensor_data {
    GUID type;

    char *unit;
    collected_number value;

    RRDSET *st_sensor;
    RRDDIM *rd_sensor;
};

// Dictionary
static DICTIONARY *sensors = NULL;

void netdata_sensor_insert_cb(const DICTIONARY_ITEM *item __maybe_unused, void *value, void *data __maybe_unused)
{
    return;
}

static int initialize()
{
    HRESULT hr = CoInitializeEx(NULL, COINIT_MULTITHREADED);
    if (FAILED(hr)) {
        nd_log(
                NDLS_COLLECTORS,
                NDLP_ERR,
                "Cannot initialize COM interface.");
        return -1;
    }

    hr = CoCreateInstance(
        &CLSID_SensorManager, NULL, CLSCTX_INPROC_SERVER, &IID_ISensorManager, (void **)&hSensorManager);
    if (hr != S_OK || !hSensorManager) {
        nd_log(
                NDLS_COLLECTORS,
                NDLP_ERR,
                "Cannot create Sensor Manager.");
        CoUninitialize();
        return -1;
    }

    sensors = dictionary_create_advanced(
            DICT_OPTION_DONT_OVERWRITE_VALUE | DICT_OPTION_FIXED_SIZE, NULL, sizeof(struct sensor_data));

    dictionary_register_insert_callback(sensors, netdata_sensor_insert_cb, NULL);

    return 0;
}

int GetSensorData(int update_every)
{
    ISensorCollection *hSensorCollection = NULL;
    HRESULT hr = hSensorManager->lpVtbl->GetSensorsByCategory(hSensorManager, &SENSOR_CATEGORY_ALL, &hSensorCollection);
    if (FAILED(hr)) {
        CoUninitialize();
        return -1;
    }

    ULONG count = 0;
    hSensorCollection->lpVtbl->GetCount(hSensorCollection, &count);
    if (unlikely(!count)) {
        nd_log(
                NDLS_COLLECTORS,
                NDLP_ERR,
                "No sensors identified, stopping collection.");
        return -1;
    }

// https://learn.microsoft.com/en-us/rest/api/data-manager-for-agri/dataplane/sensor-data-models/get?view=rest-data-manager-for-agri-dataplane-2023-11-01-preview&tabs=HTTP
#define SENSOR_MAX_LENGTH 56
    char sensor_name[SENSOR_MAX_LENGTH];
    for (ULONG i = 0; i < count; i++) {
        ISensor *hSensor = NULL;
        hr = hSensorCollection->lpVtbl->GetAt(hSensorCollection, i, &hSensor);
        if (SUCCEEDED(hr)) {
            BSTR binary_sensor_name;
            hSensor->lpVtbl->GetFriendlyName(hSensor, &binary_sensor_name);
            int len = SysStringLen(binary_sensor_name);

            wcstombs(sensor_name, binary_sensor_name, SENSOR_MAX_LENGTH);

            SysFreeString(binary_sensor_name);

            struct sensor_data *sd = dictionary_set(sensors, sensor_name, NULL, sizeof(*p));

            ISensorDataReport *hReport = NULL;
            hr = hSensor->lpVtbl->GetData(hSensor, &hReport);
            if (SUCCEEDED(hr)) {
                hReport->lpVtbl->Release(hReport);
            }
        }
    }
    hSensorManager->lpVtbl->Release(hSensorManager);

    return 0;
}

int do_GetSensors(int update_every, usec_t dt __maybe_unused)
{
    static bool initialized = false;

    if (unlikely(!initialized)) {
        initialized = true;
        if (initialize())
            return -1;
    }

    if (GetSensorData(update_every))
        return -1;

    return 0;
}
