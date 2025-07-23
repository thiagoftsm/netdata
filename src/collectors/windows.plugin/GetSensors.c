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

static inline void netdata_sensor_set_guid(struct sensor_data *sd, ISensor *hSensor)
{
    GUID type;
    hSensor->lpVtbl->GetType(hSensor, &type);
    sd->type = type;
}

static inline void netdata_sensor_set_value(struct sensor_data *sd, PROPVARIANT *value)
{
    switch(value->vt) {
        case VT_R8:
            sd->value = (collected_number ) value->dblVal;
            break;
        case VT_I4:
            sd->value = (collected_number ) value->lVal;
            break;
        case VT_BOOL:
            sd->value = (collected_number ) (value->boolVal);
            break;
        case VT_LPWSTR:
        default:
            // We are ignoring unknown and string value
            sd->value = 0;
            break;
    }
}

static void netdata_sensor_fill_dictionary(struct sensor_data *sd, ISensor *hSensor)
{
    ISensorDataReport *hReport = NULL;
    HRESULT hr = hSensor->lpVtbl->GetData(hSensor, &hReport);
    if (SUCCEEDED(hr)) {
        IPortableDeviceValues *hKeys = NULL;
        netdata_sensor_set_guid(sd, hSensor);
        hr = hReport->lpVtbl->GetSensorValues(hReport, NULL, &hKeys);
        if (SUCCEEDED(hr)) {
            DWORD keyCount;
            hKeys->lpVtbl->GetCount(hKeys, &keyCount);

            for (DWORD j = 0; j < keyCount; j++) {
                PROPERTYKEY key;
                PROPVARIANT value;
                PropVariantInit(&value);

                hKeys->lpVtbl->GetAt(hKeys, j, &key, &value);

                netdata_sensor_set_value(sd, &value);

                PropVariantClear(&value);
            }

            hKeys->lpVtbl->Release(hKeys);
        }
        hReport->lpVtbl->Release(hReport);
    }
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

            struct sensor_data *sd = dictionary_set(sensors, sensor_name, NULL, sizeof(*sd));
            if (unlikely(!sd))
                continue;

            netdata_sensor_fill_dictionary(sd, hSensor);

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
