// SPDX-License-Identifier: GPL-3.0-or-later

#include "windows-pdh.h"

#if defined(OS_WINDOWS)
static PDH_HQUERY phquery = NULL;

int netdata_pdh_init()
{
    if (phquery)
        return 0;

    PDH_STATUS pdhsts;
    pdhsts = PdhOpenQueryA(NULL, 0, &phquery);
    return (pdhsts != ERROR_SUCCESS) ? -1 : 0;
}

void netdata_pdh_cleanup()
{
    if (phquery)
        PdhCloseQuery(phquery);
}

#endif
