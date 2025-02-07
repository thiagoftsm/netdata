// SPDX-License-Identifier: GPL-3.0-or-later

#ifndef NETDATA_WINDOWS_PDH_H
#define NETDATA_WINDOWS_PDH_H

#include "../../libnetdata.h"

#if defined(OS_WINDOWS)

#include "pdh.h"

int netdata_pdh_init();
void netdata_pdh_cleanup();
#endif

#endif //NETDATA_WINDOWS_PDH_H
