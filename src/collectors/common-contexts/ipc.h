// SPDX-License-Identifier: GPL-3.0-or-later

#ifndef NETDATA_IPC_H
#define NETDATA_IPC_H

#include "common-contexts.h"

static inline void common_ipc(uint64_t semathore, NETDATA_DOUBLE red, int update_every) {
    static RRDSET *st_semaphores = NULL;
    static RRDDIM *rd_semaphores = NULL;
    if(unlikely(!st_semaphores)) {
        st_semaphores = rrdset_create_localhost(
            "system"
        , "ipc_semaphores"
        , NULL
        , "ipc semaphores"
        , NULL
        , "IPC Semaphores"
        , "semaphores"
        , _COMMON_PLUGIN_NAME
        , _COMMON_PLUGIN_MODULE_NAME
        , NETDATA_CHART_PRIO_SYSTEM_IPC_SEMAPHORES
        , update_every
        , RRDSET_TYPE_AREA
        );
        rd_semaphores = rrddim_add(st_semaphores, "semaphores", NULL, 1, 1, RRD_ALGORITHM_ABSOLUTE);
    }

    rrddim_set_by_pointer(st_semaphores, rd_semaphores, semathore);
    rrdset_done(st_semaphores);

    st_semaphores->red = red;
}

#endif //NETDATA_SYSTEM_PROCESSES_H
