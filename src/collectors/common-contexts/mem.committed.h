// SPDX-License-Identifier: GPL-3.0-or-later

#ifndef NETDATA_MEM_COMMITED_H
#define NETDATA_MEM_COMMITED_H
#include "common-contexts.h"

static inline void common_mem_committed(uint64_t commited, int update_every) {
    static RRDSET *st_mem_committed = NULL;
    static RRDDIM *rd_committed = NULL;

    if(unlikely(!st_mem_committed)) {
        st_mem_committed = rrdset_create_localhost(
            "mem"
        , "committed"
        , NULL
        , "overview"
        , NULL
        , "Committed (Allocated) Memory"
        , "MiB"
        , _COMMON_PLUGIN_NAME
        , _COMMON_PLUGIN_MODULE_NAME
        , NETDATA_CHART_PRIO_MEM_SYSTEM_COMMITTED
        , update_every
        , RRDSET_TYPE_AREA
        );

        rrdset_flag_set(st_mem_committed, RRDSET_FLAG_DETAIL);

        rd_committed = rrddim_add(st_mem_committed, "Committed", NULL, 1, 1024, RRD_ALGORITHM_ABSOLUTE);
    }

    rrddim_set_by_pointer(st_mem_committed, rd_committed, (collected_number)commited);
    rrdset_done(st_mem_committed);
}

#endif //NETDATA_MEM_COMMITED_H
