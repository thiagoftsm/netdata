// SPDX-License-Identifier: GPL-3.0-or-later

#include "ebpf.h"
#include "ebpf_md.h"

static char *md_dimension_name[NETDATA_MD_END] = { "md_flush" };
static netdata_syscall_stat_t md_aggregated_data;
static netdata_publish_syscall_t md_publish_aggregated;

static ebpf_data_t md_data;
static struct bpf_link **probe_links = NULL;
static struct bpf_object *objects = NULL;

struct config md_config = { .first_section = NULL,
    .last_section = NULL,
    .mutex = NETDATA_MUTEX_INITIALIZER,
    .index = { .avl_tree = { .root = NULL, .compar = appconfig_section_compare },
        .rwlock = AVL_LOCK_INITIALIZER } };

/*****************************************************************
 *
 *  FUNCTIONS TO CLOSE THE THREAD
 *
 *****************************************************************/

/**
 * Clean up the main thread.
 *
 * @param ptr thread data.
 */
static void ebpf_md_cleanup(void *ptr)
{
    ebpf_module_t *em = (ebpf_module_t *)ptr;
    if (!em->enabled)
        return;

    ebpf_cleanup_publish_syscall(&md_publish_aggregated);

    struct bpf_program *prog;
    size_t i = 0 ;
    bpf_object__for_each_program(prog, objects) {
        bpf_link__destroy(probe_links[i]);
        i++;
    }
    bpf_object__close(objects);
}

/**
* Main loop for this collector.
*/
static void md_collector(ebpf_module_t *em)
{

}

/*****************************************************************
 *
 *  INITIALIZE THREAD
 *
 *****************************************************************/

/**
 * Create global charts
 *
 * Call ebpf_create_chart to create the charts for the collector.
 */
static void ebpf_create_md_charts()
{
    ebpf_create_chart(NETDATA_EBPF_RAID_GROUP, NETDATA_MD_FLUSH_CHART,
                      "Calls for md_flush.",
                      EBPF_COMMON_DIMENSION_CALL, NETDATA_FLUSH_SUBMENU,
                      NULL,
                      NETDATA_EBPF_CHART_TYPE_LINE,
                      21200,
                      ebpf_create_global_dimension,
                      &md_publish_aggregated, 1);
}

/*****************************************************************
 *
 *  MAIN THREAD
 *
 *****************************************************************/

/**
 * Cachestat thread
 *
 * Thread used to make cachestat thread
 *
 * @param ptr a pointer to `struct ebpf_module`
 *
 * @return It always return NULL
 */
void *ebpf_md_thread(void *ptr)
{
    netdata_thread_cleanup_push(ebpf_md_cleanup, ptr);

    ebpf_module_t *em = (ebpf_module_t *)ptr;
    fill_ebpf_data(&md_data);

    ebpf_load_config_update_module(em, &md_config, NETDATA_MD_CONFIG_FILE);

    if (!em->enabled)
        goto endmd;

    if (ebpf_update_kernel(&md_data)) {
        pthread_mutex_unlock(&lock);
        goto endmd;
    }

    probe_links = ebpf_load_program(ebpf_plugin_dir, em, kernel_string, &objects, md_data.map_fd);
    if (!probe_links) {
        pthread_mutex_unlock(&lock);
        goto endmd;
    }

    int algorithm = NETDATA_EBPF_INCREMENTAL_IDX;
    ebpf_global_labels(&md_aggregated_data, &md_publish_aggregated, md_dimension_name, md_dimension_name,
                       &algorithm, NETDATA_MD_END);

    pthread_mutex_lock(&lock);

    ebpf_create_md_charts();

    pthread_mutex_unlock(&lock);

    md_collector(em);

endmd:
    netdata_thread_cleanup_pop(1);
    return NULL;
}
