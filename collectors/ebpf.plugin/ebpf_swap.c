// SPDX-License-Identifier: GPL-3.0-or-later

#include "ebpf.h"
#include "ebpf_swap.h"

static ebpf_data_t swap_data;
static struct bpf_link **probe_links = NULL;
static struct bpf_object *objects = NULL;

static char *swap_dimension_name[NETDATA_MD_END] = { "swap_readpage" };
static netdata_syscall_stat_t swap_aggregated_data;
static netdata_publish_syscall_t swap_publish_aggregated;

netdata_publish_swap_t **swap_pid = NULL;

struct config swap_config = { .first_section = NULL,
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
static void ebpf_swap_cleanup(void *ptr)
{
    ebpf_module_t *em = (ebpf_module_t *)ptr;
    if (!em->enabled)
        return;

    ebpf_cleanup_publish_syscall(&swap_publish_aggregated);

    struct bpf_program *prog;
    size_t i = 0 ;
    bpf_object__for_each_program(prog, objects) {
        bpf_link__destroy(probe_links[i]);
        i++;
    }
    bpf_object__close(objects);
}

/**
 * Create apps charts
 *
 * Call ebpf_create_chart to create the charts on apps submenu.
 *
 * @param em a pointer to the structure with the default values.
 */
void ebpf_swap_create_apps_charts(struct ebpf_module *em, void *ptr)
{
    UNUSED(em);
}

/*****************************************************************
 *
 *  MAIN THREAD
 *
 *****************************************************************/

/**
 * Allocate vectors used with this thread.
 *
 * We are not testing the return, because callocz does this and shutdown the software
 * case it was not possible to allocate.
 *
 * @param length is the length for the vectors used inside the collector.
 */
static void ebpf_swap_allocate_global_vectors(size_t length)
{
    cachestat_pid = callocz((size_t)pid_max, sizeof(netdata_publish_swap_t *));
}

/**
 * SWAP thread
 *
 * Thread used to make swap thread
 *
 * @param ptr a pointer to `struct ebpf_module`
 *
 * @return It always return NULL
 */
void *ebpf_swap_thread(void *ptr)
{
    netdata_thread_cleanup_push(ebpf_swap_cleanup, ptr);

    ebpf_module_t *em = (ebpf_module_t *)ptr;
    fill_ebpf_data(&swap_data);

    ebpf_update_module(em, &swap_config, NETDATA_SWAP_CONFIG_FILE);

    if (!em->enabled)
        goto endswap;

    if (ebpf_update_kernel(&swap_data)) {
        pthread_mutex_unlock(&lock);
        goto endswap;
    }

    probe_links = ebpf_load_program(ebpf_plugin_dir, em, kernel_string, &objects, swap_data.map_fd);
    if (!probe_links) {
        pthread_mutex_unlock(&lock);
        goto endswap;
    }

    ebpf_swap_allocate_global_vectors(NETDATA_SWAP_END);

    int algorithm = NETDATA_EBPF_INCREMENTAL_IDX;
    ebpf_global_labels(&swap_aggregated_data, &swap_publish_aggregated, swap_dimension_name, swap_dimension_name,
                       &algorithm, NETDATA_SWAP_END);

endswap:
    netdata_thread_cleanup_pop(1);
    return NULL;
}
