// SPDX-License-Identifier: GPL-3.0-or-later

#include "ebpf.h"
#include "ebpf_thread.h"

ebpf_local_maps_t thread_maps[] = {{.name = "bug_sizes", .internal_input = NETDATA_EBPF_BUGS_COMMON_LIMIT,
                                       .user_input = 0, .type = NETDATA_EBPF_MAP_STATIC,
                                       .map_fd = ND_EBPF_MAP_FD_NOT_INITIALIZED,
#ifdef LIBBPF_MAJOR_VERSION
                                       .map_type = BPF_MAP_TYPE_PERCPU_HASH
#endif
                                      },
                                      {.name = "bugs_ctrl", .internal_input = NETDATA_CONTROLLER_END,
                                       .user_input = 0,
                                       .type = NETDATA_EBPF_MAP_CONTROLLER,
                                       .map_fd = ND_EBPF_MAP_FD_NOT_INITIALIZED,
#ifdef LIBBPF_MAJOR_VERSION
                                        .map_type = BPF_MAP_TYPE_PERCPU_ARRAY
#endif
                                      },
                                      {.name = "bug_stat", .internal_input = ND_EBPF_DEFAULT_PID_SIZE,
                                       .user_input = 0,
                                       .type = NETDATA_EBPF_MAP_RESIZABLE | NETDATA_EBPF_MAP_PID,
                                       .map_fd = ND_EBPF_MAP_FD_NOT_INITIALIZED,
#ifdef LIBBPF_MAJOR_VERSION
                                        .map_type = BPF_MAP_TYPE_PERCPU_HASH
#endif
                                       },
                                      {.name = "bug_addr", .internal_input = ND_EBPF_DEFAULT_PID_SIZE,
                                       .user_input = 0,
                                       .type = NETDATA_EBPF_MAP_RESIZABLE | NETDATA_EBPF_MAP_PID,
                                       .map_fd = ND_EBPF_MAP_FD_NOT_INITIALIZED,
#ifdef LIBBPF_MAJOR_VERSION
                                       .map_type = BPF_MAP_TYPE_PERCPU_HASH
#endif
                                      },
                                      {.name = "bugs_memptrs", .internal_input = NETDATA_EBPF_BUGS_COMMON_LIMIT,
                                       .user_input = 0,
                                       .type = NETDATA_EBPF_MAP_STATIC,
                                       .map_fd = ND_EBPF_MAP_FD_NOT_INITIALIZED,
#ifdef LIBBPF_MAJOR_VERSION
                                       .map_type = BPF_MAP_TYPE_PERCPU_HASH
#endif
                                       },
                                      {.name = "bugs_overflow", .internal_input = NETDATA_EBPF_BUGS_COMMON_LIMIT,
                                       .user_input = 0,
                                       .type = NETDATA_EBPF_MAP_STATIC,
                                       .map_fd = ND_EBPF_MAP_FD_NOT_INITIALIZED,
#ifdef LIBBPF_MAJOR_VERSION
                                        .map_type = BPF_MAP_TYPE_PERCPU_HASH
#endif
                                      },
                                      {.name = NULL, .internal_input = 0, .user_input = 0,
                                        .type = NETDATA_EBPF_MAP_CONTROLLER,
                                        .map_fd = ND_EBPF_MAP_FD_NOT_INITIALIZED,
}};

struct config thread_config = { .first_section = NULL,
    .last_section = NULL,
    .mutex = NETDATA_MUTEX_INITIALIZER,
    .index = { .avl_tree = { .root = NULL, .compar = appconfig_section_compare },
        .rwlock = AVL_LOCK_INITIALIZER } };

netdata_ebpf_targets_t thread_targets[] = { {.name = "malloc", .mode = EBPF_LOAD_PROBE},
                                          {.name = "malloc", .mode = EBPF_LOAD_RETPROBE},
                                          {.name = "free", .mode = EBPF_LOAD_PROBE},
                                          {.name = "calloc", .mode = EBPF_LOAD_PROBE},
                                          {.name = "calloc", .mode = EBPF_LOAD_RETPROBE},
                                          {.name = "realloc", .mode = EBPF_LOAD_PROBE},
                                          {.name = "realloc", .mode = EBPF_LOAD_RETPROBE},
                                          {.name = "mmap", .mode = EBPF_LOAD_PROBE},
                                          {.name = "mmap", .mode = EBPF_LOAD_RETPROBE},
                                          {.name = "munmap", .mode = EBPF_LOAD_PROBE},
                                          {.name = "posix_memalign", .mode = EBPF_LOAD_PROBE},
                                          {.name = "posix_memalign", .mode = EBPF_LOAD_RETPROBE},
                                          {.name = "memalign", .mode = EBPF_LOAD_PROBE},
                                          {.name = "memalign", .mode = EBPF_LOAD_RETPROBE},
                                          {.name = "sprintf", .mode = EBPF_LOAD_RETPROBE},
                                          {.name = "sprintf", .mode = EBPF_LOAD_RETPROBE},
                                          {.name = "snprintf", .mode = EBPF_LOAD_RETPROBE},
                                          {.name = "snprintf", .mode = EBPF_LOAD_RETPROBE},
                                          {.name = "vfprintf", .mode = EBPF_LOAD_RETPROBE},
                                          {.name = "vfprintf", .mode = EBPF_LOAD_RETPROBE},
                                          {.name = "memcpy", .mode = EBPF_LOAD_RETPROBE},
                                          {.name = "memcpy", .mode = EBPF_LOAD_RETPROBE},
                                          {.name = "release_task", .mode = EBPF_LOAD_TRAMPOLINE},
                                          {.name = NULL, .mode = EBPF_LOAD_TRAMPOLINE}};

const char *libc_path = NULL;
const char *app_name = NULL;
static uint32_t monitor_pid = 0;
struct bugs_memleak_bpf *bugs_skel = NULL;
ebpf_mem_stat_t *bugs_vector = NULL;

struct netdata_static_thread ebpf_read_bugs = {
    .name = "EBPF_READ_THREADS",
    .config_section = NULL,
    .config_name = NULL,
    .env_name = NULL,
    .enabled = 1,
    .thread = NULL,
    .init_routine = NULL,
    .start_routine = NULL
};

netdata_ebpf_judy_pid_t ebpf_bug_pid = {.pid_table = NULL, .index = {.JudyLArray = NULL}};

/**
 * Cachestat exit.
 *
 * Cancel child and exit.
 *
 * @param ptr thread data.
 */
static void ebpf_thread_exit(void *ptr)
{
    (void)ptr;
    if (bugs_skel)
        bugs_memleak_bpf__destroy(bugs_skel);
}


/**
 * Set hash tables
 *
 * Set the values for maps according the value given by kernel.
 *
 * @param obj is the main structure for bpf objects.
 */
static void ebpf_bugs_set_hash_tables(struct bugs_memleak_bpf *obj)
{
    thread_maps[NETDATA_BUGS_SIZES].map_fd = bpf_map__fd(obj->maps.bug_sizes);
    thread_maps[NETDATA_BUGS_CTRL].map_fd = bpf_map__fd(obj->maps.bug_ctrl);
    thread_maps[NETDATA_BUGS_STAT].map_fd = bpf_map__fd(obj->maps.bug_stats);
    thread_maps[NETDATA_BUGS_ADDR].map_fd = bpf_map__fd(obj->maps.bug_addr);
    thread_maps[NETDATA_BUGS_MEMPTRS].map_fd = bpf_map__fd(obj->maps.bugs_memptrs);
    thread_maps[NETDATA_BUGS_OVERFLOW].map_fd = bpf_map__fd(obj->maps.bugs_overflow);
}

int ebpf_bugs_attach_leak_uprobes(struct bugs_memleak_bpf *skel)
{
    ATTACH_UPROBE_CHECKED(skel, libc_path, monitor_pid, malloc, malloc_enter);
    ATTACH_URETPROBE_CHECKED(skel, libc_path, monitor_pid, malloc, malloc_exit);

    ATTACH_UPROBE_CHECKED(skel, libc_path, monitor_pid, calloc, calloc_enter);
    ATTACH_URETPROBE_CHECKED(skel, libc_path, monitor_pid, calloc, calloc_exit);

    ATTACH_UPROBE_CHECKED(skel, libc_path, monitor_pid, realloc, realloc_enter);
    ATTACH_URETPROBE_CHECKED(skel, libc_path, monitor_pid, realloc, realloc_exit);

    ATTACH_UPROBE_CHECKED(skel, libc_path, monitor_pid, mmap, mmap_enter);
    ATTACH_URETPROBE_CHECKED(skel, libc_path, monitor_pid, mmap, mmap_exit);

    ATTACH_UPROBE_CHECKED(skel, libc_path, monitor_pid, posix_memalign, posix_memalign_enter);
    ATTACH_URETPROBE_CHECKED(skel, libc_path, monitor_pid, posix_memalign, posix_memalign_exit);

    ATTACH_UPROBE_CHECKED(skel, libc_path, monitor_pid, memalign, memalign_enter);
    ATTACH_URETPROBE_CHECKED(skel, libc_path, monitor_pid, memalign, memalign_exit);

    ATTACH_UPROBE_CHECKED(skel, libc_path, monitor_pid, free, free_enter);
    ATTACH_UPROBE_CHECKED(skel, libc_path, monitor_pid, munmap, munmap_enter);

    ATTACH_UPROBE_CHECKED(skel, libc_path, monitor_pid, sprintf, sprintf_enter);
//    ATTACH_UPROBE_CHECKED(skel, libc_path, monitor_pid, sprintf, sprintf_exit);

    ATTACH_UPROBE_CHECKED(skel, libc_path, monitor_pid, snprintf, snprintf_enter);
//    ATTACH_UPROBE_CHECKED(skel, libc_path, monitor_pid, snprintf, snprintf_exit);

    ATTACH_UPROBE_CHECKED(skel, libc_path, monitor_pid, vfprintf, vfprintf_enter);
//    ATTACH_UPROBE_CHECKED(skel, libc_path, monitor_pid, vfprintf, vfprintf_exit);

    ATTACH_UPROBE_CHECKED(skel, libc_path, monitor_pid, memcpy, memcpy_enter);
//    ATTACH_UPROBE_CHECKED(skel, libc_path, monitor_pid, memcpy, memcpy_exit);

    return 0;
}

/**
 * Get PID from judy
 *
 * Get a pointer for the `pid` from judy_array;
 *
 * @param judy_array a judy array where PID is the primary key
 * @param pid        pid stored.
 * @param name       name read from kernel ring.
 */
static netdata_ebpf_judy_pid_stats_t *ebpf_get_pid_from_judy_bug_unsafe(PPvoid_t judy_array,
                                                             uint32_t pid,
                                                             char *name,
                                                             uint32_t ppid)
{
    netdata_ebpf_judy_pid_stats_t **pid_pptr =
        (netdata_ebpf_judy_pid_stats_t **)ebpf_judy_insert_unsafe(judy_array, pid);
    netdata_ebpf_judy_pid_stats_t *pid_ptr = *pid_pptr;
    if (likely(*pid_pptr == NULL)) {
        // a new PID added to the index
        *pid_pptr = aral_mallocz(ebpf_bug_pid.pid_table);

        struct ebpf_target *w = NULL;
        struct ebpf_target *target = ebpf_get_apps_groups_target(&ebpf_bugs_target, name, w, name);

        pid_ptr = *pid_pptr;

        strncpyz(pid_ptr->name, name, TASK_COMM_LEN);
        pid_ptr->hash_name = simple_hash(pid_ptr->name);
        pid_ptr->name_len = strlen(pid_ptr->name);
        pid_ptr->apps_target = target;

        pid_ptr->socket_stats.JudyLArray = NULL;
        rw_spinlock_init(&pid_ptr->socket_stats.rw_spinlock);

        ebpf_add_pid_to_apps_group(pid_ptr->apps_target, pid_ptr, pid);
    }

    return pid_ptr;
}


/**
 * Cachestat sum PIDs
 *
 * Sum values for all PIDs associated to a group
 *
 * @param publish  output structure.
 */
void ebpf_bugs_sum_pids(ebpf_mem_publish_stat_t *publish, Pvoid_t JudyLArray, RW_SPINLOCK *rw_spinlock)
{
    rw_spinlock_read_lock(rw_spinlock);
    if (!JudyLArray) {
        rw_spinlock_read_unlock(rw_spinlock);
        return;
    }

    memset(&publish->data, 0, sizeof(ebpf_mem_stat_t));
    publish->leak = 0;
    rw_spinlock_read_lock(&ebpf_bug_pid.index.rw_spinlock);
    PPvoid_t judy_array = &ebpf_bug_pid.index.JudyLArray;

    Pvoid_t *pid_value;
    Word_t local_pid = 0;
    bool first_pid = true;
    ebpf_mem_stat_t *data = &publish->data;
    while ((pid_value = JudyLFirstThenNext(JudyLArray, &local_pid, &first_pid))) {
        netdata_ebpf_judy_pid_stats_t *pid_ptr = ebpf_get_pid_from_judy_bug_unsafe(judy_array,
                                                                               local_pid,
                                                                               NULL,
                                                                               1);
        if (pid_ptr) {
            ebpf_mem_stat_t *src = &pid_ptr->thread.data;
            data->alloc += src->alloc;
            data->oom += src->oom;
            data->str_copy_entry += src->str_copy_entry;
            data->released += src->released;
            data->safe_functions += src->safe_functions;
            data->unsafe_functions += src->unsafe_functions;
            if (data->signal)
                data->signal = src->signal;
            data->size_allocated += src->size_allocated;
            data->size_released += src->size_released;
            if (data->stopped)
                data->stopped = src->stopped;
            if (pid_ptr->thread.data.stopped && !pid_ptr->thread.published) {
                publish->leak += pid_ptr->thread.leak;
                pid_ptr->thread.published = 1;
            }
        }
    }
    rw_spinlock_read_unlock(&ebpf_bug_pid.index.rw_spinlock);
    rw_spinlock_read_unlock(rw_spinlock);
}

/**
 * Send data to Netdata calling auxiliary functions.
 *
 * @param root the target list.
*/
void ebpf_bugs_update_apps_data(struct ebpf_target *root)
{
    struct ebpf_target *w;

    for (w = root; w; w = w->next) {
        if (unlikely(w->exposed)) {
            ebpf_bugs_sum_pids(&w->thread, w->pid_list.JudyLArray, &w->pid_list.rw_spinlock);
        }
    }
}

/**
 * Create apps charts
 *
 * Call ebpf_create_chart to create the charts on apps submenu.
 *
 * @param em a pointer to the structure with the default values.
 */
void ebpf_thread_create_apps_charts(struct ebpf_module *em, void *ptr)
{
    struct ebpf_target *root = ptr;
    struct ebpf_target *w;
    int update_every = em->update_every;
    for (w = root; w; w = w->next) {
        if (unlikely(!w->exposed))
            continue;

        ebpf_write_chart_cmd(NETDATA_APP_FAMILY,
                             w->clean_name,
                             "_ebpf_thread_thread_exit",
                             "Threads that were stopped.",
                             EBPF_COMMON_DIMENSION_BOOL,
                             NETDATA_BUG_SUBMENU,
                             NETDATA_EBPF_CHART_TYPE_LINE,
                             "app.ebpf_thread_thread_exit",
                             20260,
                             update_every,
                             NETDATA_EBPF_MODULE_NAME_BUG);
        ebpf_create_chart_labels("app_group", w->name, 0);
        ebpf_commit_label();
        fprintf(stdout, "DIMENSION exit '' %s 1 1\n", ebpf_algorithms[NETDATA_EBPF_ABSOLUTE_IDX]);

        ebpf_write_chart_cmd(NETDATA_APP_FAMILY,
                             w->clean_name,
                             "_ebpf_thread_release_percentage",
                             "Leak ratio (released/allocated).",
                             EBPF_COMMON_DIMENSION_PERCENTAGE,
                             NETDATA_BUG_SUBMENU,
                             NETDATA_EBPF_CHART_TYPE_LINE,
                             "app.ebpf_thread_release_percentage",
                             20261,
                             update_every,
                             NETDATA_EBPF_MODULE_NAME_BUG);
        ebpf_create_chart_labels("app_group", w->name, 0);
        ebpf_commit_label();
        fprintf(stdout, "DIMENSION ratio '' %s 1 1\n", ebpf_algorithms[NETDATA_EBPF_ABSOLUTE_IDX]);

        ebpf_write_chart_cmd(NETDATA_APP_FAMILY,
                             w->clean_name,
                             "_ebpf_user_alloc_mem",
                             "Allocated memory",
                             EBPF_COMMON_DIMENSION_BYTES,
                             NETDATA_BUG_SUBMENU,
                             NETDATA_EBPF_CHART_TYPE_LINE,
                             "app.ebpf_user_alloc_mem",
                             20562,
                             update_every,
                             NETDATA_EBPF_MODULE_NAME_BUG);
        ebpf_create_chart_labels("app_group", w->name, 0);
        ebpf_commit_label();
        fprintf(stdout, "DIMENSION allocation '' %s 1 1\n", ebpf_algorithms[NETDATA_EBPF_INCREMENTAL_IDX]);

        ebpf_write_chart_cmd(NETDATA_APP_FAMILY,
                             w->clean_name,
                             "_ebpf_user_release_mem",
                             "Released memory",
                             EBPF_COMMON_DIMENSION_BYTES,
                             NETDATA_BUG_SUBMENU,
                             NETDATA_EBPF_CHART_TYPE_LINE,
                             "app.ebpf_user_release_mem",
                             20563,
                             update_every,
                             NETDATA_EBPF_MODULE_NAME_BUG);
        ebpf_create_chart_labels("app_group", w->name, 0);
        ebpf_commit_label();
        fprintf(stdout, "DIMENSION released '' %s 1 1\n", ebpf_algorithms[NETDATA_EBPF_INCREMENTAL_IDX]);

        ebpf_write_chart_cmd(NETDATA_APP_FAMILY,
                             w->clean_name,
                             "_ebpf_user_leak",
                             "Memory leak",
                             EBPF_COMMON_DIMENSION_LEAK,
                             NETDATA_BUG_SUBMENU,
                             NETDATA_EBPF_CHART_TYPE_LINE,
                             "app.ebpf_user_leak",
                             20564,
                             update_every,
                             NETDATA_EBPF_MODULE_NAME_BUG);
        ebpf_create_chart_labels("app_group", w->name, 0);
        ebpf_commit_label();
        fprintf(stdout, "DIMENSION leak '' %s 1 1\n", ebpf_algorithms[NETDATA_EBPF_ABSOLUTE_IDX]);

        ebpf_write_chart_cmd(NETDATA_APP_FAMILY,
                             w->clean_name,
                             "_ebpf_user_oom",
                             "Memory leak",
                             EBPF_COMMON_DIMENSION_LEAK,
                             NETDATA_BUG_SUBMENU,
                             NETDATA_EBPF_CHART_TYPE_LINE,
                             "app.ebpf_user_oom",
                             20565,
                             update_every,
                             NETDATA_EBPF_MODULE_NAME_BUG);
        ebpf_create_chart_labels("app_group", w->name, 0);
        ebpf_commit_label();
        fprintf(stdout, "DIMENSION oom '' %s 1 1\n", ebpf_algorithms[NETDATA_EBPF_ABSOLUTE_IDX]);

        ebpf_write_chart_cmd(NETDATA_APP_FAMILY,
                             w->clean_name,
                             "_ebpf_user_access_buffer",
                             "Store data in buffer.",
                             EBPF_COMMON_DIMENSION_CALL,
                             NETDATA_BUG_SUBMENU,
                             NETDATA_EBPF_CHART_TYPE_LINE,
                             "app.ebpf_user_access_buffer",
                             20566,
                             update_every,
                             NETDATA_EBPF_MODULE_NAME_BUG);
        ebpf_create_chart_labels("app_group", w->name, 0);
        ebpf_commit_label();
        fprintf(stdout, "DIMENSION call '' %s 1 1\n", ebpf_algorithms[NETDATA_EBPF_INCREMENTAL_IDX]);

        ebpf_write_chart_cmd(NETDATA_APP_FAMILY,
                             w->clean_name,
                             "_ebpf_user_str_functions",
                             "Store data in buffer.",
                             EBPF_COMMON_DIMENSION_CALL,
                             NETDATA_BUG_SUBMENU,
                             NETDATA_EBPF_CHART_TYPE_LINE,
                             "app.ebpf_user_str_functions",
                             20567,
                             update_every,
                             NETDATA_EBPF_MODULE_NAME_BUG);
        ebpf_create_chart_labels("app_group", w->name, 0);
        ebpf_commit_label();
        fprintf(stdout, "DIMENSION safe '' %s 1 1\n", ebpf_algorithms[NETDATA_EBPF_INCREMENTAL_IDX]);
        fprintf(stdout, "DIMENSION unsafe '' %s 1 1\n", ebpf_algorithms[NETDATA_EBPF_INCREMENTAL_IDX]);

        ebpf_write_chart_cmd(NETDATA_APP_FAMILY,
                             w->clean_name,
                             "_ebpf_user_signal",
                             "Signals sent to process.",
                             "signal",
                             NETDATA_BUG_SUBMENU,
                             NETDATA_EBPF_CHART_TYPE_LINE,
                             "app.ebpf_user_signal",
                             20568,
                             update_every,
                             NETDATA_EBPF_MODULE_NAME_BUG);
        ebpf_create_chart_labels("app_group", w->name, 0);
        ebpf_commit_label();
        fprintf(stdout, "DIMENSION signal '' %s 1 1\n", ebpf_algorithms[NETDATA_EBPF_ABSOLUTE_IDX]);

        w->charts_created |= 1<<EBPF_MODULE_THREAD_IDX;
    }
    em->apps_charts |= NETDATA_EBPF_APPS_FLAG_CHART_CREATED;

    fflush(stdout);
}

/**
 * Send data to Netdata calling auxiliary functions.
 *
 * @param root the target list.
*/
void ebpf_bugs_send_apps_data(struct ebpf_target *root)
{
    struct ebpf_target *w;
    collected_number value;

    for (w = root; w; w = w->next) {
        if (unlikely(!(w->charts_created & (1 << EBPF_MODULE_THREAD_IDX))))
            continue;

        ebpf_write_begin_chart(NETDATA_APP_FAMILY, w->clean_name, "_ebpf_thread_thread_exit");
        value = (collected_number) w->thread.data.stopped;
        write_chart_dimension("exit", value);
        ebpf_write_end_chart();

        NETDATA_DOUBLE mem_allocated = (NETDATA_DOUBLE)w->thread.data.size_allocated;
        NETDATA_DOUBLE mem_released = (NETDATA_DOUBLE)w->thread.data.size_released;
        ebpf_write_begin_chart(NETDATA_APP_FAMILY, w->clean_name, "_ebpf_thread_release_percentage");
        value = (w->thread.data.size_released) ? (collected_number) ((mem_released/mem_allocated)*100.0) : 0;
        write_chart_dimension("ratio", value);
        ebpf_write_end_chart();

        value = (collected_number)w->thread.data.size_allocated;
        ebpf_write_begin_chart(NETDATA_APP_FAMILY, w->clean_name, "_ebpf_user_alloc_mem");
        write_chart_dimension("allocation", value);
        ebpf_write_end_chart();

        value = (collected_number)w->thread.data.size_released;
        ebpf_write_begin_chart(NETDATA_APP_FAMILY, w->clean_name, "_ebpf_user_release_mem");
        write_chart_dimension("released", value);
        ebpf_write_end_chart();

        value = w->thread.leak;
        ebpf_write_begin_chart(NETDATA_APP_FAMILY, w->clean_name, "_ebpf_user_leak");
        write_chart_dimension("leak", value);
        ebpf_write_end_chart();

        value = w->thread.data.oom;
        ebpf_write_begin_chart(NETDATA_APP_FAMILY, w->clean_name, "_ebpf_user_oom");
        write_chart_dimension("oom", value);
        ebpf_write_end_chart();

        ebpf_write_begin_chart(NETDATA_APP_FAMILY, w->clean_name, "_ebpf_user_str_functions");
        write_chart_dimension("safe", w->thread.data.safe_functions);
        write_chart_dimension("unsafe", w->thread.data.unsafe_functions);
        ebpf_write_end_chart();

        value = w->thread.data.str_copy_entry;
        ebpf_write_begin_chart(NETDATA_APP_FAMILY, w->clean_name, "_ebpf_user_access_buffer");
        write_chart_dimension("call", value);
        ebpf_write_end_chart();

        value = w->thread.data.signal;
        ebpf_write_begin_chart(NETDATA_APP_FAMILY, w->clean_name, "_ebpf_user_signal");
        write_chart_dimension("signal", value);
        ebpf_write_end_chart();
    }
}

/**
* Main loop for this collector.
*/
static void ebpf_bugs_collector(ebpf_module_t *em)
{
    int update_every = em->update_every;
    heartbeat_t hb;
    heartbeat_init(&hb);
    int counter = update_every - 1;
    //This will be cancelled by its parent
    uint32_t running_time = 0;
    uint32_t lifetime = em->lifetime;
    netdata_idx_t *stats = em->hash_table_stats;
    memset(stats, 0, sizeof(em->hash_table_stats));
    while (!ebpf_plugin_exit && running_time < lifetime) {
        (void)heartbeat_next(&hb, USEC_PER_SEC);

        if (ebpf_plugin_exit || ++counter != update_every)
            continue;

        counter = 0;
        netdata_apps_integration_flags_t apps = em->apps_charts;

        pthread_mutex_lock(&collect_data_mutex);

        if (apps & NETDATA_EBPF_APPS_FLAG_CHART_CREATED)
            ebpf_bugs_update_apps_data(ebpf_bugs_target);

        pthread_mutex_unlock(&collect_data_mutex);

        pthread_mutex_lock(&lock);

        pthread_mutex_lock(&collect_data_mutex);
        if (apps & NETDATA_EBPF_APPS_FLAG_CHART_CREATED)
            ebpf_bugs_send_apps_data(ebpf_bugs_target);

        pthread_mutex_unlock(&collect_data_mutex);
        pthread_mutex_unlock(&lock);

        pthread_mutex_lock(&ebpf_exit_cleanup);
        if (running_time && !em->running_time)
            running_time = update_every;
        else
            running_time += update_every;

        em->running_time = running_time;
        pthread_mutex_unlock(&ebpf_exit_cleanup);
    }
}


/*
 * Load BPF
 *
 * Load BPF files.
 *
 * @param em the structure with configuration
 */
static int ebpf_bugs_load_bpf(ebpf_module_t *em)
{
    LIBBPF_OPTS(bpf_object_open_opts, open_opts);

    bugs_skel = bugs_memleak_bpf__open_opts(&open_opts);
    if (!bugs_skel) {
        return -1;
    }

    if (bugs_memleak_bpf__load(bugs_skel)) {
        collector_error("Fail to load bpf program.\n");
        goto ebpf_bugs_attach_err;
    }

    bpf_program__set_attach_target(bugs_skel->progs.netdata_release_task_fentry, 0, "release_task");

    if (ebpf_bugs_attach_leak_uprobes(bugs_skel)) {
        collector_error("Cannot attach uprobe to target.\n");
        goto ebpf_bugs_attach_err;
    }

    if (bugs_memleak_bpf__attach(bugs_skel)) {
        fprintf(stderr, "Fail to attach bpf program.\n");
        return -1;
    }

    ebpf_bugs_set_hash_tables(bugs_skel);

    ebpf_update_controller(thread_maps[NETDATA_BUGS_CTRL].map_fd, em);

    return 0;

ebpf_bugs_attach_err:
    return -1;
}

/**
 * Apps Accumulator
 *
 * Sum all values read from kernel and store in the first address.
 *
 * @param out the vector with read values.
 * @param maps_per_core do I need to read all cores?
 */
static void ebpf_bugs_apps_accumulator(ebpf_mem_stat_t *out, int maps_per_core)
{
    int i, end = (maps_per_core) ? ebpf_nprocs : 1;
    ebpf_mem_stat_t *total = &out[0];
    uint32_t tgid = total->tgid;
    for (i = 1; i < end; i++) {
        ebpf_mem_stat_t *w = &out[i];
        total->alloc += w->alloc;
        total->oom += w->oom;
        total->str_copy_entry += w->str_copy_entry;
        total->released += w->released;
        total->safe_functions += w->safe_functions;
        total->unsafe_functions += w->unsafe_functions;
        if (w->signal)
            total->signal = w->signal;
        total->size_allocated += w->size_allocated;
        total->size_released += w->size_released;
        if (total->stopped)
            total->stopped = w->stopped;

        if (!isascii(total->name[0]) && isascii(w->name[0])) {
            strncpyz(total->name, w->name, TASK_COMM_LEN);
        }

        if (!tgid && w->tgid)
            tgid = w->tgid;
    }
    total->tgid = tgid;
}


/**
 * Read APPS table
 *
 * Read the apps table and store data inside the structure.
 *
 * @param maps_per_core do I need to read all cores?
 */
static void ebpf_read_bugs_apps_table(int maps_per_core)
{
    netdata_thread_disable_cancelability();
    ebpf_mem_stat_t *bv = bugs_vector;
    uint32_t key = 0, next_key = 0;
    int fd = thread_maps[NETDATA_BUGS_STAT].map_fd;
    size_t length = sizeof(ebpf_mem_stat_t);
    if (maps_per_core)
        length *= ebpf_nprocs;

    // To avoid call time() different times, we only difference between starts.
    while (bpf_map_get_next_key(fd, &key, &next_key) == 0) {
        if (bpf_map_lookup_elem(fd, &key, bv)) {
            goto end_bugs_loop;
        }

        if (key > (uint32_t)pid_max) {
            goto end_bugs_loop;
        }

        ebpf_bugs_apps_accumulator(bv, maps_per_core);

        rw_spinlock_write_lock(&ebpf_bug_pid.index.rw_spinlock);
        PPvoid_t judy_array = &ebpf_bug_pid.index.JudyLArray;
        netdata_ebpf_judy_pid_stats_t *pid_ptr = ebpf_get_pid_from_judy_bug_unsafe(judy_array,
                                                                               key,
                                                                               bv->name,
                                                                               bv->tgid);
        if (!pid_ptr) {
            rw_spinlock_write_unlock(&ebpf_bug_pid.index.rw_spinlock);
            goto end_bugs_loop;
        }

        memcpy(&pid_ptr->thread.data, bv, sizeof(ebpf_mem_stat_t));
        pid_ptr->thread.leak = (!pid_ptr->thread.leak && pid_ptr->thread.data.stopped &&
                             pid_ptr->thread.data.size_allocated != pid_ptr->thread.data.size_released);

        rw_spinlock_write_unlock(&ebpf_bug_pid.index.rw_spinlock);

        // We are cleaning to avoid passing data read from one process to other.
end_bugs_loop:
        memset(bv, 0, length);
        key = next_key;
    }
    netdata_thread_enable_cancelability();
}


/**
 * Bug thread
 *
 * Thread used to generate bug charts.
 *
 * @param ptr a pointer to `struct ebpf_module`
 *
 * @return It always return NULL
 */
void *ebpf_read_bugs_thread(void *ptr)
{
    heartbeat_t hb;
    heartbeat_init(&hb);

    ebpf_module_t *em = (ebpf_module_t *)ptr;

    int maps_per_core = em->maps_per_core;
    int update_every = em->update_every;
    ebpf_read_bugs_apps_table(maps_per_core);

    int counter = update_every - 1;

    uint32_t running_time = 0;
    uint32_t lifetime = em->lifetime;
    usec_t period = update_every * USEC_PER_SEC;
    while (!ebpf_plugin_exit && running_time < lifetime) {
        (void)heartbeat_next(&hb, period);
        if (ebpf_plugin_exit || ++counter != update_every)
            continue;

        ebpf_read_bugs_apps_table(maps_per_core);

        counter = 0;
    }

    return NULL;
}


/**
 * Parse table size options
 *
 * @param cfg configuration options read from user file.
 */
void ebpf_parse_thread_opt(struct config *cfg)
{
    libc_path = appconfig_get(cfg,
                             EBPF_GLOBAL_SECTION,
                             NETDATA_EBPF_C_LIBRARY_OPT_PATH,
                             NETDATA_EBPF_C_LIBRARY_PATH);

    app_name = appconfig_get(cfg,
                              EBPF_GLOBAL_SECTION, NETDATA_EBPF_C_MONITOR_APP,
                              NULL);

    monitor_pid = (uint32_t)appconfig_get_number(cfg,
                               EBPF_GLOBAL_SECTION,
                               NETDATA_EBPF_C_PID_SELECT,
                               monitor_pid);

    if (app_name) {
        monitor_pid =  ebpf_find_pid(app_name);
    }

    if (!monitor_pid) {
        monitor_pid = getppid();
    }

#ifdef NETDATA_DEV_MODE
    collector_info("It was found the PID %u for process name %s", monitor_pid, app_name);
#endif
}

/**
 * Allocate vectors used with this thread.
 *
 * We are not testing the return, because callocz does this and shutdown the software
 * case it was not possible to allocate.
 */
static void ebpf_bugs_allocate_global_vectors()
{
    bugs_vector = callocz((size_t)ebpf_nprocs, sizeof(ebpf_mem_stat_t));
}

/**
 * Cachestat thread
 *
 * Thread used to make cachestat thread
 *
 * @param ptr a pointer to `struct ebpf_module`
 *
 * @return It always return NULL
 */
void *ebpf_thread_monitoring(void *ptr)
{
    netdata_thread_cleanup_push(ebpf_thread_exit, ptr);

    ebpf_module_t *em = (ebpf_module_t *)ptr;
    em->maps = thread_maps;

    ebpf_parse_thread_opt(&thread_config);

    ebpf_bug_pid.pid_table = ebpf_allocate_pid_aral(NETDATA_EBPF_PID_THREAD_ARAL_TABLE_NAME,
                                                    sizeof(netdata_ebpf_judy_pid_stats_t));
    rw_spinlock_init(&ebpf_bug_pid.index.rw_spinlock);

    if (ebpf_bugs_load_bpf(em)) {
        goto endbugs;
    }

    ebpf_bugs_allocate_global_vectors();

    ebpf_read_bugs.thread = mallocz(sizeof(netdata_thread_t));
    netdata_thread_create(ebpf_read_bugs.thread,
                          ebpf_read_bugs.name,
                          NETDATA_THREAD_OPTION_DEFAULT,
                          ebpf_read_bugs_thread,
                          em);

    ebpf_bugs_collector(em);

endbugs:
    netdata_thread_cleanup_pop(1);
    return NULL;
}
