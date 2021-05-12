// SPDX-License-Identifier: GPL-3.0-or-later

#ifndef NETDATA_EBPF_VFS_H
#define NETDATA_EBPF_VFS_H 1

// configuration file
#define NETDATA_DIRECTORY_VFS_CONFIG_FILE "vfs.conf"

#define NETDATA_LATENCY_VFS_SLEEP_MS 750000ULL

typedef struct netdata_publish_vfs {
    uint64_t pid_tgid;
    uint32_t pid;
    uint32_t pad;

    //Counter
    uint32_t write_call;
    uint32_t writev_call;
    uint32_t read_call;
    uint32_t readv_call;
    uint32_t unlink_call;

    //Accumulator
    uint64_t write_bytes;
    uint64_t writev_bytes;
    uint64_t readv_bytes;
    uint64_t read_bytes;

    //Counter
    uint32_t write_err;
    uint32_t writev_err;
    uint32_t read_err;
    uint32_t readv_err;
    uint32_t unlink_err;
} netdata_publish_vfs_t;

enum vfs_counters {
    NETDATA_KEY_CALLS_VFS_WRITE,
    NETDATA_KEY_ERROR_VFS_WRITE,
    NETDATA_KEY_BYTES_VFS_WRITE,

    NETDATA_KEY_CALLS_VFS_WRITEV,
    NETDATA_KEY_ERROR_VFS_WRITEV,
    NETDATA_KEY_BYTES_VFS_WRITEV,

    NETDATA_KEY_CALLS_VFS_READ,
    NETDATA_KEY_ERROR_VFS_READ,
    NETDATA_KEY_BYTES_VFS_READ,

    NETDATA_KEY_CALLS_VFS_READV,
    NETDATA_KEY_ERROR_VFS_READV,
    NETDATA_KEY_BYTES_VFS_READV,

    NETDATA_KEY_CALLS_VFS_UNLINK,
    NETDATA_KEY_ERROR_VFS_UNLINK,

    // Keep this as last and don't skip numbers as it is used as element counter
    NETDATA_VFS_COUNTER
};

enum netdata_publish_vfs_list {
    NETDATA_KEY_PUBLISH_VFS_UNLINK,
    NETDATA_KEY_PUBLISH_VFS_READ,
    NETDATA_KEY_PUBLISH_VFS_WRITE,

    NETDATA_KEY_PUBLISH_VFS_END
};

enum netdata_vfs_tables {
    NETDATA_VFS_PID,
    NETDATA_VFS_ALL
};

// Global chart name
#define NETDATA_VFS_FILE_CLEAN_COUNT "deleted_objects"
#define NETDATA_VFS_FILE_IO_COUNT "io"
#define NETDATA_VFS_FILE_ERR_COUNT "io_error"
#define NETDATA_VFS_IO_FILE_BYTES "io_bytes"

// Groups used on Dashboard
#define NETDATA_VFS_GROUP "VFS (eBPF)"

// Charts created on Apps submenu
#define NETDATA_SYSCALL_APPS_FILE_OPEN "file_open"
#define NETDATA_SYSCALL_APPS_FILE_CLOSED "file_closed"
#define NETDATA_SYSCALL_APPS_FILE_DELETED "file_deleted"
#define NETDATA_SYSCALL_APPS_VFS_WRITE_CALLS "vfs_write_call"
#define NETDATA_SYSCALL_APPS_VFS_READ_CALLS "vfs_read_call"
#define NETDATA_SYSCALL_APPS_VFS_WRITE_BYTES "vfs_write_bytes"
#define NETDATA_SYSCALL_APPS_VFS_READ_BYTES "vfs_read_bytes"
#define NETDATA_SYSCALL_APPS_TASK_PROCESS "process_create"
#define NETDATA_SYSCALL_APPS_TASK_THREAD "thread_create"
#define NETDATA_SYSCALL_APPS_TASK_CLOSE "task_close"
#define NETDATA_SYSCALL_APPS_FILE_OPEN_ERROR "file_open_error"
#define NETDATA_SYSCALL_APPS_FILE_CLOSE_ERROR "file_close_error"
#define NETDATA_SYSCALL_APPS_VFS_WRITE_CALLS_ERROR "vfs_write_error"
#define NETDATA_SYSCALL_APPS_VFS_READ_CALLS_ERROR "vfs_read_error"

extern void ebpf_vfs_create_apps_charts(struct ebpf_module *em, void *ptr);
extern void *ebpf_vfs_thread(void *ptr);
extern void clean_vfs_pid_structures();

extern netdata_publish_vfs_t **vfs_pid;

#endif /* NETDATA_EBPF_VFS_H */
