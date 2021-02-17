// SPDX-License-Identifier: GPL-3.0-or-later

#ifndef NETDATA_EBPF_IO_LATENCY_H
#define NETDATA_EBPF_IO_LATENCY_H 1

// Proc file
#define NETDATA_LATENCY_PROC_PARTITIONS "/proc/partitions"

// Global defintions
#define NETDATA_LATENCY_READ_SLEEP_MS 700000ULL
#define NETDATA_LATENCY_HIST_BINS 32

// Global chart name
#define NETDATA_LATENCY_IOPS "iops"
#define NETDATA_LATENCY_BYTES "iops_bytes"
#define NETDATA_LATENCY_BLOCK_IO "Block IO"

// Sync chart
#define NETDATA_LATENCY_SYNC "Sync"

#define NETDATA_BOOTSECTOR_MONITORING "bootsector"
#define NETDATA_EBPF_SECURITY "Security"

// Mount calls monitoring
#define NETDATA_MOUNT_CALLS "mount_calls"
#define NETDATA_MOUNT_ERROR "mount_errors"
#define NETDATA_MOUNT_MENU "Mount"

// This enum cannot have its order changed, this will affect the chart results.
enum io_latency_counters {
    NETDATA_KEY_CALLS_BLOCK_RQ_ISSUE,
    NETDATA_KEY_CALLS_BLOCK_RQ_COMPLETE_READ,
    NETDATA_KEY_CALLS_BLOCK_RQ_COMPLETE_WRITE,
    NETDATA_KEY_BYTES_READ,
    NETDATA_KEY_BYTES_WRITE,
    NETDATA_KEY_CALL_SYNC,
    NETDATA_KEY_CALL_MOUNT_CALL,
    NETDATA_KEY_CALL_UMOUNT_CALL,
    NETDATA_KEY_CALL_MOUNT_ERR,
    NETDATA_KEY_CALL_UMOUNT_ERR,

    NETDATA_LATENCY_COUNTER
};

enum io_latency_tables {
    NETDATA_IO_LATENCY_READ_BYTES_HISTOGRAM,
    NETDATA_IO_LATENCY_READ_CALL_HISTOGRAM,
    NETDATA_IO_LATENCY_WRITE_BYTES_HISTOGRAM,
    NETDATA_IO_LATENCY_WRITE_CALL_HISTOGRAM,
    NETDATA_IO_LATENCY_GLOBAL_STATS,
//   NETDATA_IO_MD_FLUSH,
    NETDATA_IO_LATENCY_TEMPORARY_TABLE,
    NETDATA_BOOTSECTOR_INFO
};

typedef struct netdata_bootsector {
    uint64_t start_sector;
    uint64_t end_sector;
    uint64_t timestamp;
    uint64_t changed_sector;
    uint64_t size;
} netdata_bootsector_t;

enum netdata_latency_disks_flags {
    NETDATA_DISK_CREATED = 1,
    NETDATA_DISK_PLOT = 2,
    NETDATA_DISK_HAS_EFI = 4
};

/*
 * The definition (DISK_NAME_LEN) has been a stable value since Kernel 3.0,
 * I decided to bring it as internal definition, to avoid include linux/genhd.h.
 */
#define NETDATA_DISK_NAME_LEN 32
typedef struct netdata_latency_disks {
    // Search
    avl avl;
    uint32_t dev;
    uint32_t major;
    uint32_t minor;

    // Print information
    char family[NETDATA_DISK_NAME_LEN];
    char *chart;
    uint64_t *histogram_read_calls;
    uint64_t read_bytes;
    uint64_t *histogram_write_calls;
    uint64_t written_bytes;
    uint32_t flags;
    uint32_t bootsector_key;
    uint64_t start; // start sector
    uint64_t end;   // end sectpr
    struct netdata_latency_disks *next;
} netdata_latency_disks_t;

typedef struct block_key {
    uint32_t bin;
    uint32_t dev;
} block_key_t;

typedef struct netdata_flush_key {
    char key[NETDATA_DISK_NAME_LEN];
} netdata_flush_key_t;

// Decode function extracted from: https://elixir.bootlin.com/linux/v5.10.8/source/include/linux/kdev_t.h#L46
static inline uint32_t netdata_new_encode_dev(uint32_t major, uint32_t minor) {
    return (minor & 0xff) | (major << 8) | ((minor & ~0xff) << 12);
}

// Decode function extracted from: https://elixir.bootlin.com/linux/v5.10.8/source/include/linux/kdev_t.h#L7
#define MINORBITS	20
#define MKDEV(ma,mi)	(((ma) << MINORBITS) | (mi))

extern void *ebpf_io_latency_thread(void *ptr);

#endif
