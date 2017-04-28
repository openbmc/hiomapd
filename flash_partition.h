#pragma once

#define PARTITION_NAME_MAX 15
#define PARTITION_VERSION_1 1
#define HDR_MAGIC 0x50415254
#define ENTRY_PID_TOPLEVEL 0xFFFFFFFF
#define ENTRY_USER_WORDS 16
#define PARTITION_ECC_PROTECTED 0x8000
#define PARTITION_PRESERVED 0x80000000
#define PARTITION_READONLY 0x40000000
#define PARTITION_TYPE_DATA 1


/**
 * struct partition_entry - Partition entry
 *
 * @name:       Opaque null terminated string
 * @base:       Starting offset of partition in flash (in hdr.blockSize)
 * @size:       Partition size (in hdr.blockSize)
 * @pid:        Parent partition entry
 * @id:         Partition entry ID [1..65536]
 * @type:       Describe type of partition
 * @flags:      Partition attributes (optional)
 * @actual:     Actual partition size (in bytes)
 * @resvd:      Reserved words for future use
 * @user:       User data (optional)
 * @checksum:   Partition entry checksum (includes all above)
 */
struct partition_entry {
    char         name[PARTITION_NAME_MAX + 1];
    uint32_t     base;
    uint32_t     size;
    uint32_t     pid;
    uint32_t     id;
    uint32_t     type;
    uint32_t     flags;
    uint32_t     actual;
    uint32_t     resvd[4];
    struct
    {
        uint32_t data[ENTRY_USER_WORDS];
    } user;
    uint32_t     checksum;
} __attribute__ ((packed));

/**
 * struct partition_hdr - Partition header
 *
 * @magic:          Eye catcher/corruption detector
 * @version:        Version of the structure
 * @size:           Size of partition table (in blockSize)
 * @entry_size:     Size of struct partition_entry element (in bytes)
 * @entry_count:    Number of struct partition_entry elements in @entries array
 * @block_size:     Size of block on device (in bytes)
 * @block_count:    Number of blocks on device
 * @resvd:          Reserved words for future use
 * @checksum:       Header checksum
 * @entries:        Pointer to array of partition entries
 */
struct partition_hdr {
    uint32_t         magic;
    uint32_t         version;
    uint32_t         size;
    uint32_t         entry_size;
    uint32_t         entry_count;
    uint32_t         block_size;
    uint32_t         block_count;
    uint32_t         resvd[4];
    uint32_t         checksum;
    struct partition_entry entries[];
} __attribute__ ((packed));
