/* SPDX-License-Identifier: GPL-2.0-or-later */
/* 
 * Copyright (C) 2026 Surajit. All Rights Reserved.
 * Cross-Process Memory Debugger Framework Header
 */

#ifndef _KPM_MEMORY_FRAMEWORK_H
#define _KPM_MEMORY_FRAMEWORK_H

/* Only use NDK headers - avoid APatch ktypes.h conflicts */
#include <stdint.h>
#include <stdbool.h>
#include <stddef.h>

/* Operation Codes */
#define OP_RESOLVE_BASE    0x1000
#define OP_READ_VM         0x2000
#define OP_WRITE_VM        0x3000
#define OP_QUERY_PHYS      0x4000

/* Status Codes */
#define STATUS_SUCCESS          0x0000
#define STATUS_INVALID_PID      0x1001
#define STATUS_INVALID_ADDR     0x1002
#define STATUS_ACCESS_DENIED    0x1003
#define STATUS_PAGE_FAULT       0x1004
#define STATUS_INVALID_SIZE     0x1005
#define STATUS_MMAP_LOCK_FAIL   0x1006
#define STATUS_PAGE_WALK_FAIL   0x1007
#define STATUS_MEM_ALLOC_FAIL   0x1008
#define STATUS_COPY_FAIL        0x1009
#define STATUS_MODULE_BUSY      0x1010

/* Safety limits */
#define MAX_TRANSFER_SIZE      0x100000
#define MAX_PAGES_PER_OP       256
#define KPM_PREFIX             "KPM_MEM_DBG"

/**
 * struct k_packet - Universal Data Packet
 */
struct k_packet {
    uint32_t op_code;
    uint32_t target_pid;
    uint64_t user_buffer;
    uint64_t target_addr;
    uint64_t target_addr_end;
    uint32_t size;
    uint32_t status;
    uint64_t physical_addr;
    uint64_t resolved_base;
    uint32_t page_count;
    uint32_t reserved;
} __attribute__((aligned(8), packed));

#endif /* _KPM_MEMORY_FRAMEWORK_H */
