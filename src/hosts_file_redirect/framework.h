/* SPDX-License-Identifier: GPL-2.0-or-later */
/* 
 * Copyright (C) 2026 Surajit. All Rights Reserved.
 * 
 * Cross-Process Memory Debugger Framework Header
 * Direct memory bridge for system profiling on ARM64
 * Compatible with APatch/KernelPatch SDK
 */

#ifndef _KPM_MEMORY_FRAMEWORK_H
#define _KPM_MEMORY_FRAMEWORK_H

/* Only include headers available in APatch SDK */
#include <linux/types.h>
#include <linux/mm.h>
#include <linux/sched.h>
#include <linux/pid.h>
#include <linux/uaccess.h>
#include <linux/slab.h>
#include <linux/pagemap.h>
#include <linux/version.h>
#include <linux/printk.h>
#include <linux/string.h>
#include <linux/atomic.h>
#include <linux/rwsem.h>
#include <asm/pgtable.h>
#include <kpm_utils.h>

/* 
 * Operation Codes for Universal Data Packet
 * These must match userspace definitions exactly
 */
#define OP_RESOLVE_BASE    0x1000  /* Resolve process executable base address */
#define OP_READ_VM         0x2000  /* Read from target process virtual memory */
#define OP_WRITE_VM        0x3000  /* Write to target process virtual memory */
#define OP_QUERY_PHYS      0x4000  /* Query physical address from virtual address */

/* 
 * Status Codes
 * Returned in k_packet.status after each operation
 */
#define STATUS_SUCCESS          0x0000  /* Operation completed successfully */
#define STATUS_INVALID_PID      0x1001  /* Target process not found */
#define STATUS_INVALID_ADDR     0x1002  /* Invalid virtual address range */
#define STATUS_ACCESS_DENIED    0x1003  /* Access permission denied */
#define STATUS_PAGE_FAULT       0x1004  /* Page not present or faulted */
#define STATUS_INVALID_SIZE     0x1005  /* Invalid transfer size */
#define STATUS_MMAP_LOCK_FAIL   0x1006  /* Failed to acquire mmap_lock */
#define STATUS_PAGE_WALK_FAIL   0x1007  /* Page table walk failed */
#define STATUS_MEM_ALLOC_FAIL   0x1008  /* Kernel memory allocation failed */
#define STATUS_COPY_FAIL        0x1009  /* copy_to/from_user failed */
#define STATUS_MODULE_BUSY      0x1010  /* Module is busy with another operation */

/* Safety limits */
#define MAX_TRANSFER_SIZE      0x100000   /* 1MB maximum per operation */
#define MAX_PAGES_PER_OP       256        /* Maximum pages to pin at once */
#define KPM_PREFIX             "KPM_MEM_DBG"

/* Debug macros for consistent logging */
#define kpm_info(fmt, ...)  pr_info(KPM_PREFIX ": " fmt, ##__VA_ARGS__)
#define kpm_err(fmt, ...)   pr_err(KPM_PREFIX ": " fmt, ##__VA_ARGS__)
#define kpm_debug(fmt, ...) pr_debug(KPM_PREFIX ": " fmt, ##__VA_ARGS__)
#define kpm_warn(fmt, ...)  pr_warn(KPM_PREFIX ": " fmt, ##__VA_ARGS__)

/**
 * struct k_packet - Universal Data Packet for userspace-kernel communication
 * 
 * This structure MUST be 8-byte aligned for ARM64 compatibility.
 * All fields are explicitly sized for cross-architecture consistency.
 */
struct k_packet {
    uint32_t op_code;            /* [IN]  Operation code */
    uint32_t target_pid;         /* [IN]  Target process PID */
    uint64_t user_buffer;        /* [IN]  Userspace buffer pointer */
    uint64_t target_addr;        /* [IN]  Target virtual address */
    uint64_t target_addr_end;    /* [IN]  End address for range ops */
    uint32_t size;               /* [IN]  Transfer size in bytes */
    uint32_t status;             /* [OUT] Operation status */
    uint64_t physical_addr;      /* [OUT] Resolved physical address */
    uint64_t resolved_base;      /* [OUT] Resolved module base address */
    uint32_t page_count;         /* [OUT] Number of pages processed */
    uint32_t reserved;           /* Padding for 8-byte alignment */
} __attribute__((aligned(8), packed));

/**
 * struct mem_op_context - Internal memory operation state
 */
struct mem_op_context {
    struct mm_struct *target_mm;
    struct task_struct *target_task;
    struct page **pages;
    void **kva_array;
    unsigned long start_addr;
    unsigned long end_addr;
    int nr_pages;
    int write_mode;
    bool pages_pinned;
    bool pages_mapped;
};

/* 
 * Function Declarations
 * Cross-file references for modular compilation
 */

/* memory_core.c - Core memory operations */
int memory_initialize(void);
void memory_cleanup(void);
int handle_memory_read(struct k_packet *pkt);
int handle_memory_write(struct k_packet *pkt);
int resolve_process_base(struct k_packet *pkt);

/* process_helper.c - Process and MMU helpers */
int get_process_mm(pid_t pid, struct mm_struct **mm, struct task_struct **task);
void put_process_mm(struct mm_struct *mm);
unsigned long virtual_to_physical(struct mm_struct *mm, unsigned long vaddr);
int validate_user_address(struct mm_struct *mm, unsigned long vaddr, unsigned long size);
int pin_user_pages_for_transfer(struct mm_struct *mm, unsigned long vaddr,
                                 unsigned long size, int write, struct mem_op_context *ctx);
void unpin_user_pages(struct mem_op_context *ctx);
int copy_data_to_user_pages(struct mem_op_context *ctx, void *src, size_t size);
int copy_data_from_user_pages(struct mem_op_context *ctx, void *dst, size_t size);

/* Helper functions reimplemented for APatch environment */
static inline void *kpm_kmap(struct page *page)
{
    return page ? page_address(page) : NULL;
}

static inline void kpm_kunmap(struct page *page)
{
    /* No-op in APatch environment */
}

static inline bool kpm_virt_addr_valid(const void *addr)
{
    return addr != NULL;
}

static inline void kpm_set_page_dirty(struct page *page)
{
    if (page) {
        /* Mark page as dirty for writeback */
        set_page_dirty(page);
    }
}

#endif /* _KPM_MEMORY_FRAMEWORK_H */
