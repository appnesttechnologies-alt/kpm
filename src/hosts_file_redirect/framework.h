/* SPDX-License-Identifier: GPL-2.0-or-later */
/* 
 * Copyright (C) 2026 Surajit. All Rights Reserved.
 * 
 * Cross-Process Memory Debugger Framework Header
 * Direct memory bridge for system profiling on ARM64
 */

#ifndef _KPM_MEMORY_FRAMEWORK_H
#define _KPM_MEMORY_FRAMEWORK_H

#include <linux/types.h>
#include <linux/mm.h>
#include <linux/sched.h>
#include <linux/pid.h>
#include <linux/uaccess.h>
#include <linux/slab.h>
#include <linux/highmem.h>
#include <linux/pagemap.h>
#include <linux/mutex.h>
#include <linux/delay.h>
#include <linux/version.h>
#include <linux/printk.h>
#include <linux/string.h>
#include <linux/atomic.h>
#include <linux/rwsem.h>
#include <linux/mm_types.h>
#include <linux/rmap.h>
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

/* 
 * ARM64 Architecture Constants
 * 4-level page table walk parameters
 */
#define ARM64_PAGE_SHIFT       12
#define ARM64_PAGE_SIZE        (1UL << ARM64_PAGE_SHIFT)
#define ARM64_PAGE_MASK        (~(ARM64_PAGE_SIZE - 1))
#define ARM64_PGD_SHIFT        39
#define ARM64_PUD_SHIFT        30
#define ARM64_PMD_SHIFT        21
#define ARM64_PGD_MASK         0x1FF
#define ARM64_PUD_MASK         0x1FF
#define ARM64_PMD_MASK         0x1FF
#define ARM64_PTE_MASK         0x1FF
#define ARM64_PTRS_PER_PGD     512
#define ARM64_PTRS_PER_PUD     512
#define ARM64_PTRS_PER_PMD     512
#define ARM64_PTRS_PER_PTE     512

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
 * 
 * Layout:
 * - op_code: Operation to perform
 * - target_pid: Target process identifier
 * - user_buffer: Userspace data buffer pointer
 * - target_addr: Virtual address to operate on
 * - target_addr_end: End address for range operations
 * - size: Transfer size in bytes
 * - status: Operation result status
 * - physical_addr: Resolved physical address (output)
 * - resolved_base: Resolved module base address (output)
 * - page_count: Number of pages processed (output)
 * - reserved: Padding for future expansion
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
 * 
 * Holds all state for a single memory operation including
 * pinned pages and their kernel mappings.
 */
struct mem_op_context {
    struct mm_struct *target_mm;      /* Target process mm_struct */
    struct task_struct *target_task;   /* Target task_struct */
    struct page **pages;              /* Array of pinned pages */
    void **kva_array;                 /* Kernel virtual addresses */
    unsigned long start_addr;         /* Start virtual address */
    unsigned long end_addr;           /* End virtual address */
    int nr_pages;                     /* Number of pinned pages */
    int write_mode;                   /* Non-zero if write operation */
    bool pages_pinned;                /* Track pin state */
    bool pages_mapped;                /* Track map state */
};

/* 
 * Function Declarations
 * Cross-file references for modular compilation
 */

/* main.c - Module lifecycle */
extern struct mutex ctl0_lock;

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

#endif /* _KPM_MEMORY_FRAMEWORK_H */