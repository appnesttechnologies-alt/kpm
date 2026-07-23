/* SPDX-License-Identifier: GPL-2.0-or-later */
/* 
 * Copyright (C) 2026 Surajit. All Rights Reserved.
 * 
 * Cross-Process Memory Debugger Framework Header
 * Compatible with APatch/KernelPatch SDK
 */

#ifndef _KPM_MEMORY_FRAMEWORK_H
#define _KPM_MEMORY_FRAMEWORK_H

/* Minimal includes - avoid APatch SDK type conflicts */
#include <linux/types.h>
#include <linux/mm.h>
#include <linux/uaccess.h>
#include <linux/slab.h>
#include <linux/version.h>
#include <linux/printk.h>
#include <linux/string.h>
#include <kpm_utils.h>

/* Forward declarations for types we need */
struct task_struct;
struct mm_struct;
struct vm_area_struct;
struct page;
struct pid;

/* Include sched and pid via KPM utils */
#include <linux/sched.h>
#include <linux/pid.h>

/* 
 * Operation Codes for Universal Data Packet
 */
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

/* Debug macros */
#define kpm_info(fmt, ...)  pr_info(KPM_PREFIX ": " fmt, ##__VA_ARGS__)
#define kpm_err(fmt, ...)   pr_err(KPM_PREFIX ": " fmt, ##__VA_ARGS__)
#define kpm_debug(fmt, ...) pr_info(KPM_PREFIX ": " fmt, ##__VA_ARGS__)
#define kpm_warn(fmt, ...)  pr_warn(KPM_PREFIX ": " fmt, ##__VA_ARGS__)

/* Mutex implementation - simple spinlock based */
struct kpm_mutex {
    atomic_t locked;
};

#define DEFINE_KPM_MUTEX(name) \
    struct kpm_mutex name = { .locked = ATOMIC_INIT(0) }

static inline void kpm_mutex_lock(struct kpm_mutex *m)
{
    while (atomic_cmpxchg(&m->locked, 0, 1) != 0)
        cpu_relax();
}

static inline void kpm_mutex_unlock(struct kpm_mutex *m)
{
    atomic_set(&m->locked, 0);
}

/**
 * struct k_packet - Universal Data Packet
 * MUST be 8-byte aligned for ARM64
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

/**
 * struct mem_op_context - Internal operation state
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

/* Function Declarations */
int memory_initialize(void);
void memory_cleanup(void);
int handle_memory_read(struct k_packet *pkt);
int handle_memory_write(struct k_packet *pkt);
int resolve_process_base(struct k_packet *pkt);

int get_process_mm(pid_t pid, struct mm_struct **mm, struct task_struct **task);
void put_process_mm(struct mm_struct *mm);
unsigned long virtual_to_physical(struct mm_struct *mm, unsigned long vaddr);
int validate_user_address(struct mm_struct *mm, unsigned long vaddr, unsigned long size);
int pin_user_pages_for_transfer(struct mm_struct *mm, unsigned long vaddr,
                                 unsigned long size, int write, struct mem_op_context *ctx);
void unpin_user_pages(struct mem_op_context *ctx);
int copy_data_to_user_pages(struct mem_op_context *ctx, void *src, size_t size);
int copy_data_from_user_pages(struct mem_op_context *ctx, void *dst, size_t size);

/* KPM-compatible page helpers */
static inline void *kpm_page_address(struct page *page)
{
    return page ? ((void *)((unsigned long)page_to_virt(page))) : NULL;
}

static inline bool kpm_page_valid(struct page *page)
{
    return page != NULL;
}

static inline void kpm_set_page_dirty(struct page *page)
{
    if (page) {
        set_page_dirty(page);
    }
}

#endif /* _KPM_MEMORY_FRAMEWORK_H */
