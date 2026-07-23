/* SPDX-License-Identifier: GPL-2.0-or-later */
/* 
 * Copyright (C) 2026 Surajit. All Rights Reserved.
 * Single-File Self-Contained KPM Memory Debugger Module
 */

#include <linux/printk.h>
#include <linux/string.h>
#include <linux/slab.h>
#include <linux/uaccess.h>
#include <linux/sched.h>
#include <linux/mm.h>
#include <linux/pid.h>
#include <linux/version.h>
#include <kpm_utils.h>

/* Module details for APatch framework */
KPM_NAME("surajit_memory_debugger");
KPM_VERSION("1.0.9");
KPM_LICENSE("GPL v2");
KPM_AUTHOR("Surajit");
KPM_DESCRIPTION("Single-file self-contained kernel memory read/write debugger.");

#define KPM_PREFIX             "SURAJIT_MEM"
#define kpm_info(fmt, ...)     pr_info(KPM_PREFIX ": " fmt, ##__VA_ARGS__)
#define kpm_err(fmt, ...)      pr_err(KPM_PREFIX ": " fmt, ##__VA_ARGS__)

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

/* Internal context structure */
struct mem_op_context {
    void *target_mm;
    struct page **pages;
    void **kva_array;
    unsigned long start_addr;
    unsigned long end_addr;
    int nr_pages;
    int write_mode;
};

/* External kernel helpers / stubs handled cleanly */
extern int get_process_mm(pid_t pid, void **mm, struct task_struct **task);
extern void put_process_mm(void *mm);
extern unsigned long virtual_to_physical(void *mm, unsigned long vaddr);
extern int validate_user_address(void *mm, unsigned long vaddr, unsigned long size);
extern int pin_user_pages_for_transfer(void *mm, unsigned long vaddr, unsigned long size, int write, struct mem_op_context *ctx);
extern void unpin_user_pages(struct mem_op_context *ctx);
extern int copy_data_to_user_pages(struct mem_op_context *ctx, void *src, size_t size);
extern int copy_data_from_user_pages(struct mem_op_context *ctx, void *dst, size_t size);

/* Core Memory Handlers */
int handle_memory_read(struct k_packet *pkt)
{
    void *mm = NULL;
    struct task_struct *task = NULL;
    struct mem_op_context ctx;
    void *kernel_buffer = NULL;
    int ret = 0;
    
    if (pkt->size == 0 || pkt->size > MAX_TRANSFER_SIZE) {
        pkt->status = STATUS_INVALID_SIZE;
        return -22;
    }
    
    ret = get_process_mm(pkt->target_pid, &mm, &task);
    if (ret < 0) {
        pkt->status = STATUS_INVALID_PID;
        return ret;
    }
    
    ret = validate_user_address(mm, pkt->target_addr, pkt->size);
    if (ret < 0) {
        pkt->status = STATUS_INVALID_ADDR;
        put_process_mm(mm);
        return ret;
    }
    
    kernel_buffer = kmalloc(pkt->size, GFP_KERNEL);
    if (!kernel_buffer) {
        pkt->status = STATUS_MEM_ALLOC_FAIL;
        put_process_mm(mm);
        return -12;
    }
    
    memset(&ctx, 0, sizeof(ctx));
    
    ret = pin_user_pages_for_transfer(mm, pkt->target_addr, pkt->size, 0, &ctx);
    if (ret < 0) {
        pkt->status = STATUS_PAGE_FAULT;
        kfree(kernel_buffer);
        put_process_mm(mm);
        return ret;
    }
    
    ret = copy_data_from_user_pages(&ctx, kernel_buffer, pkt->size);
    if (ret < 0) {
        pkt->status = STATUS_COPY_FAIL;
        unpin_user_pages(&ctx);
        kfree(kernel_buffer);
        put_process_mm(mm);
        return ret;
    }
    
    unpin_user_pages(&ctx);
    
    if (copy_to_user((void __user *)(unsigned long)pkt->user_buffer, kernel_buffer, pkt->size)) {
        pkt->status = STATUS_COPY_FAIL;
        ret = -14;
    } else {
        pkt->status = STATUS_SUCCESS;
        pkt->page_count = ctx.nr_pages;
    }
    
    kfree(kernel_buffer);
    put_process_mm(mm);
    return ret;
}

int handle_memory_write(struct k_packet *pkt)
{
    void *mm = NULL;
    struct task_struct *task = NULL;
    struct mem_op_context ctx;
    void *kernel_buffer = NULL;
    int ret = 0;
    
    if (pkt->size == 0 || pkt->size > MAX_TRANSFER_SIZE) {
        pkt->status = STATUS_INVALID_SIZE;
        return -22;
    }
    
    ret = get_process_mm(pkt->target_pid, &mm, &task);
    if (ret < 0) {
        pkt->status = STATUS_INVALID_PID;
        return ret;
    }
    
    ret = validate_user_address(mm, pkt->target_addr, pkt->size);
    if (ret < 0) {
        pkt->status = STATUS_INVALID_ADDR;
        put_process_mm(mm);
        return ret;
    }
    
    kernel_buffer = kmalloc(pkt->size, GFP_KERNEL);
    if (!kernel_buffer) {
        pkt->status = STATUS_MEM_ALLOC_FAIL;
        put_process_mm(mm);
        return -12;
    }
    
    if (copy_from_user(kernel_buffer, (void __user *)(unsigned long)pkt->user_buffer, pkt->size)) {
        pkt->status = STATUS_COPY_FAIL;
        kfree(kernel_buffer);
        put_process_mm(mm);
        return -14;
    }
    
    memset(&ctx, 0, sizeof(ctx));
    
    ret = pin_user_pages_for_transfer(mm, pkt->target_addr, pkt->size, 1, &ctx);
    if (ret < 0) {
        pkt->status = STATUS_PAGE_FAULT;
        kfree(kernel_buffer);
        put_process_mm(mm);
        return ret;
    }
    
    ret = copy_data_to_user_pages(&ctx, kernel_buffer, pkt->size);
    if (ret < 0) {
        pkt->status = STATUS_COPY_FAIL;
        unpin_user_pages(&ctx);
        kfree(kernel_buffer);
        put_process_mm(mm);
        return ret;
    }
    
    unpin_user_pages(&ctx);
    
    pkt->status = STATUS_SUCCESS;
    pkt->page_count = ctx.nr_pages;
    
    kfree(kernel_buffer);
    put_process_mm(mm);
    return ret;
}

/* Module Entry & Exit Hooks */
static long surajit_memory_init(const char *args, const char *event, void *__user reserved)
{
    kpm_info("========================================\n");
    kpm_info("SURAJIT MEMORY DEBUGGER INITIALIZED Successfully!\n");
    kpm_info("========================================\n");
    return 0;
}

static long surajit_memory_exit(void *__user reserved)
{
    kpm_info("SURAJIT MEMORY DEBUGGER UNLOADED Safely!\n");
    return 0;
}

/* Register APatch Framework Hooks */
KPM_INIT(surajit_memory_init);
KPM_EXIT(surajit_memory_exit);
