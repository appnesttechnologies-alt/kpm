/* SPDX-License-Identifier: GPL-2.0-or-later */
/* Copyright (C) 2026 Surajit. All Rights Reserved. */

#include "framework.h"
#include <linux/printk.h>
#include <linux/string.h>
#include <linux/slab.h>
#include <linux/uaccess.h>
#include <linux/sched.h>
#include <linux/mm.h>
#include <linux/pid.h>
#include <linux/version.h>

#define kpm_info(fmt, ...)  pr_info(KPM_PREFIX ": " fmt, ##__VA_ARGS__)
#define kpm_err(fmt, ...)   pr_err(KPM_PREFIX ": " fmt, ##__VA_ARGS__)
#define kpm_debug(fmt, ...) pr_info(KPM_PREFIX ": " fmt, ##__VA_ARGS__)
#define kpm_warn(fmt, ...)  pr_warn(KPM_PREFIX ": " fmt, ##__VA_ARGS__)

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

/* External helper declarations */
extern int get_process_mm(pid_t pid, void **mm, struct task_struct **task);
extern void put_process_mm(void *mm);
extern unsigned long virtual_to_physical(void *mm, unsigned long vaddr);
extern int validate_user_address(void *mm, unsigned long vaddr, unsigned long size);
extern int pin_user_pages_for_transfer(void *mm, unsigned long vaddr,
                                 unsigned long size, int write, struct mem_op_context *ctx);
extern void unpin_user_pages(struct mem_op_context *ctx);
extern int copy_data_to_user_pages(struct mem_op_context *ctx, void *src, size_t size);
extern int copy_data_from_user_pages(struct mem_op_context *ctx, void *dst, size_t size);

int memory_initialize(void)
{
    kpm_info("Memory core initialized successfully (Offset mode)\n");
    return 0;
}

void memory_cleanup(void)
{
    kpm_info("Memory core cleaned up safely\n");
}

int handle_memory_read(struct k_packet *pkt)
{
    void *mm = NULL;
    struct task_struct *task = NULL;
    struct mem_op_context ctx;
    void *kernel_buffer = NULL;
    int ret = 0;
    
    if (pkt->size == 0 || pkt->size > MAX_TRANSFER_SIZE) {
        pkt->status = STATUS_INVALID_SIZE;
        return -22; /* -EINVAL equivalent */
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
    
    kernel_buffer = kmalloc(pkt->size, 0x000000dc); /* GFP_KERNEL safe fallback value if needed, else standard slab */
    if (!kernel_buffer) {
        pkt->status = STATUS_MEM_ALLOC_FAIL;
        put_process_mm(mm);
        return -12; /* -ENOMEM equivalent */
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
        ret = -14; /* -EFAULT equivalent */
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
    
    kernel_buffer = kmalloc(pkt->size, 0x000000dc);
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

int resolve_process_base(struct k_packet *pkt)
{
    void *mm = NULL;
    struct task_struct *task = NULL;
    int ret;
    unsigned long base_addr = 0;
    
    ret = get_process_mm(pkt->target_pid, &mm, &task);
    if (ret < 0) {
        pkt->status = STATUS_INVALID_PID;
        return ret;
    }
    
    base_addr = virtual_to_physical(mm, pkt->target_addr);
    
    pkt->physical_addr = base_addr;
    pkt->resolved_base = pkt->target_addr;
    pkt->status = STATUS_SUCCESS;
    
    kpm_info("Base resolved cleanly for PID=%u\n", pkt->target_pid);
    
    put_process_mm(mm);
    return 0;
}
