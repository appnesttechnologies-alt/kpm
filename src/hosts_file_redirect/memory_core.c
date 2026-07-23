/* SPDX-License-Identifier: GPL-2.0-or-later */
/* 
 * Copyright (C) 2026 Surajit. All Rights Reserved.
 * 
 * Core Memory Operations
 */

#include "framework.h"

int memory_initialize(void)
{
    kpm_info("Memory core subsystem initialized\n");
    return 0;
}

void memory_cleanup(void)
{
    kpm_info("Memory core subsystem cleaned up\n");
}

int handle_memory_read(struct k_packet *pkt)
{
    struct mm_struct *mm = NULL;
    struct task_struct *task = NULL;
    struct mem_op_context ctx;
    void *kernel_buffer = NULL;
    int ret = 0;
    
    kpm_debug("Read: PID=%u ADDR=0x%llX SIZE=%u\n", 
              pkt->target_pid, pkt->target_addr, pkt->size);
    
    if (pkt->size == 0 || pkt->size > MAX_TRANSFER_SIZE) {
        kpm_err("Invalid read size: %u\n", pkt->size);
        pkt->status = STATUS_INVALID_SIZE;
        return -EINVAL;
    }
    
    ret = get_process_mm(pkt->target_pid, &mm, &task);
    if (ret < 0) {
        kpm_err("Cannot get process MM for PID %u\n", pkt->target_pid);
        pkt->status = STATUS_INVALID_PID;
        return ret;
    }
    
    ret = validate_user_address(mm, pkt->target_addr, pkt->size);
    if (ret < 0) {
        kpm_err("Address range invalid\n");
        pkt->status = STATUS_INVALID_ADDR;
        put_process_mm(mm);
        return ret;
    }
    
    kernel_buffer = kmalloc(pkt->size, GFP_KERNEL);
    if (!kernel_buffer) {
        kpm_err("Cannot allocate kernel buffer\n");
        pkt->status = STATUS_MEM_ALLOC_FAIL;
        put_process_mm(mm);
        return -ENOMEM;
    }
    
    memset(&ctx, 0, sizeof(ctx));
    
    ret = pin_user_pages_for_transfer(mm, pkt->target_addr, pkt->size, 0, &ctx);
    if (ret < 0) {
        kpm_err("Failed to pin user pages: %d\n", ret);
        pkt->status = STATUS_PAGE_FAULT;
        goto cleanup;
    }
    
    ret = copy_data_from_user_pages(&ctx, kernel_buffer, pkt->size);
    if (ret < 0) {
        kpm_err("Failed to copy from pages: %d\n", ret);
        pkt->status = STATUS_COPY_FAIL;
        unpin_user_pages(&ctx);
        goto cleanup;
    }
    
    unpin_user_pages(&ctx);
    
    if (copy_to_user((void __user *)pkt->user_buffer, kernel_buffer, pkt->size)) {
        kpm_err("copy_to_user failed\n");
        pkt->status = STATUS_COPY_FAIL;
        ret = -EFAULT;
        goto cleanup;
    }
    
    pkt->status = STATUS_SUCCESS;
    pkt->page_count = ctx.nr_pages;
    
    kpm_debug("Read successful: %u bytes\n", pkt->size);
    
cleanup:
    if (kernel_buffer) {
        kfree(kernel_buffer);
    }
    put_process_mm(mm);
    return ret;
}

int handle_memory_write(struct k_packet *pkt)
{
    struct mm_struct *mm = NULL;
    struct task_struct *task = NULL;
    struct mem_op_context ctx;
    void *kernel_buffer = NULL;
    int ret = 0;
    
    kpm_debug("Write: PID=%u ADDR=0x%llX SIZE=%u\n", 
              pkt->target_pid, pkt->target_addr, pkt->size);
    
    if (pkt->size == 0 || pkt->size > MAX_TRANSFER_SIZE) {
        kpm_err("Invalid write size: %u\n", pkt->size);
        pkt->status = STATUS_INVALID_SIZE;
        return -EINVAL;
    }
    
    ret = get_process_mm(pkt->target_pid, &mm, &task);
    if (ret < 0) {
        kpm_err("Cannot get process MM for PID %u\n", pkt->target_pid);
        pkt->status = STATUS_INVALID_PID;
        return ret;
    }
    
    ret = validate_user_address(mm, pkt->target_addr, pkt->size);
    if (ret < 0) {
        kpm_err("Address range invalid\n");
        pkt->status = STATUS_INVALID_ADDR;
        put_process_mm(mm);
        return ret;
    }
    
    kernel_buffer = kmalloc(pkt->size, GFP_KERNEL);
    if (!kernel_buffer) {
        kpm_err("Cannot allocate kernel buffer\n");
        pkt->status = STATUS_MEM_ALLOC_FAIL;
        put_process_mm(mm);
        return -ENOMEM;
    }
    
    if (copy_from_user(kernel_buffer, (void __user *)pkt->user_buffer, pkt->size)) {
        kpm_err("copy_from_user failed\n");
        pkt->status = STATUS_COPY_FAIL;
        ret = -EFAULT;
        goto cleanup;
    }
    
    memset(&ctx, 0, sizeof(ctx));
    
    ret = pin_user_pages_for_transfer(mm, pkt->target_addr, pkt->size, 1, &ctx);
    if (ret < 0) {
        kpm_err("Failed to pin user pages: %d\n", ret);
        pkt->status = STATUS_PAGE_FAULT;
        goto cleanup;
    }
    
    ret = copy_data_to_user_pages(&ctx, kernel_buffer, pkt->size);
    if (ret < 0) {
        kpm_err("Failed to copy to pages: %d\n", ret);
        pkt->status = STATUS_COPY_FAIL;
        unpin_user_pages(&ctx);
        goto cleanup;
    }
    
    unpin_user_pages(&ctx);
    
    pkt->status = STATUS_SUCCESS;
    pkt->page_count = ctx.nr_pages;
    
    kpm_debug("Write successful: %u bytes\n", pkt->size);
    
cleanup:
    if (kernel_buffer) {
        kfree(kernel_buffer);
    }
    put_process_mm(mm);
    return ret;
}

int resolve_process_base(struct k_packet *pkt)
{
    struct mm_struct *mm = NULL;
    struct task_struct *task = NULL;
    struct vm_area_struct *vma;
    int ret;
    unsigned long base_addr = 0;
    
    kpm_debug("Resolving base for PID %u\n", pkt->target_pid);
    
    ret = get_process_mm(pkt->target_pid, &mm, &task);
    if (ret < 0) {
        kpm_err("Cannot get process MM for PID %u\n", pkt->target_pid);
        pkt->status = STATUS_INVALID_PID;
        return ret;
    }
    
    if (down_read_killable(&mm->mmap_lock)) {
        kpm_err("Cannot acquire mmap_lock\n");
        pkt->status = STATUS_MMAP_LOCK_FAIL;
        put_process_mm(mm);
        return -EINTR;
    }
    
    for (vma = mm->mmap; vma; vma = vma->vm_next) {
        if (vma->vm_flags & VM_EXEC) {
            base_addr = vma->vm_start;
            break;
        }
    }
    
    if (!base_addr && mm->start_code) {
        base_addr = mm->start_code;
    }
    
    if (!base_addr && mm->mmap) {
        base_addr = mm->mmap->vm_start;
    }
    
    up_read(&mm->mmap_lock);
    
    if (!base_addr) {
        kpm_err("Could not resolve base address\n");
        pkt->status = STATUS_INVALID_ADDR;
        put_process_mm(mm);
        return -EINVAL;
    }
    
    pkt->physical_addr = virtual_to_physical(mm, base_addr);
    pkt->resolved_base = base_addr;
    pkt->status = STATUS_SUCCESS;
    
    kpm_info("Resolved: PID=%u Base=0x%llX Physical=0x%llX\n",
             pkt->target_pid, pkt->resolved_base, pkt->physical_addr);
    
    put_process_mm(mm);
    return 0;
}
