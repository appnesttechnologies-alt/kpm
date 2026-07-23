/* SPDX-License-Identifier: GPL-2.0-or-later */
/* 
 * Copyright (C) 2026 Surajit. All Rights Reserved.
 * 
 * Core Memory Operations - Read/Write/Resolve Handlers
 * Implements page-split aware, panic-safe memory access
 */

#include "framework.h"

/**
 * memory_initialize - Initialize memory core subsystem
 * 
 * Prepares any global state needed for memory operations.
 * Currently performs validation checks.
 * 
 * Returns: 0 on success
 */
int memory_initialize(void)
{
    kpm_info("Memory core subsystem initialized\n");
    kpm_debug("Page size: %lu bytes, Max pages: %d\n", 
              PAGE_SIZE, MAX_PAGES_PER_OP);
    return 0;
}

/**
 * memory_cleanup - Cleanup memory core subsystem
 * 
 * Ensures no lingering allocations or locks.
 */
void memory_cleanup(void)
{
    kpm_info("Memory core subsystem cleaned up\n");
}

/**
 * handle_memory_read - Robust read from target process memory
 * @pkt: Operation packet with target details
 * 
 * Implementation strategy:
 * 1. Validate all parameters
 * 2. Acquire target process MM
 * 3. Pin user pages (read-only)
 * 4. Copy data page-by-page to kernel buffer
 * 5. Copy kernel buffer to userspace
 * 6. Clean up all resources
 * 
 * Handles page splits automatically via pin_user_pages.
 * 
 * Returns: 0 on success, negative error on failure
 */
int handle_memory_read(struct k_packet *pkt)
{
    struct mm_struct *mm = NULL;
    struct task_struct *task = NULL;
    struct mem_op_context ctx;
    void *kernel_buffer = NULL;
    int ret = 0;
    unsigned long read_addr, read_size;
    
    read_addr = pkt->target_addr;
    read_size = pkt->size;
    
    kpm_debug("Read: PID=%u ADDR=0x%llX SIZE=%lu\n", 
              pkt->target_pid, read_addr, read_size);
    
    /* Step 1: Parameter validation */
    if (read_size == 0 || read_size > MAX_TRANSFER_SIZE) {
        kpm_err("Invalid read size: %lu\n", read_size);
        pkt->status = STATUS_INVALID_SIZE;
        return -EINVAL;
    }
    
    /* Step 2: Acquire target process */
    ret = get_process_mm(pkt->target_pid, &mm, &task);
    if (ret < 0) {
        kpm_err("Cannot get process MM for PID %u\n", pkt->target_pid);
        pkt->status = STATUS_INVALID_PID;
        return ret;
    }
    
    /* Step 3: Validate address range */
    ret = validate_user_address(mm, read_addr, read_size);
    if (ret < 0) {
        kpm_err("Address range invalid: 0x%llX-0x%llX\n",
                read_addr, read_addr + read_size);
        pkt->status = STATUS_INVALID_ADDR;
        put_process_mm(mm);
        return ret;
    }
    
    /* Step 4: Allocate temporary kernel buffer */
    kernel_buffer = kmalloc(read_size, GFP_KERNEL);
    if (!kernel_buffer) {
        kpm_err("Cannot allocate kernel buffer of %lu bytes\n", read_size);
        pkt->status = STATUS_MEM_ALLOC_FAIL;
        put_process_mm(mm);
        return -ENOMEM;
    }
    
    /* Step 5: Initialize operation context */
    memset(&ctx, 0, sizeof(ctx));
    
    /* Step 6: Pin user pages for DMA-style access */
    ret = pin_user_pages_for_transfer(mm, read_addr, read_size, 0, &ctx);
    if (ret < 0) {
        kpm_err("Failed to pin user pages: %d\n", ret);
        pkt->status = STATUS_PAGE_FAULT;
        goto cleanup;
    }
    
    /* Step 7: Copy data from pinned pages */
    ret = copy_data_from_user_pages(&ctx, kernel_buffer, read_size);
    if (ret < 0) {
        kpm_err("Failed to copy from pinned pages: %d\n", ret);
        pkt->status = STATUS_COPY_FAIL;
        unpin_user_pages(&ctx);
        goto cleanup;
    }
    
    /* Step 8: Release page pins */
    unpin_user_pages(&ctx);
    
    /* Step 9: Copy to userspace */
    if (copy_to_user((void __user *)pkt->user_buffer, kernel_buffer, read_size)) {
        kpm_err("copy_to_user failed\n");
        pkt->status = STATUS_COPY_FAIL;
        ret = -EFAULT;
        goto cleanup;
    }
    
    pkt->status = STATUS_SUCCESS;
    pkt->page_count = ctx.nr_pages;
    
    kpm_debug("Read successful: %lu bytes, %d pages\n", read_size, ctx.nr_pages);
    
cleanup:
    if (kernel_buffer) {
        kzfree(kernel_buffer);
    }
    put_process_mm(mm);
    return ret;
}

/**
 * handle_memory_write - Robust write to target process memory
 * @pkt: Operation packet with target details
 * 
 * Implementation strategy:
 * 1. Validate all parameters
 * 2. Acquire target process MM
 * 3. Copy data from userspace to kernel buffer
 * 4. Pin user pages (with write access)
 * 5. Copy data page-by-page to pinned pages
 * 6. Mark pages dirty for writeback
 * 7. Clean up all resources
 * 
 * Returns: 0 on success, negative error on failure
 */
int handle_memory_write(struct k_packet *pkt)
{
    struct mm_struct *mm = NULL;
    struct task_struct *task = NULL;
    struct mem_op_context ctx;
    void *kernel_buffer = NULL;
    int ret = 0;
    unsigned long write_addr, write_size;
    
    write_addr = pkt->target_addr;
    write_size = pkt->size;
    
    kpm_debug("Write: PID=%u ADDR=0x%llX SIZE=%lu\n", 
              pkt->target_pid, write_addr, write_size);
    
    /* Step 1: Parameter validation */
    if (write_size == 0 || write_size > MAX_TRANSFER_SIZE) {
        kpm_err("Invalid write size: %lu\n", write_size);
        pkt->status = STATUS_INVALID_SIZE;
        return -EINVAL;
    }
    
    /* Step 2: Acquire target process */
    ret = get_process_mm(pkt->target_pid, &mm, &task);
    if (ret < 0) {
        kpm_err("Cannot get process MM for PID %u\n", pkt->target_pid);
        pkt->status = STATUS_INVALID_PID;
        return ret;
    }
    
    /* Step 3: Validate address range */
    ret = validate_user_address(mm, write_addr, write_size);
    if (ret < 0) {
        kpm_err("Address range invalid: 0x%llX-0x%llX\n",
                write_addr, write_addr + write_size);
        pkt->status = STATUS_INVALID_ADDR;
        put_process_mm(mm);
        return ret;
    }
    
    /* Step 4: Allocate and copy from userspace */
    kernel_buffer = kmalloc(write_size, GFP_KERNEL);
    if (!kernel_buffer) {
        kpm_err("Cannot allocate kernel buffer of %lu bytes\n", write_size);
        pkt->status = STATUS_MEM_ALLOC_FAIL;
        put_process_mm(mm);
        return -ENOMEM;
    }
    
    if (copy_from_user(kernel_buffer, (void __user *)pkt->user_buffer, write_size)) {
        kpm_err("copy_from_user failed\n");
        pkt->status = STATUS_COPY_FAIL;
        ret = -EFAULT;
        goto cleanup;
    }
    
    /* Step 5: Initialize operation context */
    memset(&ctx, 0, sizeof(ctx));
    
    /* Step 6: Pin user pages with write access */
    ret = pin_user_pages_for_transfer(mm, write_addr, write_size, 1, &ctx);
    if (ret < 0) {
        kpm_err("Failed to pin user pages for write: %d\n", ret);
        pkt->status = STATUS_PAGE_FAULT;
        goto cleanup;
    }
    
    /* Step 7: Copy data to pinned pages */
    ret = copy_data_to_user_pages(&ctx, kernel_buffer, write_size);
    if (ret < 0) {
        kpm_err("Failed to copy to pinned pages: %d\n", ret);
        pkt->status = STATUS_COPY_FAIL;
        unpin_user_pages(&ctx);
        goto cleanup;
    }
    
    /* Step 8: Release page pins (marks dirty for writeback) */
    unpin_user_pages(&ctx);
    
    pkt->status = STATUS_SUCCESS;
    pkt->page_count = ctx.nr_pages;
    
    kpm_debug("Write successful: %lu bytes, %d pages\n", write_size, ctx.nr_pages);
    
cleanup:
    if (kernel_buffer) {
        kzfree(kernel_buffer);
    }
    put_process_mm(mm);
    return ret;
}

/**
 * resolve_process_base - Resolve executable base of target process
 * @pkt: Operation packet
 * 
 * Uses VMA traversal to find the first executable mapping.
 * Falls back to mm->start_code if no executable VMA found.
 * Also resolves physical address via page table walk.
 * 
 * Returns: 0 on success, negative error on failure
 */
int resolve_process_base(struct k_packet *pkt)
{
    struct mm_struct *mm = NULL;
    struct task_struct *task = NULL;
    struct vm_area_struct *vma;
    int ret;
    unsigned long base_addr = 0;
    
    kpm_debug("Resolving base for PID %u\n", pkt->target_pid);
    
    /* Acquire target process */
    ret = get_process_mm(pkt->target_pid, &mm, &task);
    if (ret < 0) {
        kpm_err("Cannot get process MM for PID %u\n", pkt->target_pid);
        pkt->status = STATUS_INVALID_PID;
        return ret;
    }
    
    /* Lock MM for VMA traversal */
    if (down_read_killable(&mm->mmap_lock)) {
        kpm_err("Cannot acquire mmap_lock\n");
        pkt->status = STATUS_MMAP_LOCK_FAIL;
        put_process_mm(mm);
        return -EINTR;
    }
    
    /* Traverse VMA tree for executable mapping */
    for (vma = mm->mmap; vma; vma = vma->vm_next) {
        if (vma->vm_flags & VM_EXEC) {
            base_addr = vma->vm_start;
            kpm_debug("Found executable VMA: 0x%lx-0x%lx\n",
                      vma->vm_start, vma->vm_end);
            break;
        }
    }
    
    /* Fallback strategies */
    if (!base_addr && mm->start_code) {
        base_addr = mm->start_code;
        kpm_debug("Using start_code: 0x%lx\n", base_addr);
    }
    
    if (!base_addr && mm->mmap) {
        base_addr = mm->mmap->vm_start;
        kpm_debug("Using first VMA: 0x%lx\n", base_addr);
    }
    
    up_read(&mm->mmap_lock);
    
    if (!base_addr) {
        kpm_err("Could not resolve base address\n");
        pkt->status = STATUS_INVALID_ADDR;
        put_process_mm(mm);
        return -EINVAL;
    }
    
    /* Resolve physical address */
    pkt->physical_addr = virtual_to_physical(mm, base_addr);
    pkt->resolved_base = base_addr;
    pkt->status = STATUS_SUCCESS;
    
    kpm_info("Resolved: PID=%u Base=0x%llX Physical=0x%llX\n",
             pkt->target_pid, pkt->resolved_base, pkt->physical_addr);
    
    put_process_mm(mm);
    return 0;
}