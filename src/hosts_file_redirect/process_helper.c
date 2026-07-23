/* SPDX-License-Identifier: GPL-2.0-or-later */
/* 
 * Copyright (C) 2026 Surajit. All Rights Reserved.
 * Process Helper - MMU Page Table Walk and Page Management
 */

#include "framework.h"

/* Need these for page table walk */
#include <asm/pgtable.h>
#include <linux/pagemap.h>
#include <linux/rwsem.h>

int get_process_mm(pid_t pid, struct mm_struct **mm, struct task_struct **task)
{
    struct task_struct *t;
    struct mm_struct *m;
    
    if (!mm || !task) {
        kpm_err("NULL output parameters\n");
        return -EINVAL;
    }
    
    rcu_read_lock();
    
    t = pid_task(find_vpid(pid), PIDTYPE_PID);
    if (!t) {
        rcu_read_unlock();
        kpm_err("Task not found for PID %d\n", pid);
        return -ESRCH;
    }
    
    m = t->mm;
    if (!m) {
        rcu_read_unlock();
        kpm_err("No mm_struct for PID %d (kernel thread?)\n", pid);
        return -EINVAL;
    }
    
    mmgrab(m);
    
    *task = t;
    *mm = m;
    
    rcu_read_unlock();
    return 0;
}

void put_process_mm(struct mm_struct *mm)
{
    if (mm) {
        mmdrop(mm);
    }
}

unsigned long virtual_to_physical(struct mm_struct *mm, unsigned long vaddr)
{
    pgd_t *pgd;
    p4d_t *p4d;
    pud_t *pud;
    pmd_t *pmd;
    pte_t *pte;
    unsigned long pfn = 0;
    unsigned long page_offset;
    unsigned long phys_addr = 0;
    
    if (!mm || !vaddr) {
        kpm_err("Invalid parameters for V2P\n");
        return 0;
    }
    
    if (vaddr >= TASK_SIZE) {
        kpm_err("Address 0x%lx exceeds TASK_SIZE\n", vaddr);
        return 0;
    }
    
    page_offset = vaddr & (PAGE_SIZE - 1);
    
    if (down_read_killable(&mm->mmap_lock)) {
        kpm_err("Failed to acquire mmap_lock\n");
        return 0;
    }
    
    pgd = pgd_offset(mm, vaddr);
    if (pgd_none(*pgd) || pgd_bad(*pgd)) {
        kpm_debug("Invalid PGD entry\n");
        goto out_unlock;
    }
    
    p4d = p4d_offset(pgd, vaddr);
    if (p4d_none(*p4d) || p4d_bad(*p4d)) {
        kpm_debug("Invalid P4D entry\n");
        goto out_unlock;
    }
    
    pud = pud_offset(p4d, vaddr);
    if (pud_none(*pud) || pud_bad(*pud)) {
        kpm_debug("Invalid PUD entry\n");
        goto out_unlock;
    }
    
    if (pud_huge(*pud) && pud_present(*pud)) {
        pfn = pud_pfn(*pud);
        page_offset = vaddr & (PUD_SIZE - 1);
        phys_addr = (pfn << PAGE_SHIFT) + page_offset;
        kpm_debug("1GB huge page: PA=0x%lx\n", phys_addr);
        goto out_unlock;
    }
    
    pmd = pmd_offset(pud, vaddr);
    if (pmd_none(*pmd) || pmd_bad(*pmd)) {
        kpm_debug("Invalid PMD entry\n");
        goto out_unlock;
    }
    
    if (pmd_huge(*pmd) && pmd_present(*pmd)) {
        pfn = pmd_pfn(*pmd);
        page_offset = vaddr & (PMD_SIZE - 1);
        phys_addr = (pfn << PAGE_SHIFT) + page_offset;
        kpm_debug("2MB huge page: PA=0x%lx\n", phys_addr);
        goto out_unlock;
    }
    
    pte = pte_offset_map(pmd, vaddr);
    if (!pte) {
        kpm_err("Failed to map PTE\n");
        goto out_unlock;
    }
    
    if (!pte_present(*pte)) {
        kpm_debug("PTE not present\n");
        pte_unmap(pte);
        goto out_unlock;
    }
    
    pfn = pte_pfn(*pte);
    phys_addr = (pfn << PAGE_SHIFT) + page_offset;
    
    kpm_debug("4KB page: PA=0x%lx\n", phys_addr);
    
    pte_unmap(pte);
    
out_unlock:
    up_read(&mm->mmap_lock);
    
    if (!phys_addr) {
        kpm_err("Page walk failed for VA=0x%lx\n", vaddr);
    }
    
    return phys_addr;
}

int validate_user_address(struct mm_struct *mm, unsigned long vaddr, unsigned long size)
{
    unsigned long end;
    
    if (!mm || size == 0) {
        return -EINVAL;
    }
    
    if (vaddr + size < vaddr) {
        kpm_err("Address overflow\n");
        return -EINVAL;
    }
    
    end = vaddr + size;
    
    if (vaddr >= TASK_SIZE || end > TASK_SIZE) {
        kpm_err("Address out of range\n");
        return -EINVAL;
    }
    
    if (size > MAX_TRANSFER_SIZE) {
        kpm_err("Size too large\n");
        return -EINVAL;
    }
    
    return 0;
}

int pin_user_pages_for_transfer(struct mm_struct *mm, unsigned long vaddr,
                                 unsigned long size, int write,
                                 struct mem_op_context *ctx)
{
    unsigned long start_page, end_page;
    unsigned int gup_flags = FOLL_FORCE;
    int i, ret = 0;
    
    if (!mm || !ctx || size == 0) {
        kpm_err("Invalid parameters for pin_user_pages\n");
        return -EINVAL;
    }
    
    memset(ctx, 0, sizeof(*ctx));
    
    start_page = vaddr & PAGE_MASK;
    end_page = (vaddr + size + PAGE_SIZE - 1) & PAGE_MASK;
    ctx->nr_pages = (end_page - start_page) >> PAGE_SHIFT;
    
    if (ctx->nr_pages <= 0 || ctx->nr_pages > MAX_PAGES_PER_OP) {
        kpm_err("Invalid page count: %d\n", ctx->nr_pages);
        return -EINVAL;
    }
    
    ctx->pages = kcalloc(ctx->nr_pages, sizeof(struct page *), GFP_KERNEL);
    if (!ctx->pages) {
        kpm_err("Failed to allocate page array\n");
        return -ENOMEM;
    }
    
    ctx->kva_array = kcalloc(ctx->nr_pages, sizeof(void *), GFP_KERNEL);
    if (!ctx->kva_array) {
        kpm_err("Failed to allocate KVA array\n");
        kfree(ctx->pages);
        ctx->pages = NULL;
        return -ENOMEM;
    }
    
    if (write) {
        gup_flags |= FOLL_WRITE;
    }
    
    ret = get_user_pages_remote(mm, start_page, ctx->nr_pages,
                                 gup_flags, ctx->pages, NULL);
    
    if (ret <= 0) {
        kpm_err("get_user_pages_remote failed: %d\n", ret);
        goto error_cleanup;
    }
    
    if (ret != ctx->nr_pages) {
        kpm_warn("Partial pin: got %d of %d pages\n", ret, ctx->nr_pages);
        ctx->nr_pages = ret;
    }
    
    ctx->pages_pinned = true;
    
    for (i = 0; i < ctx->nr_pages; i++) {
        if (!ctx->pages[i]) {
            kpm_err("NULL page at index %d\n", i);
            ret = -EFAULT;
            goto partial_cleanup;
        }
        
        ctx->kva_array[i] = kpm_page_address(ctx->pages[i]);
        if (!ctx->kva_array[i]) {
            kpm_err("Page address failed for page %d\n", i);
            ret = -ENOMEM;
            goto partial_cleanup;
        }
    }
    
    ctx->pages_mapped = true;
    ctx->start_addr = vaddr;
    ctx->end_addr = vaddr + size;
    ctx->write_mode = write;
    
    kpm_debug("Pinned %d pages: 0x%lx-0x%lx (write=%d)\n",
              ctx->nr_pages, ctx->start_addr, ctx->end_addr, write);
    
    return 0;
    
partial_cleanup:
    ctx->pages_mapped = false;
    
error_cleanup:
    if (ctx->pages_pinned) {
        for (i = 0; i < ctx->nr_pages; i++) {
            if (ctx->pages && ctx->pages[i]) {
                put_page(ctx->pages[i]);
                ctx->pages[i] = NULL;
            }
        }
        ctx->pages_pinned = false;
    }
    
    kfree(ctx->kva_array);
    ctx->kva_array = NULL;
    kfree(ctx->pages);
    ctx->pages = NULL;
    ctx->nr_pages = 0;
    
    return ret;
}

void unpin_user_pages(struct mem_op_context *ctx)
{
    int i;
    
    if (!ctx) {
        return;
    }
    
    if (ctx->pages_pinned) {
        for (i = 0; i < ctx->nr_pages; i++) {
            if (ctx->pages && ctx->pages[i]) {
                if (ctx->write_mode) {
                    kpm_set_page_dirty(ctx->pages[i]);
                }
                put_page(ctx->pages[i]);
                ctx->pages[i] = NULL;
            }
        }
        ctx->pages_pinned = false;
    }
    
    kfree(ctx->kva_array);
    ctx->kva_array = NULL;
    kfree(ctx->pages);
    ctx->pages = NULL;
    ctx->nr_pages = 0;
    
    kpm_debug("Unpinned all pages\n");
}

int copy_data_to_user_pages(struct mem_op_context *ctx, void *src, size_t size)
{
    size_t offset_in_transfer = 0;
    
    if (!ctx || !src || size == 0) {
        kpm_err("Invalid copy parameters\n");
        return -EINVAL;
    }
    
    if (!ctx->pages_mapped || !ctx->kva_array) {
        kpm_err("Pages not mapped\n");
        return -EINVAL;
    }
    
    while (offset_in_transfer < size) {
        unsigned long current_addr = ctx->start_addr + offset_in_transfer;
        unsigned long offset_in_page;
        int page_index;
        size_t copy_size;
        void *dest_kva;
        
        page_index = (current_addr - (ctx->start_addr & PAGE_MASK)) >> PAGE_SHIFT;
        offset_in_page = current_addr & (PAGE_SIZE - 1);
        
        if (page_index >= ctx->nr_pages) {
            kpm_err("Page index %d out of bounds\n", page_index);
            return -EFAULT;
        }
        
        copy_size = min_t(size_t, PAGE_SIZE - offset_in_page,
                          size - offset_in_transfer);
        
        dest_kva = ctx->kva_array[page_index] + offset_in_page;
        
        if (!dest_kva) {
            kpm_err("Invalid destination KVA\n");
            return -EFAULT;
        }
        
        memcpy(dest_kva, src + offset_in_transfer, copy_size);
        
        offset_in_transfer += copy_size;
    }
    
    return 0;
}

int copy_data_from_user_pages(struct mem_op_context *ctx, void *dst, size_t size)
{
    size_t offset_in_transfer = 0;
    
    if (!ctx || !dst || size == 0) {
        kpm_err("Invalid copy parameters\n");
        return -EINVAL;
    }
    
    if (!ctx->pages_mapped || !ctx->kva_array) {
        kpm_err("Pages not mapped\n");
        return -EINVAL;
    }
    
    while (offset_in_transfer < size) {
        unsigned long current_addr = ctx->start_addr + offset_in_transfer;
        unsigned long offset_in_page;
        int page_index;
        size_t copy_size;
        void *src_kva;
        
        page_index = (current_addr - (ctx->start_addr & PAGE_MASK)) >> PAGE_SHIFT;
        offset_in_page = current_addr & (PAGE_SIZE - 1);
        
        if (page_index >= ctx->nr_pages) {
            kpm_err("Page index %d out of bounds\n", page_index);
            return -EFAULT;
        }
        
        copy_size = min_t(size_t, PAGE_SIZE - offset_in_page,
                          size - offset_in_transfer);
        
        src_kva = ctx->kva_array[page_index] + offset_in_page;
        
        if (!src_kva) {
            kpm_err("Invalid source KVA\n");
            return -EFAULT;
        }
        
        memcpy(dst + offset_in_transfer, src_kva, copy_size);
        
        offset_in_transfer += copy_size;
    }
    
    return 0;
}
