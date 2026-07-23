/* SPDX-License-Identifier: GPL-2.0-or-later */
/* Copyright (C) 2026 Surajit. All Rights Reserved. */

#include "framework.h"
#include <linux/printk.h>
#include <linux/string.h>
#include <linux/slab.h>
#include <linux/sched.h>
#include <linux/mm.h>
#include <linux/pid.h>
#include <linux/pagemap.h>

/* pgtable functions are available through linux/mm.h in APatch SDK */

#define kpm_info(fmt, ...)  pr_info(KPM_PREFIX ": " fmt, ##__VA_ARGS__)
#define kpm_err(fmt, ...)   pr_err(KPM_PREFIX ": " fmt, ##__VA_ARGS__)
#define kpm_debug(fmt, ...) pr_info(KPM_PREFIX ": " fmt, ##__VA_ARGS__)
#define kpm_warn(fmt, ...)  pr_warn(KPM_PREFIX ": " fmt, ##__VA_ARGS__)

/* Internal context structure */
struct mem_op_context {
    struct mm_struct *target_mm;
    struct page **pages;
    void **kva_array;
    unsigned long start_addr;
    unsigned long end_addr;
    int nr_pages;
    int write_mode;
};

int get_process_mm(pid_t pid, struct mm_struct **mm, struct task_struct **task)
{
    struct task_struct *t;
    struct mm_struct *m;
    
    if (!mm || !task)
        return -EINVAL;
    
    rcu_read_lock();
    
    t = pid_task(find_vpid(pid), PIDTYPE_PID);
    if (!t) {
        rcu_read_unlock();
        return -ESRCH;
    }
    
    m = t->mm;
    if (!m) {
        rcu_read_unlock();
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
    if (mm)
        mmdrop(mm);
}

unsigned long virtual_to_physical(struct mm_struct *mm, unsigned long vaddr)
{
    pgd_t *pgd;
    p4d_t *p4d;
    pud_t *pud;
    pmd_t *pmd;
    pte_t *pte;
    unsigned long pfn = 0;
    unsigned long phys_addr = 0;
    unsigned long page_offset;
    
    if (!mm || !vaddr || vaddr >= TASK_SIZE)
        return 0;
    
    page_offset = vaddr & (PAGE_SIZE - 1);
    
    if (down_read_killable(&mm->mmap_lock))
        return 0;
    
    pgd = pgd_offset(mm, vaddr);
    if (pgd_none(*pgd) || pgd_bad(*pgd))
        goto out;
    
    p4d = p4d_offset(pgd, vaddr);
    if (p4d_none(*p4d) || p4d_bad(*p4d))
        goto out;
    
    pud = pud_offset(p4d, vaddr);
    if (pud_none(*pud) || pud_bad(*pud))
        goto out;
    
    if (pud_huge(*pud) && pud_present(*pud)) {
        pfn = pud_pfn(*pud);
        phys_addr = (pfn << PAGE_SHIFT) + (vaddr & (PUD_SIZE - 1));
        goto out;
    }
    
    pmd = pmd_offset(pud, vaddr);
    if (pmd_none(*pmd) || pmd_bad(*pmd))
        goto out;
    
    if (pmd_huge(*pmd) && pmd_present(*pmd)) {
        pfn = pmd_pfn(*pmd);
        phys_addr = (pfn << PAGE_SHIFT) + (vaddr & (PMD_SIZE - 1));
        goto out;
    }
    
    pte = pte_offset_map(pmd, vaddr);
    if (!pte)
        goto out;
    
    if (!pte_present(*pte)) {
        pte_unmap(pte);
        goto out;
    }
    
    pfn = pte_pfn(*pte);
    phys_addr = (pfn << PAGE_SHIFT) + page_offset;
    pte_unmap(pte);
    
out:
    up_read(&mm->mmap_lock);
    return phys_addr;
}

int validate_user_address(struct mm_struct *mm, unsigned long vaddr, unsigned long size)
{
    unsigned long end = vaddr + size;
    
    if (!mm || size == 0)
        return -EINVAL;
    if (end < vaddr)
        return -EINVAL;
    if (vaddr >= TASK_SIZE || end > TASK_SIZE)
        return -EINVAL;
    if (size > MAX_TRANSFER_SIZE)
        return -EINVAL;
    
    return 0;
}

int pin_user_pages_for_transfer(struct mm_struct *mm, unsigned long vaddr,
                                 unsigned long size, int write,
                                 struct mem_op_context *ctx)
{
    unsigned long start_page, end_page;
    unsigned int gup_flags = FOLL_FORCE;
    int i, ret;
    
    if (!mm || !ctx || size == 0)
        return -EINVAL;
    
    memset(ctx, 0, sizeof(*ctx));
    
    start_page = vaddr & PAGE_MASK;
    end_page = (vaddr + size + PAGE_SIZE - 1) & PAGE_MASK;
    ctx->nr_pages = (end_page - start_page) >> PAGE_SHIFT;
    
    if (ctx->nr_pages <= 0 || ctx->nr_pages > MAX_PAGES_PER_OP)
        return -EINVAL;
    
    ctx->pages = kmalloc_array(ctx->nr_pages, sizeof(struct page *), GFP_KERNEL);
    if (!ctx->pages)
        return -ENOMEM;
    
    ctx->kva_array = kmalloc_array(ctx->nr_pages, sizeof(void *), GFP_KERNEL);
    if (!ctx->kva_array) {
        kfree(ctx->pages);
        return -ENOMEM;
    }
    
    if (write)
        gup_flags |= FOLL_WRITE;
    
    ret = get_user_pages_remote(mm, start_page, ctx->nr_pages,
                                 gup_flags, ctx->pages, NULL);
    
    if (ret <= 0) {
        kfree(ctx->kva_array);
        kfree(ctx->pages);
        return -EFAULT;
    }
    
    ctx->nr_pages = ret;
    
    for (i = 0; i < ctx->nr_pages; i++) {
        ctx->kva_array[i] = page_address(ctx->pages[i]);
        if (!ctx->kva_array[i]) {
            for (i--; i >= 0; i--)
                put_page(ctx->pages[i]);
            kfree(ctx->kva_array);
            kfree(ctx->pages);
            return -ENOMEM;
        }
    }
    
    ctx->start_addr = vaddr;
    ctx->end_addr = vaddr + size;
    ctx->write_mode = write;
    
    return 0;
}

void unpin_user_pages(struct mem_op_context *ctx)
{
    int i;
    
    if (!ctx)
        return;
    
    for (i = 0; i < ctx->nr_pages; i++) {
        if (ctx->write_mode)
            set_page_dirty_lock(ctx->pages[i]);
        put_page(ctx->pages[i]);
    }
    
    kfree(ctx->kva_array);
    kfree(ctx->pages);
    memset(ctx, 0, sizeof(*ctx));
}

int copy_data_to_user_pages(struct mem_op_context *ctx, void *src, size_t size)
{
    size_t copied = 0;
    
    if (!ctx || !src || size == 0)
        return -EINVAL;
    
    while (copied < size) {
        unsigned long addr = ctx->start_addr + copied;
        int page_idx = (addr - (ctx->start_addr & PAGE_MASK)) >> PAGE_SHIFT;
        unsigned long offset = addr & (PAGE_SIZE - 1);
        size_t chunk = PAGE_SIZE - offset;
        void *dest;
        
        if (size - copied < chunk)
            chunk = size - copied;
        
        if (page_idx >= ctx->nr_pages)
            return -EFAULT;
        
        dest = ctx->kva_array[page_idx] + offset;
        memcpy(dest, src + copied, chunk);
        copied += chunk;
    }
    
    return 0;
}

int copy_data_from_user_pages(struct mem_op_context *ctx, void *dst, size_t size)
{
    size_t copied = 0;
    
    if (!ctx || !dst || size == 0)
        return -EINVAL;
    
    while (copied < size) {
        unsigned long addr = ctx->start_addr + copied;
        int page_idx = (addr - (ctx->start_addr & PAGE_MASK)) >> PAGE_SHIFT;
        unsigned long offset = addr & (PAGE_SIZE - 1);
        size_t chunk = PAGE_SIZE - offset;
        void *src;
        
        if (size - copied < chunk)
            chunk = size - copied;
        
        if (page_idx >= ctx->nr_pages)
            return -EFAULT;
        
        src = ctx->kva_array[page_idx] + offset;
        memcpy(dst + copied, src, chunk);
        copied += chunk;
    }
    
    return 0;
}
