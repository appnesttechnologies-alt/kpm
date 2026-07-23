/* SPDX-License-Identifier: GPL-2.0-or-later */
/* 
 * Copyright (C) 2026 Surajit. All Rights Reserved.
 * 
 * Process Helper - MMU Page Table Walk and Page Management
 * Implements ARM64 4-level translation and safe page pinning
 */

#include "framework.h"

/**
 * get_process_mm - Safely acquire task and mm_struct for target PID
 * @pid: Target process identifier
 * @mm: Output parameter for mm_struct
 * @task: Output parameter for task_struct
 * 
 * Thread-safe acquisition using RCU and reference counting.
 * Caller must call put_process_mm() to release.
 * 
 * Returns: 0 on success, -ESRCH if not found, -EINVAL for kernel threads
 */
int get_process_mm(pid_t pid, struct mm_struct **mm, struct task_struct **task)
{
    struct task_struct *t;
    struct mm_struct *m;
    
    if (!mm || !task) {
        kpm_err("NULL output parameters\n");
        return -EINVAL;
    }
    
    rcu_read_lock();
    
    /* Find task by PID */
    t = pid_task(find_vpid(pid), PIDTYPE_PID);
    if (!t) {
        rcu_read_unlock();
        kpm_err("Task not found for PID %d\n", pid);
        return -ESRCH;
    }
    
    /* Get mm_struct */
    m = t->mm;
    if (!m) {
        rcu_read_unlock();
        kpm_err("No mm_struct for PID %d (kernel thread?)\n", pid);
        return -EINVAL;
    }
    
    /* Atomic increment to prevent premature deallocation */
    mmgrab(m);
    
    *task = t;
    *mm = m;
    
    rcu_read_unlock();
    return 0;
}

/**
 * put_process_mm - Release mm_struct reference
 * @mm: mm_struct to release
 * 
 * Decrements reference count safely.
 */
void put_process_mm(struct mm_struct *mm)
{
    if (mm) {
        mmdrop(mm);
    }
}

/**
 * virtual_to_physical - ARM64 4-level page table walk
 * @mm: Target process memory descriptor
 * @vaddr: User virtual address to translate
 * 
 * Implements complete ARM64 translation:
 * 
 * Virtual Address (48-bit):
 * | 47:39 | 38:30 | 29:21 | 20:12 | 11:0 |
 * |  PGD  |  PUD  |  PMD  |  PTE  | OFF  |
 * 
 * 1. PGD (Level 0): 9 bits, 512 entries, 512GB each
 * 2. PUD (Level 1): 9 bits, 512 entries, 1GB each
 * 3. PMD (Level 2): 9 bits, 512 entries, 2MB each
 * 4. PTE (Level 3): 9 bits, 512 entries, 4KB each
 * 
 * Supports huge pages at PUD (1GB) and PMD (2MB) levels.
 * 
 * Thread safety: Holds mmap_lock in read mode during walk.
 * 
 * Returns: Physical address (with page offset), or 0 on failure
 */
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
    
    /* Parameter validation */
    if (!mm) {
        kpm_err("NULL mm_struct\n");
        return 0;
    }
    
    if (!vaddr) {
        kpm_err("NULL virtual address\n");
        return 0;
    }
    
    /* Bounds check - user addresses must be below TASK_SIZE */
    if (vaddr >= TASK_SIZE) {
        kpm_err("Address 0x%lx exceeds TASK_SIZE (0x%lx)\n", vaddr, TASK_SIZE);
        return 0;
    }
    
    /* Page offset within 4KB page */
    page_offset = vaddr & (PAGE_SIZE - 1);
    
    /* Acquire mmap_lock for safe page table walk */
    if (down_read_killable(&mm->mmap_lock)) {
        kpm_err("Failed to acquire mmap_lock (killed)\n");
        return 0;
    }
    
    /* Level 0: Page Global Directory */
    pgd = pgd_offset(mm, vaddr);
    if (pgd_none(*pgd) || pgd_bad(*pgd)) {
        kpm_debug("Invalid PGD entry for 0x%lx\n", vaddr);
        goto out_unlock;
    }
    
    /* Level 1: Page 4th-level Directory */
    p4d = p4d_offset(pgd, vaddr);
    if (p4d_none(*p4d) || p4d_bad(*p4d)) {
        kpm_debug("Invalid P4D entry for 0x%lx\n", vaddr);
        goto out_unlock;
    }
    
    /* Level 2: Page Upper Directory */
    pud = pud_offset(p4d, vaddr);
    if (pud_none(*pud) || pud_bad(*pud)) {
        kpm_debug("Invalid PUD entry for 0x%lx\n", vaddr);
        goto out_unlock;
    }
    
    /* Check for 1GB huge page at PUD level */
    if (pud_huge(*pud) && pud_present(*pud)) {
        pfn = pud_pfn(*pud);
        page_offset = vaddr & (PUD_SIZE - 1);
        phys_addr = (pfn << PAGE_SHIFT) + page_offset;
        kpm_debug("1GB huge page: PFN=0x%lx PA=0x%lx\n", pfn, phys_addr);
        goto out_unlock;
    }
    
    /* Level 3: Page Middle Directory */
    pmd = pmd_offset(pud, vaddr);
    if (pmd_none(*pmd) || pmd_bad(*pmd)) {
        kpm_debug("Invalid PMD entry for 0x%lx\n", vaddr);
        goto out_unlock;
    }
    
    /* Check for 2MB huge page at PMD level */
    if (pmd_huge(*pmd) && pmd_present(*pmd)) {
        pfn = pmd_pfn(*pmd);
        page_offset = vaddr & (PMD_SIZE - 1);
        phys_addr = (pfn << PAGE_SHIFT) + page_offset;
        kpm_debug("2MB huge page: PFN=0x%lx PA=0x%lx\n", pfn, phys_addr);
        goto out_unlock;
    }
    
    /* Level 4: Page Table Entry */
    pte = pte_offset_map(pmd, vaddr);
    if (!pte) {
        kpm_err("Failed to map PTE for 0x%lx\n", vaddr);
        goto out_unlock;
    }
    
    /* Verify PTE is present and valid */
    if (!pte_present(*pte)) {
        kpm_debug("PTE not present for 0x%lx\n", vaddr);
        pte_unmap(pte);
        goto out_unlock;
    }
    
    /* Extract physical frame number */
    pfn = pte_pfn(*pte);
    phys_addr = (pfn << PAGE_SHIFT) + page_offset;
    
    kpm_debug("4KB page: PFN=0x%lx PA=0x%lx\n", pfn, phys_addr);
    
    pte_unmap(pte);
    
out_unlock:
    up_read(&mm->mmap_lock);
    
    if (!phys_addr) {
        kpm_err("Page walk failed for VA=0x%lx\n", vaddr);
    }
    
    return phys_addr;
}

/**
 * validate_user_address - Validate user address range for safety
 * @mm: Target process mm_struct
 * @vaddr: Starting virtual address
 * @size: Range size in bytes
 * 
 * Checks:
 * - Address is within user space bounds
 * - Address range doesn't wrap around
 * - Size is within acceptable limits
 * 
 * Returns: 0 if valid, -EINVAL otherwise
 */
int validate_user_address(struct mm_struct *mm, unsigned long vaddr, unsigned long size)
{
    unsigned long end;
    
    if (!mm || size == 0) {
        return -EINVAL;
    }
    
    /* Check for overflow */
    if (vaddr + size < vaddr) {
        kpm_err("Address overflow: 0x%lx + %lu\n", vaddr, size);
        return -EINVAL;
    }
    
    end = vaddr + size;
    
    /* User addresses must be below TASK_SIZE */
    if (vaddr >= TASK_SIZE || end > TASK_SIZE) {
        kpm_err("Address out of range: 0x%lx-0x%lx (TASK_SIZE=0x%lx)\n",
                vaddr, end, TASK_SIZE);
        return -EINVAL;
    }
    
    if (size > MAX_TRANSFER_SIZE) {
        kpm_err("Size too large: %lu (max: %u)\n", size, MAX_TRANSFER_SIZE);
        return -EINVAL;
    }
    
    return 0;
}

/**
 * pin_user_pages_for_transfer - Pin user pages for DMA-style access
 * @mm: Target process mm_struct
 * @vaddr: Starting virtual address
 * @size: Total transfer size
 * @write: Non-zero to request write access (FOLL_WRITE)
 * @ctx: Operation context to populate
 * 
 * Handles the complete page pinning workflow:
 * 1. Calculate page boundaries and count
 * 2. Allocate page pointer arrays
 * 3. Pin pages with get_user_pages_remote()
 * 4. Map each page to kernel virtual address via kmap()
 * 5. Verify all mappings are valid
 * 
 * Uses kmap() instead of kmap_atomic() for compatibility
 * with sleeping operations.
 * 
 * Returns: 0 on success, negative error on failure
 *          On partial failure, cleans up already-pinned pages
 */
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
    
    /* Initialize context */
    memset(ctx, 0, sizeof(*ctx));
    
    /* Calculate page-aligned boundaries */
    start_page = vaddr & PAGE_MASK;
    end_page = (vaddr + size + PAGE_SIZE - 1) & PAGE_MASK;
    ctx->nr_pages = (end_page - start_page) >> PAGE_SHIFT;
    
    if (ctx->nr_pages <= 0) {
        kpm_err("Invalid page count: %d\n", ctx->nr_pages);
        return -EINVAL;
    }
    
    if (ctx->nr_pages > MAX_PAGES_PER_OP) {
        kpm_err("Too many pages: %d (max: %d)\n", ctx->nr_pages, MAX_PAGES_PER_OP);
        return -E2BIG;
    }
    
    /* Allocate page pointer arrays with zero initialization */
    ctx->pages = kcalloc(ctx->nr_pages, sizeof(struct page *), GFP_KERNEL);
    if (!ctx->pages) {
        kpm_err("Failed to allocate page array (%d entries)\n", ctx->nr_pages);
        return -ENOMEM;
    }
    
    ctx->kva_array = kcalloc(ctx->nr_pages, sizeof(void *), GFP_KERNEL);
    if (!ctx->kva_array) {
        kpm_err("Failed to allocate KVA array\n");
        kfree(ctx->pages);
        ctx->pages = NULL;
        return -ENOMEM;
    }
    
    /* Set GUP flags based on access type */
    if (write) {
        gup_flags |= FOLL_WRITE;
    }
    
    /* Pin user pages - this internally handles mmap_lock */
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
    
    /* Map each page to kernel virtual address */
    for (i = 0; i < ctx->nr_pages; i++) {
        void *page_addr;
        
        if (!ctx->pages[i]) {
            kpm_err("NULL page at index %d\n", i);
            ret = -EFAULT;
            goto partial_cleanup;
        }
        
        /* Verify page is valid before mapping */
        page_addr = page_address(ctx->pages[i]);
        if (!page_addr || !virt_addr_valid(page_addr)) {
            kpm_err("Invalid page at index %d (addr=0x%px)\n", i, page_addr);
            ret = -EFAULT;
            goto partial_cleanup;
        }
        
        /* Map to kernel virtual address */
        ctx->kva_array[i] = kmap(ctx->pages[i]);
        if (!ctx->kva_array[i]) {
            kpm_err("kmap failed for page %d\n", i);
            ret = -ENOMEM;
            goto partial_cleanup;
        }
    }
    
    ctx->pages_mapped = true;
    ctx->start_addr = vaddr;
    ctx->end_addr = vaddr + size;
    ctx->write_mode = write;
    ctx->target_mm = mm;
    ctx->target_task = current;
    
    kpm_debug("Pinned %d pages: 0x%lx-0x%lx (write=%d)\n",
              ctx->nr_pages, ctx->start_addr, ctx->end_addr, write);
    
    return 0;
    
partial_cleanup:
    /* Clean up partially mapped pages */
    for (i = 0; i < ctx->nr_pages; i++) {
        if (ctx->kva_array && ctx->kva_array[i]) {
            kunmap(ctx->pages[i]);
            ctx->kva_array[i] = NULL;
        }
    }
    ctx->pages_mapped = false;
    
    /* Fall through to full cleanup */
    
error_cleanup:
    /* Release all pinned pages */
    if (ctx->pages_pinned) {
        for (i = 0; i < ctx->nr_pages; i++) {
            if (ctx->pages && ctx->pages[i]) {
                put_page(ctx->pages[i]);
                ctx->pages[i] = NULL;
            }
        }
        ctx->pages_pinned = false;
    }
    
    /* Free arrays */
    kfree(ctx->kva_array);
    ctx->kva_array = NULL;
    kfree(ctx->pages);
    ctx->pages = NULL;
    ctx->nr_pages = 0;
    
    return ret;
}

/**
 * unpin_user_pages - Release all pinned pages and mappings
 * @ctx: Operation context to clean up
 * 
 * Safe cleanup in reverse order:
 * 1. Unmap kernel virtual addresses
 * 2. Mark pages dirty if write operation
 * 3. Release page references
 * 4. Free arrays
 */
void unpin_user_pages(struct mem_op_context *ctx)
{
    int i;
    
    if (!ctx) {
        return;
    }
    
    /* Unmap kernel virtual addresses */
    if (ctx->pages_mapped) {
        for (i = 0; i < ctx->nr_pages; i++) {
            if (ctx->kva_array && ctx->kva_array[i]) {
                kunmap(ctx->pages[i]);
                ctx->kva_array[i] = NULL;
            }
        }
        ctx->pages_mapped = false;
    }
    
    /* Release page references */
    if (ctx->pages_pinned) {
        for (i = 0; i < ctx->nr_pages; i++) {
            if (ctx->pages && ctx->pages[i]) {
                /* Mark dirty if write operation for proper writeback */
                if (ctx->write_mode) {
                    set_page_dirty_lock(ctx->pages[i]);
                }
                put_page(ctx->pages[i]);
                ctx->pages[i] = NULL;
            }
        }
        ctx->pages_pinned = false;
    }
    
    /* Free arrays */
    kfree(ctx->kva_array);
    ctx->kva_array = NULL;
    kfree(ctx->pages);
    ctx->pages = NULL;
    ctx->nr_pages = 0;
    
    kpm_debug("Unpinned all pages\n");
}

/**
 * copy_data_to_user_pages - Copy data from kernel buffer to pinned pages
 * @ctx: Operation context with pinned pages
 * @src: Source kernel buffer
 * @size: Number of bytes to copy
 * 
 * Handles page boundary crossings automatically by:
 * 1. Calculating page index for each segment
 * 2. Computing offset within each page
 * 3. Splitting copy into page-sized chunks
 * 4. Validating each destination before writing
 * 
 * This is used for WRITE operations.
 * 
 * Returns: 0 on success, -EFAULT on error
 */
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
        
        /* Calculate which page and where within it */
        page_index = (current_addr - (ctx->start_addr & PAGE_MASK)) >> PAGE_SHIFT;
        offset_in_page = current_addr & (PAGE_SIZE - 1);
        
        if (page_index >= ctx->nr_pages) {
            kpm_err("Page index %d out of bounds (max: %d)\n",
                    page_index, ctx->nr_pages);
            return -EFAULT;
        }
        
        /* Calculate copy size for this page chunk */
        copy_size = min_t(size_t, PAGE_SIZE - offset_in_page,
                          size - offset_in_transfer);
        
        /* Get destination kernel virtual address */
        dest_kva = ctx->kva_array[page_index] + offset_in_page;
        
        /* Critical: Verify destination is valid before writing */
        if (!virt_addr_valid(dest_kva)) {
            kpm_err("Invalid destination KVA: 0x%px (page %d, offset %lu)\n",
                    dest_kva, page_index, offset_in_page);
            return -EFAULT;
        }
        
        /* Zero-byte verification - check for zero page */
        if (is_zero_pfn(page_to_pfn(ctx->pages[page_index]))) {
            kpm_warn("Writing to zero page at index %d\n", page_index);
        }
        
        /* Perform the copy */
        memcpy(dest_kva, src + offset_in_transfer, copy_size);
        
        offset_in_transfer += copy_size;
    }
    
    return 0;
}

/**
 * copy_data_from_user_pages - Copy data from pinned pages to kernel buffer
 * @ctx: Operation context with pinned pages
 * @dst: Destination kernel buffer
 * @size: Number of bytes to copy
 * 
 * Handles page boundary crossings automatically.
 * Validates each source address before reading.
 * 
 * This is used for READ operations.
 * 
 * Returns: 0 on success, -EFAULT on error
 */
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
        
        /* Calculate which page and where within it */
        page_index = (current_addr - (ctx->start_addr & PAGE_MASK)) >> PAGE_SHIFT;
        offset_in_page = current_addr & (PAGE_SIZE - 1);
        
        if (page_index >= ctx->nr_pages) {
            kpm_err("Page index %d out of bounds (max: %d)\n",
                    page_index, ctx->nr_pages);
            return -EFAULT;
        }
        
        /* Calculate copy size for this page chunk */
        copy_size = min_t(size_t, PAGE_SIZE - offset_in_page,
                          size - offset_in_transfer);
        
        /* Get source kernel virtual address */
        src_kva = ctx->kva_array[page_index] + offset_in_page;
        
        /* Critical: Verify source is valid before reading */
        if (!virt_addr_valid(src_kva)) {
            kpm_err("Invalid source KVA: 0x%px (page %d, offset %lu)\n",
                    src_kva, page_index, offset_in_page);
            return -EFAULT;
        }
        
        /* Perform the copy */
        memcpy(dst + offset_in_transfer, src_kva, copy_size);
        
        offset_in_transfer += copy_size;
    }
    
    return 0;
}