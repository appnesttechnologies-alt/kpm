/**
 * process_helper.c - Process management and MMU page table walk implementation
 * 
 * This module handles:
 * - Safe process/MM struct acquisition
 * - Multi-level ARM64 page table walk (PGD->P4D->PUD->PMD->PTE)
 * - Physical address resolution from virtual addresses
 * - Memory region validation and page pinning
 */

#include "framework.h"

/**
 * get_process_mm - Safely acquire task and mm_struct for target PID
 * @pid: Target process identifier
 * @mm: Output mm_struct pointer
 * @task: Output task_struct pointer
 * 
 * Uses RCU read lock for safe task_struct access.
 * Increments mm reference count to prevent premature deallocation.
 * 
 * Returns: 0 on success, negative error code on failure
 */
int get_process_mm(pid_t pid, struct mm_struct **mm, struct task_struct **task)
{
    struct task_struct *t;
    struct mm_struct *m;
    
    rcu_read_lock();
    
    t = pid_task(find_vpid(pid), PIDTYPE_PID);
    if (!t) {
        rcu_read_unlock();
        pr_err("KPM_MEM: Failed to find task for PID %d\n", pid);
        return -ESRCH;
    }
    
    m = t->mm;
    if (!m) {
        rcu_read_unlock();
        pr_err("KPM_MEM: No mm_struct for PID %d (kernel thread?)\n", pid);
        return -EINVAL;
    }
    
    /* Atomic reference count increment */
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
 * Decrements reference count, may trigger delayed cleanup.
 */
void put_process_mm(struct mm_struct *mm)
{
    if (mm)
        mmdrop(mm);
}

/**
 * virtual_to_physical - ARM64 multi-level page table walk
 * @mm: Target process memory descriptor
 * @vaddr: User virtual address to translate
 * 
 * Locks mmap_lock (read) and walks ARM64 translation tables:
 * PGD (Level 0) -> P4D (Level 1) -> PUD (Level 2) -> PMD (Level 3) -> PTE
 * 
 * For 4KB pages on ARM64:
 * - PGD: Bits [47:39] (9 bits, 512 entries)
 * - PUD: Bits [38:30] (9 bits, 512 entries)
 * - PMD: Bits [29:21] (9 bits, 512 entries)
 * - PTE: Bits [20:12] (9 bits, 512 entries)
 * - Offset: Bits [11:0] (12 bits, 4096 bytes)
 * 
 * Returns: Physical address + page offset, or 0 on failure
 */
unsigned long virtual_to_physical(struct mm_struct *mm, unsigned long vaddr)
{
    pgd_t *pgd;
    p4d_t *p4d;
    pud_t *pud;
    pmd_t *pmd;
    pte_t *pte;
    unsigned long pfn;
    unsigned long page_offset;
    unsigned long phys_addr = 0;
    
    if (!mm || !vaddr) {
        pr_err("KPM_MEM: Invalid parameters for V2P translation\n");
        return 0;
    }
    
    /* Check if address is within user range (ARM64: typically 0-0x7FFFFFFFFFFF) */
    if (vaddr >= TASK_SIZE) {
        pr_err("KPM_MEM: Address 0x%lx exceeds TASK_SIZE\n", vaddr);
        return 0;
    }
    
    /* Acquire mmap_lock for safe page table walk */
    if (down_read_killable(&mm->mmap_lock)) {
        pr_err("KPM_MEM: Failed to acquire mmap_lock\n");
        return 0;
    }
    
    /* Level 0: Page Global Directory */
    pgd = pgd_offset(mm, vaddr);
    if (pgd_none(*pgd) || pgd_bad(*pgd)) {
        pr_err("KPM_MEM: Invalid PGD entry for vaddr 0x%lx\n", vaddr);
        goto out_unlock;
    }
    
    /* Level 1: Page 4th-level Directory (P4D) */
    p4d = p4d_offset(pgd, vaddr);
    if (p4d_none(*p4d) || p4d_bad(*p4d)) {
        pr_err("KPM_MEM: Invalid P4D entry for vaddr 0x%lx\n", vaddr);
        goto out_unlock;
    }
    
    /* Level 2: Page Upper Directory */
    pud = pud_offset(p4d, vaddr);
    if (pud_none(*pud) || pud_bad(*pud)) {
        pr_err("KPM_MEM: Invalid PUD entry for vaddr 0x%lx\n", vaddr);
        goto out_unlock;
    }
    
    /* Check for huge page at PUD level */
    if (pud_huge(*pud)) {
        pfn = pud_pfn(*pud);
        page_offset = vaddr & (PUD_SIZE - 1);
        phys_addr = (pfn << PAGE_SHIFT_4K) + page_offset;
        goto out_unlock;
    }
    
    /* Level 3: Page Middle Directory */
    pmd = pmd_offset(pud, vaddr);
    if (pmd_none(*pmd) || pmd_bad(*pmd)) {
        pr_err("KPM_MEM: Invalid PMD entry for vaddr 0x%lx\n", vaddr);
        goto out_unlock;
    }
    
    /* Check for huge page at PMD level */
    if (pmd_huge(*pmd)) {
        pfn = pmd_pfn(*pmd);
        page_offset = vaddr & (PMD_SIZE - 1);
        phys_addr = (pfn << PAGE_SHIFT_4K) + page_offset;
        goto out_unlock;
    }
    
    /* Level 4: Page Table Entry */
    pte = pte_offset_map(pmd, vaddr);
    if (!pte) {
        pr_err("KPM_MEM: Failed to map PTE for vaddr 0x%lx\n", vaddr);
        goto out_unlock;
    }
    
    if (pte_none(*pte) || !pte_present(*pte)) {
        pr_err("KPM_MEM: PTE not present for vaddr 0x%lx\n", vaddr);
        pte_unmap(pte);
        goto out_unlock;
    }
    
    /* Extract physical frame number and calculate final address */
    pfn = pte_pfn(*pte);
    page_offset = vaddr & (PAGE_SIZE - 1);
    phys_addr = (pfn << PAGE_SHIFT_4K) + page_offset;
    
    pte_unmap(pte);
    
    pr_debug("KPM_MEM: V2P: 0x%lx -> 0x%lx (PFN: 0x%lx, offset: 0x%lx)\n",
             vaddr, phys_addr, pfn, page_offset);
    
out_unlock:
    up_read(&mm->mmap_lock);
    return phys_addr;
}

/**
 * validate_user_address - Verify user address range validity
 * @mm: Target process mm_struct
 * @vaddr: Starting virtual address
 * @size: Range size
 * 
 * Returns: 0 if valid, negative error code otherwise
 */
int validate_user_address(struct mm_struct *mm, unsigned long vaddr, unsigned long size)
{
    unsigned long end = vaddr + size;
    
    /* Basic bounds checking */
    if (vaddr >= TASK_SIZE || end < vaddr || end >= TASK_SIZE) {
        pr_err("KPM_MEM: Address range 0x%lx-0x%lx out of bounds\n", vaddr, end);
        return -EINVAL;
    }
    
    if (size == 0 || size > MAX_TRANSFER_SIZE) {
        pr_err("KPM_MEM: Invalid transfer size %lu\n", size);
        return -EINVAL;
    }
    
    return 0;
}

/**
 * pin_user_pages_for_transfer - Pin user pages for DMA-style access
 * @mm: Target process mm_struct
 * @vaddr: Starting virtual address
 * @size: Total transfer size
 * @write: Non-zero for write access (FOLL_WRITE)
 * @ctx: Operation context to populate
 * 
 * Calculates required page count, pins all pages via get_user_pages_remote(),
 * and maps them to kernel virtual addresses using kmap or kmap_atomic.
 * 
 * Returns: 0 on success, negative error code on failure
 */
int pin_user_pages_for_transfer(struct mm_struct *mm, unsigned long vaddr,
                                 unsigned long size, int write, struct mem_op_context *ctx)
{
    unsigned long start_page, end_page;
    unsigned int gup_flags = FOLL_FORCE;
    int i, ret;
    
    if (!mm || !ctx || size == 0) {
        pr_err("KPM_MEM: Invalid pin_user_pages parameters\n");
        return -EINVAL;
    }
    
    /* Calculate page boundaries */
    start_page = vaddr & PAGE_MASK_4K;
    end_page = (vaddr + size + PAGE_SIZE - 1) & PAGE_MASK_4K;
    ctx->nr_pages = (end_page - start_page) >> PAGE_SHIFT_4K;
    
    if (ctx->nr_pages <= 0 || ctx->nr_pages > 256) {  /* Safety limit */
        pr_err("KPM_MEM: Invalid page count %d\n", ctx->nr_pages);
        return -EINVAL;
    }
    
    /* Allocate page pointer array */
    ctx->pages = kcalloc(ctx->nr_pages, sizeof(struct page *), GFP_KERNEL);
    if (!ctx->pages) {
        pr_err("KPM_MEM: Failed to allocate page array\n");
        return -ENOMEM;
    }
    
    /* Allocate KVA array */
    ctx->kva_array = kcalloc(ctx->nr_pages, sizeof(void *), GFP_KERNEL);
    if (!ctx->kva_array) {
        kfree(ctx->pages);
        return -ENOMEM;
    }
    
    if (write)
        gup_flags |= FOLL_WRITE;
    
    /* Pin user pages - safely acquires mmap_lock internally */
#if LINUX_VERSION_CODE >= KERNEL_VERSION(5, 8, 0)
    ret = get_user_pages_remote(mm, start_page, ctx->nr_pages, gup_flags,
                                ctx->pages, NULL);
#else
    ret = get_user_pages_remote(NULL, mm, start_page, ctx->nr_pages,
                                gup_flags, ctx->pages, NULL, NULL);
#endif
    
    if (ret < 0 || ret != ctx->nr_pages) {
        pr_err("KPM_MEM: get_user_pages_remote failed: %d (expected %d)\n",
               ret, ctx->nr_pages);
        if (ret > 0) {
            ctx->nr_pages = ret;
            goto partial_cleanup;
        }
        ctx->nr_pages = 0;
        kfree(ctx->kva_array);
        kfree(ctx->pages);
        return ret < 0 ? ret : -EFAULT;
    }
    
    /* Map each page to kernel virtual address */
    for (i = 0; i < ctx->nr_pages; i++) {
        /* Verify page validity before mapping */
        if (!ctx->pages[i] || !virt_addr_valid(page_address(ctx->pages[i]))) {
            pr_err("KPM_MEM: Invalid page %d detected\n", i);
            ctx->nr_pages = i;
            goto partial_cleanup;
        }
        
        ctx->kva_array[i] = kmap(ctx->pages[i]);
        if (!ctx->kva_array[i]) {
            pr_err("KPM_MEM: kmap failed for page %d\n", i);
            ctx->nr_pages = i;
            goto partial_cleanup;
        }
    }
    
    ctx->start_addr = vaddr;
    ctx->end_addr = vaddr + size;
    ctx->write_mode = write;
    ctx->target_mm = mm;
    
    return 0;
    
partial_cleanup:
    /* Release any pages we successfully pinned */
    for (i = 0; i < ctx->nr_pages; i++) {
        if (ctx->kva_array[i]) {
            kunmap(ctx->pages[i]);
            ctx->kva_array[i] = NULL;
        }
        if (ctx->pages[i]) {
            put_page(ctx->pages[i]);
            ctx->pages[i] = NULL;
        }
    }
    kfree(ctx->kva_array);
    kfree(ctx->pages);
    return -EFAULT;
}

/**
 * unpin_user_pages - Release pinned pages and unmap KVAs
 * @ctx: Operation context to clean up
 * 
 * Reverse operation of pin_user_pages_for_transfer.
 * Unmaps kernel virtual addresses and releases page references.
 */
void unpin_user_pages(struct mem_op_context *ctx)
{
    int i;
    
    if (!ctx)
        return;
    
    for (i = 0; i < ctx->nr_pages; i++) {
        if (ctx->kva_array && ctx->kva_array[i]) {
            /* Unmap kernel virtual address */
            kunmap(ctx->pages[i]);
            ctx->kva_array[i] = NULL;
        }
        
        if (ctx->pages && ctx->pages[i]) {
            /* Release page reference */
            if (ctx->write_mode)
                set_page_dirty_lock(ctx->pages[i]);
            put_page(ctx->pages[i]);
            ctx->pages[i] = NULL;
        }
    }
    
    kfree(ctx->kva_array);
    kfree(ctx->pages);
    ctx->kva_array = NULL;
    ctx->pages = NULL;
    ctx->nr_pages = 0;
}

/**
 * copy_data_to_user_pages - Copy data from kernel buffer to pinned pages
 * @ctx: Operation context with pinned pages
 * @src: Source kernel buffer
 * @size: Transfer size
 * 
 * Handles page boundary crossings by iterating through pinned pages.
 * 
 * Returns: 0 on success, negative error code on failure
 */
int copy_data_to_user_pages(struct mem_op_context *ctx, void *src, size_t size)
{
    unsigned long offset_in_page;
    unsigned long offset_in_transfer = 0;
    size_t copy_size;
    int page_index;
    void *dest_kva;
    
    if (!ctx || !src || size == 0)
        return -EINVAL;
    
    while (offset_in_transfer < size) {
        /* Calculate current page index and offset */
        unsigned long current_addr = ctx->start_addr + offset_in_transfer;
        page_index = (current_addr - (ctx->start_addr & PAGE_MASK_4K)) >> PAGE_SHIFT_4K;
        offset_in_page = current_addr & (PAGE_SIZE - 1);
        
        if (page_index >= ctx->nr_pages) {
            pr_err("KPM_MEM: Page index %d out of bounds\n", page_index);
            return -EFAULT;
        }
        
        /* Calculate copy size for this page */
        copy_size = min_t(size_t, PAGE_SIZE - offset_in_page,
                          size - offset_in_transfer);
        
        /* Get kernel virtual address for this page */
        dest_kva = ctx->kva_array[page_index];
        if (!dest_kva) {
            pr_err("KPM_MEM: NULL KVA for page %d\n", page_index);
            return -EFAULT;
        }
        
        /* Validate KVA before writing */
        if (!virt_addr_valid(dest_kva + offset_in_page)) {
            pr_err("KPM_MEM: Invalid destination KVA 0x%px+%lu\n",
                   dest_kva, offset_in_page);
            return -EFAULT;
        }
        
        /* Perform copy */
        memcpy(dest_kva + offset_in_page, src + offset_in_transfer, copy_size);
        
        offset_in_transfer += copy_size;
    }
    
    return 0;
}

/**
 * copy_data_from_user_pages - Copy data from pinned pages to kernel buffer
 * @ctx: Operation context with pinned pages
 * @dst: Destination kernel buffer
 * @size: Transfer size
 * 
 * Handles page boundary crossings by iterating through pinned pages.
 * 
 * Returns: 0 on success, negative error code on failure
 */
int copy_data_from_user_pages(struct mem_op_context *ctx, void *dst, size_t size)
{
    unsigned long offset_in_page;
    unsigned long offset_in_transfer = 0;
    size_t copy_size;
    int page_index;
    void *src_kva;
    
    if (!ctx || !dst || size == 0)
        return -EINVAL;
    
    while (offset_in_transfer < size) {
        /* Calculate current page index and offset */
        unsigned long current_addr = ctx->start_addr + offset_in_transfer;
        page_index = (current_addr - (ctx->start_addr & PAGE_MASK_4K)) >> PAGE_SHIFT_4K;
        offset_in_page = current_addr & (PAGE_SIZE - 1);
        
        if (page_index >= ctx->nr_pages) {
            pr_err("KPM_MEM: Page index %d out of bounds\n", page_index);
            return -EFAULT;
        }
        
        /* Calculate copy size for this page */
        copy_size = min_t(size_t, PAGE_SIZE - offset_in_page,
                          size - offset_in_transfer);
        
        /* Get kernel virtual address for this page */
        src_kva = ctx->kva_array[page_index];
        if (!src_kva) {
            pr_err("KPM_MEM: NULL KVA for page %d\n", page_index);
            return -EFAULT;
        }
        
        /* Validate KVA before reading */
        if (!virt_addr_valid(src_kva + offset_in_page)) {
            pr_err("KPM_MEM: Invalid source KVA 0x%px+%lu\n",
                   src_kva, offset_in_page);
            return -EFAULT;
        }
        
        /* Perform copy */
        memcpy(dst + offset_in_transfer, src_kva + offset_in_page, copy_size);
        
        offset_in_transfer += copy_size;
    }
    
    return 0;
}