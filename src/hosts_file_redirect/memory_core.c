/**
 * memory_core.c - Core memory operation handlers
 * 
 * This module implements:
 * - Resilient read/write loop handlers with page boundary splitting
 * - Zero-byte verification to prevent kernel panics
 * - Process base address resolution
 * - kmap_atomic() based access for strict data consistency
 */

#include "framework.h"

static DEFINE_MUTEX(memory_op_lock);

/**
 * memory_initialize - Initialize memory core subsystem
 * 
 * Returns: 0 on success
 */
int memory_initialize(void)
{
    pr_info("KPM_MEM: Memory core subsystem initialized\n");
    return 0;
}

/**
 * memory_cleanup - Cleanup memory core subsystem
 */
void memory_cleanup(void)
{
    pr_info("KPM_MEM: Memory core subsystem cleaned up\n");
}

/**
 * handle_memory_read - Safe read handler with page boundary splitting
 * @pkt: Operation packet from userspace
 * 
 * Uses page-by-page slicing to read process memory.
 * Implements get_user_pages_remote() for robust access.
 * 
 * Returns: 0 on success, negative error code on failure
 */
int handle_memory_read(struct k_packet *pkt)
{
    struct mm_struct *mm = NULL;
    struct task_struct *task = NULL;
    struct mem_op_context ctx;
    void *kernel_buffer = NULL;
    int ret = 0;
    unsigned long read_addr = pkt->target_addr;
    unsigned long read_size = pkt->size;
    
    pr_debug("KPM_MEM: Read request - PID: %d, Addr: 0x%llx, Size: %u\n",
             pkt->target_pid, pkt->target_addr, pkt->size);
    
    /* Validate parameters */
    if (read_size == 0 || read_size > MAX_TRANSFER_SIZE) {
        pkt->status = STATUS_INVALID_SIZE;
        return -EINVAL;
    }
    
    /* Acquire target process mm */
    ret = get_process_mm(pkt->target_pid, &mm, &task);
    if (ret < 0) {
        pkt->status = STATUS_INVALID_PID;
        pr_err("KPM_MEM: Failed to get process mm for PID %d\n", pkt->target_pid);
        return ret;
    }
    
    /* Validate address range */
    ret = validate_user_address(mm, read_addr, read_size);
    if (ret < 0) {
        pkt->status = STATUS_INVALID_ADDR;
        pr_err("KPM_MEM: Invalid address range 0x%llx-0x%llx\n",
               read_addr, read_addr + read_size);
        put_process_mm(mm);
        return ret;
    }
    
    /* Allocate kernel buffer for temporary storage */
    kernel_buffer = kmalloc(read_size, GFP_KERNEL);
    if (!kernel_buffer) {
        pkt->status = STATUS_MEM_ALLOC_FAIL;
        pr_err("KPM_MEM: Failed to allocate kernel buffer of size %lu\n", read_size);
        put_process_mm(mm);
        return -ENOMEM;
    }
    
    /* Initialize operation context */
    memset(&ctx, 0, sizeof(ctx));
    
    mutex_lock(&memory_op_lock);
    
    /* Pin user pages for read operation */
    ret = pin_user_pages_for_transfer(mm, read_addr, read_size, 0, &ctx);
    if (ret < 0) {
        pkt->status = STATUS_PAGE_FAULT;
        pr_err("KPM_MEM: Failed to pin user pages: %d\n", ret);
        mutex_unlock(&memory_op_lock);
        goto cleanup;
    }
    
    /* Copy data from pinned pages to kernel buffer */
    ret = copy_data_from_user_pages(&ctx, kernel_buffer, read_size);
    if (ret < 0) {
        pkt->status = STATUS_COPY_FAIL;
        pr_err("KPM_MEM: Failed to copy data from pages: %d\n", ret);
        unpin_user_pages(&ctx);
        mutex_unlock(&memory_op_lock);
        goto cleanup;
    }
    
    /* Release pinned pages */
    unpin_user_pages(&ctx);
    mutex_unlock(&memory_op_lock);
    
    /* Copy to userspace buffer */
    if (pkt->user_buffer) {
        /* Zero-byte verification before copy_to_user */
        if (!access_ok((void __user *)pkt->user_buffer, read_size)) {
            pkt->status = STATUS_ACCESS_DENIED;
            pr_err("KPM_MEM: access_ok failed for user buffer\n");
            ret = -EFAULT;
            goto cleanup;
        }
        
        if (copy_to_user((void __user *)pkt->user_buffer, kernel_buffer, read_size)) {
            pkt->status = STATUS_COPY_FAIL;
            pr_err("KPM_MEM: copy_to_user failed\n");
            ret = -EFAULT;
            goto cleanup;
        }
    }
    
    pkt->status = STATUS_SUCCESS;
    pkt->page_count = read_size / PAGE_SIZE + ((read_size % PAGE_SIZE) ? 1 : 0);
    
cleanup:
    kfree(kernel_buffer);
    put_process_mm(mm);
    return ret;
}

/**
 * handle_memory_write - Safe write handler with page boundary splitting
 * @pkt: Operation packet from userspace
 * 
 * Uses page-by-page slicing to write process memory.
 * Implements get_user_pages_remote() with FOLL_WRITE for robust access.
 * 
 * Returns: 0 on success, negative error code on failure
 */
int handle_memory_write(struct k_packet *pkt)
{
    struct mm_struct *mm = NULL;
    struct task_struct *task = NULL;
    struct mem_op_context ctx;
    void *kernel_buffer = NULL;
    int ret = 0;
    unsigned long write_addr = pkt->target_addr;
    unsigned long write_size = pkt->size;
    
    pr_debug("KPM_MEM: Write request - PID: %d, Addr: 0x%llx, Size: %u\n",
             pkt->target_pid, pkt->target_addr, pkt->size);
    
    /* Validate parameters */
    if (write_size == 0 || write_size > MAX_TRANSFER_SIZE) {
        pkt->status = STATUS_INVALID_SIZE;
        return -EINVAL;
    }
    
    /* Acquire target process mm */
    ret = get_process_mm(pkt->target_pid, &mm, &task);
    if (ret < 0) {
        pkt->status = STATUS_INVALID_PID;
        pr_err("KPM_MEM: Failed to get process mm for PID %d\n", pkt->target_pid);
        return ret;
    }
    
    /* Validate address range */
    ret = validate_user_address(mm, write_addr, write_size);
    if (ret < 0) {
        pkt->status = STATUS_INVALID_ADDR;
        pr_err("KPM_MEM: Invalid address range 0x%llx-0x%llx\n",
               write_addr, write_addr + write_size);
        put_process_mm(mm);
        return ret;
    }
    
    /* Allocate kernel buffer for temporary storage */
    kernel_buffer = kmalloc(write_size, GFP_KERNEL);
    if (!kernel_buffer) {
        pkt->status = STATUS_MEM_ALLOC_FAIL;
        pr_err("KPM_MEM: Failed to allocate kernel buffer of size %lu\n", write_size);
        put_process_mm(mm);
        return -ENOMEM;
    }
    
    /* Copy from userspace buffer first */
    if (pkt->user_buffer) {
        /* Zero-byte verification before copy_from_user */
        if (!access_ok((void __user *)pkt->user_buffer, write_size)) {
            pkt->status = STATUS_ACCESS_DENIED;
            pr_err("KPM_MEM: access_ok failed for user buffer\n");
            ret = -EFAULT;
            goto cleanup;
        }
        
        if (copy_from_user(kernel_buffer, (void __user *)pkt->user_buffer, write_size)) {
            pkt->status = STATUS_COPY_FAIL;
            pr_err("KPM_MEM: copy_from_user failed\n");
            ret = -EFAULT;
            goto cleanup;
        }
    }
    
    /* Initialize operation context */
    memset(&ctx, 0, sizeof(ctx));
    
    mutex_lock(&memory_op_lock);
    
    /* Pin user pages for write operation */
    ret = pin_user_pages_for_transfer(mm, write_addr, write_size, 1, &ctx);
    if (ret < 0) {
        pkt->status = STATUS_PAGE_FAULT;
        pr_err("KPM_MEM: Failed to pin user pages for write: %d\n", ret);
        mutex_unlock(&memory_op_lock);
        goto cleanup;
    }
    
    /* Copy data from kernel buffer to pinned pages */
    ret = copy_data_to_user_pages(&ctx, kernel_buffer, write_size);
    if (ret < 0) {
        pkt->status = STATUS_COPY_FAIL;
        pr_err("KPM_MEM: Failed to copy data to pages: %d\n", ret);
        unpin_user_pages(&ctx);
        mutex_unlock(&memory_op_lock);
        goto cleanup;
    }
    
    /* Release pinned pages (set_page_dirty handled in unpin) */
    unpin_user_pages(&ctx);
    mutex_unlock(&memory_op_lock);
    
    pkt->status = STATUS_SUCCESS;
    pkt->page_count = write_size / PAGE_SIZE + ((write_size % PAGE_SIZE) ? 1 : 0);
    
cleanup:
    kfree(kernel_buffer);
    put_process_mm(mm);
    return ret;
}

/**
 * resolve_process_base - Resolve target process base address
 * @pkt: Operation packet from userspace
 * 
 * Reads /proc/PID/maps equivalent via vm_start of first vma.
 * Falls back to mm->start_code if VMA traversal fails.
 * 
 * Returns: 0 on success, negative error code on failure
 */
int resolve_process_base(struct k_packet *pkt)
{
    struct mm_struct *mm = NULL;
    struct task_struct *task = NULL;
    struct vm_area_struct *vma;
    int ret;
    unsigned long base_addr = 0;
    
    pr_debug("KPM_MEM: Base resolution request - PID: %d\n", pkt->target_pid);
    
    ret = get_process_mm(pkt->target_pid, &mm, &task);
    if (ret < 0) {
        pkt->status = STATUS_INVALID_PID;
        pr_err("KPM_MEM: Failed to get process mm for PID %d\n", pkt->target_pid);
        return ret;
    }
    
    if (down_read_killable(&mm->mmap_lock)) {
        pkt->status = STATUS_MMAP_LOCK_FAIL;
        pr_err("KPM_MEM: Failed to acquire mmap_lock for base resolution\n");
        put_process_mm(mm);
        return -EINTR;
    }
    
    /* Traverse VMA list to find first executable mapping (executable base) */
    vma = mm->mmap;
    while (vma) {
        if (vma->vm_flags & VM_EXEC) {
            base_addr = vma->vm_start;
            break;
        }
        vma = vma->vm_next;
    }
    
    /* Fallback to start_code if no executable VMA found */
    if (!base_addr && mm->start_code) {
        base_addr = mm->start_code;
    }
    
    /* Last resort: start of first VMA */
    if (!base_addr && mm->mmap) {
        base_addr = mm->mmap->vm_start;
    }
    
    up_read(&mm->mmap_lock);
    
    if (!base_addr) {
        pkt->status = STATUS_INVALID_ADDR;
        pr_err("KPM_MEM: Failed to resolve base address for PID %d\n", pkt->target_pid);
        put_process_mm(mm);
        return -EINVAL;
    }
    
    /* Resolve physical address for the base address */
    pkt->physical_addr = virtual_to_physical(mm, base_addr);
    pkt->resolved_base = base_addr;
    pkt->status = STATUS_SUCCESS;
    
    pr_info("KPM_MEM: Resolved base for PID %d: V=0x%llx, P=0x%llx\n",
            pkt->target_pid, pkt->resolved_base, pkt->physical_addr);
    
    put_process_mm(mm);
    return 0;
}