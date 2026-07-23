/**
 * main.c - APatch KPM Module Entry Point and IOCTL Controller
 * 
 * This module registers with APatch/KernelPatch SDK and provides:
 * - Module lifecycle management (init/exit)
 * - IOCTL bridge controller (KPM_CTL0)
 * - Safe copy_from_user/copy_to_user transaction handling
 * - Resource cleanup guarantees
 */

#include "framework.h"

/* Global module state */
static DEFINE_MUTEX(ctl0_lock);
static atomic_t module_refcount = ATOMIC_INIT(0);

/**
 * kpm_memory_ctl0_handler - IOCTL bridge controller
 * @user_data: Raw userspace data pointer
 * @user_size: Size of userspace data
 * 
 * Primary interface for userspace-to-kernel communication.
 * 1. copy_from_user the k_packet structure
 * 2. Execute requested operation
 * 3. copy_to_user status back to caller
 * 4. Clean up any allocated resources
 * 
 * Returns: 0 on success, negative error code on failure
 */
static long kpm_memory_ctl0_handler(void __user *user_data, size_t user_size)
{
    struct k_packet *pkt = NULL;
    int ret = 0;
    
    /* Validate input size */
    if (!user_data || user_size != sizeof(struct k_packet)) {
        pr_err("KPM_MEM: Invalid CTL0 call - wrong size: %zu\n", user_size);
        return -EINVAL;
    }
    
    /* Validate userspace pointer */
    if (!access_ok(user_data, sizeof(struct k_packet))) {
        pr_err("KPM_MEM: access_ok failed for user_data\n");
        return -EFAULT;
    }
    
    /* Allocate kernel-side packet */
    pkt = kmalloc(sizeof(struct k_packet), GFP_KERNEL);
    if (!pkt) {
        pr_err("KPM_MEM: Failed to allocate kernel packet\n");
        return -ENOMEM;
    }
    
    /* Copy from userspace */
    if (copy_from_user(pkt, user_data, sizeof(struct k_packet))) {
        pr_err("KPM_MEM: copy_from_user failed\n");
        ret = -EFAULT;
        goto out_free;
    }
    
    /* Increment module refcount */
    atomic_inc(&module_refcount);
    
    pr_info("KPM_MEM: CTL0 request - OP: 0x%x, PID: %d, Addr: 0x%llx, Size: %u\n",
            pkt->op_code, pkt->target_pid, pkt->target_addr, pkt->size);
    
    mutex_lock(&ctl0_lock);
    
    /* Dispatch based on operation code */
    switch (pkt->op_code) {
    case OP_RESOLVE_BASE:
        pr_debug("KPM_MEM: Dispatching OP_RESOLVE_BASE\n");
        ret = resolve_process_base(pkt);
        break;
        
    case OP_READ_VM:
        pr_debug("KPM_MEM: Dispatching OP_READ_VM\n");
        ret = handle_memory_read(pkt);
        break;
        
    case OP_WRITE_VM:
        pr_debug("KPM_MEM: Dispatching OP_WRITE_VM\n");
        ret = handle_memory_write(pkt);
        break;
        
    case OP_QUERY_PHYS: {
        struct mm_struct *mm = NULL;
        struct task_struct *task = NULL;
        
        pr_debug("KPM_MEM: Dispatching OP_QUERY_PHYS\n");
        ret = get_process_mm(pkt->target_pid, &mm, &task);
        if (ret < 0) {
            pkt->status = STATUS_INVALID_PID;
            pr_err("KPM_MEM: Failed to get mm for physical query\n");
        } else {
            pkt->physical_addr = virtual_to_physical(mm, pkt->target_addr);
            if (pkt->physical_addr) {
                pkt->status = STATUS_SUCCESS;
                pr_info("KPM_MEM: Physical addr resolved: 0x%llx\n",
                        pkt->physical_addr);
            } else {
                pkt->status = STATUS_PAGE_WALK_FAIL;
                pr_err("KPM_MEM: Page walk failed for 0x%llx\n",
                       pkt->target_addr);
                ret = -EINVAL;
            }
            put_process_mm(mm);
        }
        break;
    }
    
    default:
        pr_err("KPM_MEM: Unknown operation code: 0x%x\n", pkt->op_code);
        pkt->status = STATUS_INVALID_SIZE;
        ret = -EINVAL;
        break;
    }
    
    mutex_unlock(&ctl0_lock);
    
    /* Always copy status back to userspace */
    if (copy_to_user(user_data, pkt, sizeof(struct k_packet))) {
        pr_err("KPM_MEM: copy_to_user failed on return\n");
        ret = -EFAULT;
    }
    
    atomic_dec(&module_refcount);
    
out_free:
    kfree(pkt);
    return ret;
}

/**
 * kpm_memory_init - Module initialization
 * 
 * Called by APatch framework on module load.
 * Initializes all subsystems and registers CTL0 handler.
 * 
 * Returns: 0 on success
 */
static int __init kpm_memory_init(void)
{
    int ret;
    
    pr_info("KPM_MEM: Initializing KPM Memory Debugger Module\n");
    
    /* Initialize memory core subsystem */
    ret = memory_initialize();
    if (ret < 0) {
        pr_err("KPM_MEM: Failed to initialize memory core: %d\n", ret);
        return ret;
    }
    
    pr_info("KPM_MEM: Module loaded successfully\n");
    pr_info("KPM_MEM: Supported operations: RESOLVE_BASE, READ_VM, WRITE_VM, QUERY_PHYS\n");
    
    return 0;
}

/**
 * kpm_memory_exit - Module cleanup
 * 
 * Called by APatch framework on module unload.
 * Waits for active operations to complete, then cleans up resources.
 */
static void __exit kpm_memory_exit(void)
{
    pr_info("KPM_MEM: Unloading KPM Memory Debugger Module\n");
    
    /* Wait for all active operations to complete */
    while (atomic_read(&module_refcount) > 0) {
        pr_info("KPM_MEM: Waiting for %d active operations...\n",
                atomic_read(&module_refcount));
        msleep(100);
    }
    
    /* Cleanup memory core */
    memory_cleanup();
    
    pr_info("KPM_MEM: Module unloaded successfully\n");
}

/* APatch/KernelPatch SDK Module Registration Macros */
KPM_INIT(kpm_memory_init);
KPM_EXIT(kpm_memory_exit);
KPM_CTL0(kpm_memory_ctl0_handler);

MODULE_LICENSE("GPL");
MODULE_AUTHOR("KPM Memory Debugger Team");
MODULE_DESCRIPTION("Cross-Process Memory Debugger KPM for APatch");
MODULE_VERSION("1.0.0");