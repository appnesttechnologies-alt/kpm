/* SPDX-License-Identifier: GPL-2.0-or-later */
/* 
 * Copyright (C) 2026 Surajit. All Rights Reserved.
 * 
 * KPM Memory Debugger - Main Module Entry Point
 * Provides IOCTL bridge controller for APatch framework
 */

#include "framework.h"

/* APatch KPM Module Metadata */
KPM_NAME("kpm_memory_debugger");
KPM_VERSION(HFR_VERSION);
KPM_LICENSE("GPL v2");
KPM_AUTHOR("Surajit");
KPM_DESCRIPTION("Cross-Process Memory Debugger with MMU Page Table Walk and R/W Handlers");

/* Global synchronization primitives */
DEFINE_MUTEX(ctl0_lock);
static atomic_t module_refcount = ATOMIC_INIT(0);
static bool module_initialized = false;

/**
 * validate_kpm_packet - Validate incoming packet for sanity
 * @pkt: Packet to validate
 * 
 * Performs basic sanity checks on the packet fields
 * to prevent kernel crashes from malformed requests.
 * 
 * Returns: true if valid, false otherwise
 */
static bool validate_kpm_packet(const struct k_packet *pkt)
{
    /* Check operation code range */
    if (pkt->op_code < OP_RESOLVE_BASE || pkt->op_code > OP_QUERY_PHYS) {
        kpm_err("Invalid op_code: 0x%04X\n", pkt->op_code);
        return false;
    }
    
    /* Validate PID range (1 to 4194304 for 32-bit PIDs) */
    if (pkt->target_pid == 0 || pkt->target_pid > 0x400000) {
        kpm_err("Invalid target_pid: %u\n", pkt->target_pid);
        return false;
    }
    
    /* Size validation for read/write operations */
    if ((pkt->op_code == OP_READ_VM || pkt->op_code == OP_WRITE_VM) &&
        (pkt->size == 0 || pkt->size > MAX_TRANSFER_SIZE)) {
        kpm_err("Invalid transfer size: %u (max: %u)\n", 
                pkt->size, MAX_TRANSFER_SIZE);
        return false;
    }
    
    /* User buffer required for read/write operations */
    if ((pkt->op_code == OP_READ_VM || pkt->op_code == OP_WRITE_VM) &&
        pkt->user_buffer == 0) {
        kpm_err("NULL user_buffer for R/W operation\n");
        return false;
    }
    
    return true;
}

/**
 * kpm_memory_ctl0_handler - Primary IOCTL bridge controller
 * @user_data: Userspace data pointer (struct k_packet)
 * @user_size: Size of userspace data
 * 
 * This is the main entry point for all userspace requests.
 * Thread-safe, serialized access with proper error handling.
 * 
 * Request Flow:
 * 1. Validate input parameters
 * 2. Copy packet from userspace (copy_from_user)
 * 3. Validate packet contents
 * 4. Execute requested operation
 * 5. Copy results back to userspace (copy_to_user)
 * 6. Clean up all resources
 * 
 * Returns: 0 on success, negative error on failure
 */
static long kpm_memory_ctl0_handler(void __user *user_data, size_t user_size)
{
    struct k_packet *pkt = NULL;
    struct k_packet local_pkt;
    int ret = 0;
    
    /* Phase 1: Input validation */
    if (!user_data) {
        kpm_err("NULL user_data pointer\n");
        return -EINVAL;
    }
    
    if (user_size != sizeof(struct k_packet)) {
        kpm_err("Invalid packet size: %zu (expected: %zu)\n",
                user_size, sizeof(struct k_packet));
        return -EINVAL;
    }
    
    if (!access_ok(user_data, sizeof(struct k_packet))) {
        kpm_err("access_ok failed for user_data\n");
        return -EFAULT;
    }
    
    /* Phase 2: Allocate kernel working copy */
    pkt = kzalloc(sizeof(struct k_packet), GFP_KERNEL);
    if (!pkt) {
        kpm_err("Failed to allocate kernel packet - OOM\n");
        return -ENOMEM;
    }
    
    /* Phase 3: Copy packet from userspace with retry logic */
    if (copy_from_user(pkt, user_data, sizeof(struct k_packet))) {
        kpm_err("copy_from_user failed - bad user pointer\n");
        ret = -EFAULT;
        goto out_free;
    }
    
    /* Save local copy for debugging */
    memcpy(&local_pkt, pkt, sizeof(struct k_packet));
    
    /* Phase 4: Validate packet contents */
    if (!validate_kpm_packet(pkt)) {
        pkt->status = STATUS_INVALID_SIZE;
        ret = -EINVAL;
        goto out_copy;
    }
    
    /* Phase 5: Acquire operation slot */
    atomic_inc(&module_refcount);
    
    kpm_info("Request: OP=0x%04X PID=%u ADDR=0x%llX SIZE=%u\n",
             pkt->op_code, pkt->target_pid, pkt->target_addr, pkt->size);
    
    /* Phase 6: Execute operation under mutex protection */
    mutex_lock(&ctl0_lock);
    
    switch (pkt->op_code) {
    case OP_RESOLVE_BASE:
        kpm_debug("Executing OP_RESOLVE_BASE\n");
        ret = resolve_process_base(pkt);
        break;
        
    case OP_READ_VM:
        kpm_debug("Executing OP_READ_VM\n");
        ret = handle_memory_read(pkt);
        break;
        
    case OP_WRITE_VM:
        kpm_debug("Executing OP_WRITE_VM\n");
        ret = handle_memory_write(pkt);
        break;
        
    case OP_QUERY_PHYS: {
        struct mm_struct *mm = NULL;
        struct task_struct *task = NULL;
        
        kpm_debug("Executing OP_QUERY_PHYS\n");
        
        ret = get_process_mm(pkt->target_pid, &mm, &task);
        if (ret < 0) {
            pkt->status = STATUS_INVALID_PID;
            kpm_err("Failed to get process MM for PID %u\n", pkt->target_pid);
        } else {
            pkt->physical_addr = virtual_to_physical(mm, pkt->target_addr);
            
            if (pkt->physical_addr) {
                pkt->status = STATUS_SUCCESS;
                kpm_info("Physical: VA=0x%llX -> PA=0x%llX\n",
                         pkt->target_addr, pkt->physical_addr);
            } else {
                pkt->status = STATUS_PAGE_WALK_FAIL;
                kpm_err("Page walk failed for VA=0x%llX\n", pkt->target_addr);
                ret = -EINVAL;
            }
            put_process_mm(mm);
        }
        break;
    }
    
    default:
        kpm_err("Unknown op_code: 0x%04X\n", pkt->op_code);
        pkt->status = STATUS_INVALID_SIZE;
        ret = -EINVAL;
        break;
    }
    
    mutex_unlock(&ctl0_lock);
    
    /* Phase 7: Log operation result */
    if (ret == 0) {
        kpm_debug("Operation completed successfully\n");
    } else {
        kpm_err("Operation failed with status: 0x%04X, ret: %d\n", 
                pkt->status, ret);
    }
    
    /* Phase 8: Copy results back to userspace */
out_copy:
    if (copy_to_user(user_data, pkt, sizeof(struct k_packet))) {
        kpm_err("copy_to_user failed on return path\n");
        ret = -EFAULT;
    }
    
    atomic_dec(&module_refcount);
    
out_free:
    if (pkt) {
        /* Secure cleanup - zero sensitive data */
        kzfree(pkt);
    }
    
    return ret;
}

/**
 * kpm_memory_init - Module initialization
 * @args: Optional arguments from userspace
 * @event: Event trigger string
 * @reserved: Reserved for future use
 * 
 * Called by APatch framework when module is loaded.
 * Initializes all subsystems and prints banner.
 * 
 * Returns: 0 on success, negative error on failure
 */
static long kpm_memory_init(const char *args, const char *event, void *__user reserved)
{
    int ret;
    
    /* Print initialization banner */
    kpm_info("========================================\n");
    kpm_info("KPM Memory Debugger - Initializing\n");
    kpm_info("========================================\n");
    kpm_info("Version    : %s\n", HFR_VERSION);
    kpm_info("Author     : Surajit\n");
    kpm_info("Arch       : ARM64 (4-Level Page Tables)\n");
    kpm_info("Features   : VM R/W, MMU Walk, Physical Query\n");
    kpm_info("Max Size   : %u bytes per operation\n", MAX_TRANSFER_SIZE);
    kpm_info("========================================\n");
    
    /* Initialize memory core subsystem */
    ret = memory_initialize();
    if (ret < 0) {
        kpm_err("Memory core initialization failed: %d\n", ret);
        kpm_info("========================================\n");
        kpm_info("INITIALIZATION FAILED !!!\n");
        kpm_info("========================================\n");
        return ret;
    }
    
    module_initialized = true;
    
    kpm_info("Module loaded successfully\n");
    kpm_info("Operations:\n");
    kpm_info("  OP_RESOLVE_BASE (0x1000)\n");
    kpm_info("  OP_READ_VM      (0x2000)\n");
    kpm_info("  OP_WRITE_VM     (0x3000)\n");
    kpm_info("  OP_QUERY_PHYS   (0x4000)\n");
    kpm_info("========================================\n");
    kpm_info("READY FOR PROFILING !!!\n");
    kpm_info("========================================\n");
    
    return 0;
}

/**
 * kpm_memory_exit - Module cleanup
 * @reserved: Reserved for future use
 * 
 * Called by APatch framework when module is unloaded.
 * Ensures all resources are freed safely.
 * 
 * Returns: 0 on success
 */
static long kpm_memory_exit(void *__user reserved)
{
    int wait_count = 0;
    
    kpm_info("========================================\n");
    kpm_info("KPM Memory Debugger - Shutting Down\n");
    kpm_info("========================================\n");
    
    if (!module_initialized) {
        kpm_warn("Module was not fully initialized\n");
        return 0;
    }
    
    /* Wait for active operations to complete */
    while (atomic_read(&module_refcount) > 0 && wait_count < 100) {
        if (wait_count % 10 == 0) {
            kpm_info("Waiting for %d active operations...\n",
                     atomic_read(&module_refcount));
        }
        msleep(50);
        wait_count++;
    }
    
    if (atomic_read(&module_refcount) > 0) {
        kpm_warn("Force unloading with %d active operations\n",
                 atomic_read(&module_refcount));
    }
    
    /* Cleanup memory core */
    memory_cleanup();
    
    module_initialized = false;
    
    kpm_info("All resources released\n");
    kpm_info("========================================\n");
    kpm_info("UNLOADED SAFELY WITHOUT FREEZING !!!\n");
    kpm_info("========================================\n");
    
    return 0;
}

/* Register with APatch framework */
KPM_INIT(kpm_memory_init);
KPM_EXIT(kpm_memory_exit);
KPM_CTL0(kpm_memory_ctl0_handler);