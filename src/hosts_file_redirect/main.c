/* SPDX-License-Identifier: GPL-2.0-or-later */
/* 
 * Copyright (C) 2026 Surajit. All Rights Reserved.
 * 
 * KPM Memory Debugger - Main Module Entry Point
 */

#include "framework.h"

/* APatch KPM Module Metadata */
KPM_NAME("kpm_memory_debugger");
KPM_VERSION(HFR_VERSION);
KPM_LICENSE("GPL v2");
KPM_AUTHOR("Surajit");
KPM_DESCRIPTION("Cross-Process Memory Debugger with MMU Page Table Walk and R/W Handlers");

/* Global synchronization */
static DEFINE_MUTEX(ctl0_lock);
static atomic_t module_refcount = ATOMIC_INIT(0);
static bool module_initialized = false;

static bool validate_kpm_packet(const struct k_packet *pkt)
{
    if (pkt->op_code < OP_RESOLVE_BASE || pkt->op_code > OP_QUERY_PHYS) {
        kpm_err("Invalid op_code: 0x%04X\n", pkt->op_code);
        return false;
    }
    
    if (pkt->target_pid == 0 || pkt->target_pid > 0x400000) {
        kpm_err("Invalid target_pid: %u\n", pkt->target_pid);
        return false;
    }
    
    if ((pkt->op_code == OP_READ_VM || pkt->op_code == OP_WRITE_VM) &&
        (pkt->size == 0 || pkt->size > MAX_TRANSFER_SIZE)) {
        kpm_err("Invalid transfer size: %u\n", pkt->size);
        return false;
    }
    
    if ((pkt->op_code == OP_READ_VM || pkt->op_code == OP_WRITE_VM) &&
        pkt->user_buffer == 0) {
        kpm_err("NULL user_buffer for R/W operation\n");
        return false;
    }
    
    return true;
}

static long kpm_memory_ctl0_handler(void __user *user_data, size_t user_size)
{
    struct k_packet *pkt = NULL;
    int ret = 0;
    
    if (!user_data || user_size != sizeof(struct k_packet)) {
        kpm_err("Invalid CTL0 call - size: %zu\n", user_size);
        return -EINVAL;
    }
    
    if (!access_ok(user_data, sizeof(struct k_packet))) {
        kpm_err("access_ok failed\n");
        return -EFAULT;
    }
    
    pkt = kzalloc(sizeof(struct k_packet), GFP_KERNEL);
    if (!pkt) {
        kpm_err("Failed to allocate kernel packet\n");
        return -ENOMEM;
    }
    
    if (copy_from_user(pkt, user_data, sizeof(struct k_packet))) {
        kpm_err("copy_from_user failed\n");
        ret = -EFAULT;
        goto out_free;
    }
    
    if (!validate_kpm_packet(pkt)) {
        pkt->status = STATUS_INVALID_SIZE;
        ret = -EINVAL;
        goto out_copy;
    }
    
    atomic_inc(&module_refcount);
    
    kpm_info("Request: OP=0x%04X PID=%u ADDR=0x%llX SIZE=%u\n",
             pkt->op_code, pkt->target_pid, pkt->target_addr, pkt->size);
    
    mutex_lock(&ctl0_lock);
    
    switch (pkt->op_code) {
    case OP_RESOLVE_BASE:
        ret = resolve_process_base(pkt);
        break;
        
    case OP_READ_VM:
        ret = handle_memory_read(pkt);
        break;
        
    case OP_WRITE_VM:
        ret = handle_memory_write(pkt);
        break;
        
    case OP_QUERY_PHYS: {
        struct mm_struct *mm = NULL;
        struct task_struct *task = NULL;
        
        ret = get_process_mm(pkt->target_pid, &mm, &task);
        if (ret < 0) {
            pkt->status = STATUS_INVALID_PID;
        } else {
            pkt->physical_addr = virtual_to_physical(mm, pkt->target_addr);
            if (pkt->physical_addr) {
                pkt->status = STATUS_SUCCESS;
                kpm_info("Physical: VA=0x%llX -> PA=0x%llX\n",
                         pkt->target_addr, pkt->physical_addr);
            } else {
                pkt->status = STATUS_PAGE_WALK_FAIL;
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
    
    if (ret == 0) {
        kpm_debug("Operation completed successfully\n");
    } else {
        kpm_err("Operation failed: status=0x%04X ret=%d\n", pkt->status, ret);
    }
    
out_copy:
    if (copy_to_user(user_data, pkt, sizeof(struct k_packet))) {
        kpm_err("copy_to_user failed on return\n");
        ret = -EFAULT;
    }
    
    atomic_dec(&module_refcount);
    
out_free:
    if (pkt) {
        kfree(pkt);
    }
    
    return ret;
}

static long kpm_memory_init(const char *args, const char *event, void *__user reserved)
{
    int ret;
    
    kpm_info("========================================\n");
    kpm_info("KPM Memory Debugger - Initializing\n");
    kpm_info("========================================\n");
    kpm_info("Version    : %s\n", HFR_VERSION);
    kpm_info("Author     : Surajit\n");
    kpm_info("Arch       : ARM64 (4-Level Page Tables)\n");
    kpm_info("Features   : VM R/W, MMU Walk, Physical Query\n");
    kpm_info("Max Size   : %u bytes per operation\n", MAX_TRANSFER_SIZE);
    kpm_info("========================================\n");
    
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
    
    memory_cleanup();
    module_initialized = false;
    
    kpm_info("========================================\n");
    kpm_info("UNLOADED SAFELY WITHOUT FREEZING !!!\n");
    kpm_info("========================================\n");
    
    return 0;
}

KPM_INIT(kpm_memory_init);
KPM_EXIT(kpm_memory_exit);
KPM_CTL0(kpm_memory_ctl0_handler);
