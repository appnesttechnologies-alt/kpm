/* SPDX-License-Identifier: GPL-2.0-or-later */
/* 
 * Copyright (C) 2026 Surajit. All Rights Reserved.
 * KPM Memory Debugger - Main Module
 */

#include "framework.h"

/* APatch required includes */
#include <linux/printk.h>
#include <linux/string.h>
#include <linux/slab.h>
#include <linux/uaccess.h>
#include <linux/sched.h>
#include <linux/mm.h>
#include <linux/pid.h>
#include <asm/pgtable.h>
#include <linux/pagemap.h>
#include <linux/rwsem.h>
#include <kpm_utils.h>

/* APatch Module Metadata */
KPM_NAME("kpm_memory_debugger");
KPM_VERSION(HFR_VERSION);
KPM_LICENSE("GPL v2");
KPM_AUTHOR("Surajit");
KPM_DESCRIPTION("Cross-Process Memory Debugger with MMU Page Table Walk and R/W");

#define kpm_info(fmt, ...)  pr_info(KPM_PREFIX ": " fmt, ##__VA_ARGS__)
#define kpm_err(fmt, ...)   pr_err(KPM_PREFIX ": " fmt, ##__VA_ARGS__)
#define kpm_debug(fmt, ...) pr_info(KPM_PREFIX ": " fmt, ##__VA_ARGS__)
#define kpm_warn(fmt, ...)  pr_warn(KPM_PREFIX ": " fmt, ##__VA_ARGS__)

/* Simple spinlock for synchronization */
struct kpm_spinlock {
    int locked;
};

static inline void kpm_spin_lock(struct kpm_spinlock *lock)
{
    while (__sync_lock_test_and_set(&lock->locked, 1))
        ;
}

static inline void kpm_spin_unlock(struct kpm_spinlock *lock)
{
    __sync_lock_release(&lock->locked);
}

/* Global state */
static struct kpm_spinlock ctl0_lock = {0};
static int module_refcount = 0;
static bool module_initialized = false;

/* Forward declarations */
int memory_initialize(void);
void memory_cleanup(void);
int handle_memory_read(struct k_packet *pkt);
int handle_memory_write(struct k_packet *pkt);
int resolve_process_base(struct k_packet *pkt);

static bool validate_packet(const struct k_packet *pkt)
{
    if (pkt->op_code < OP_RESOLVE_BASE || pkt->op_code > OP_QUERY_PHYS) {
        kpm_err("Invalid op_code: 0x%04X\n", pkt->op_code);
        return false;
    }
    
    if (pkt->target_pid == 0) {
        kpm_err("Invalid target_pid: %u\n", pkt->target_pid);
        return false;
    }
    
    if ((pkt->op_code == OP_READ_VM || pkt->op_code == OP_WRITE_VM) &&
        (pkt->size == 0 || pkt->size > MAX_TRANSFER_SIZE)) {
        kpm_err("Invalid transfer size: %u\n", pkt->size);
        return false;
    }
    
    return true;
}

static long kpm_memory_ctl0_handler(void __user *user_data, size_t user_size)
{
    struct k_packet pkt;
    int ret = 0;
    struct mm_struct *mm = NULL;
    struct task_struct *task = NULL;
    
    if (!user_data || user_size != sizeof(struct k_packet)) {
        kpm_err("Invalid CTL0 call - size: %zu\n", user_size);
        return -EINVAL;
    }
    
    if (copy_from_user(&pkt, user_data, sizeof(struct k_packet))) {
        kpm_err("copy_from_user failed\n");
        return -EFAULT;
    }
    
    if (!validate_packet(&pkt)) {
        pkt.status = STATUS_INVALID_SIZE;
        ret = -EINVAL;
        goto out_copy;
    }
    
    kpm_spin_lock(&ctl0_lock);
    module_refcount++;
    
    kpm_info("Request: OP=0x%04X PID=%u ADDR=0x%llX SIZE=%u\n",
             pkt.op_code, pkt.target_pid, pkt.target_addr, pkt.size);
    
    switch (pkt.op_code) {
    case OP_RESOLVE_BASE:
        ret = resolve_process_base(&pkt);
        break;
        
    case OP_READ_VM:
        ret = handle_memory_read(&pkt);
        break;
        
    case OP_WRITE_VM:
        ret = handle_memory_write(&pkt);
        break;
        
    case OP_QUERY_PHYS:
        ret = get_process_mm(pkt.target_pid, &mm, &task);
        if (ret < 0) {
            pkt.status = STATUS_INVALID_PID;
            kpm_err("Cannot get process MM for PID %u\n", pkt.target_pid);
        } else {
            pkt.physical_addr = virtual_to_physical(mm, pkt.target_addr);
            if (pkt.physical_addr) {
                pkt.status = STATUS_SUCCESS;
                kpm_info("Physical: VA=0x%llX -> PA=0x%llX\n",
                         pkt.target_addr, pkt.physical_addr);
            } else {
                pkt.status = STATUS_PAGE_WALK_FAIL;
                ret = -EINVAL;
            }
            put_process_mm(mm);
        }
        break;
        
    default:
        kpm_err("Unknown op_code: 0x%04X\n", pkt.op_code);
        pkt.status = STATUS_INVALID_SIZE;
        ret = -EINVAL;
        break;
    }
    
    module_refcount--;
    kpm_spin_unlock(&ctl0_lock);
    
out_copy:
    if (copy_to_user(user_data, &pkt, sizeof(struct k_packet))) {
        kpm_err("copy_to_user failed on return\n");
        ret = -EFAULT;
    }
    
    return ret;
}

static long kpm_memory_init(const char *args, const char *event, void *__user reserved)
{
    int ret;
    
    kpm_info("========================================\n");
    kpm_info("KPM Memory Debugger v%s - Surajit\n", HFR_VERSION);
    kpm_info("ARM64 MMU Walk + VM R/W + Physical Query\n");
    kpm_info("========================================\n");
    
    ret = memory_initialize();
    if (ret < 0) {
        kpm_err("Init failed: %d\n", ret);
        return ret;
    }
    
    module_initialized = true;
    kpm_info("READY FOR PROFILING !!!\n");
    
    return 0;
}

static long kpm_memory_exit(void *__user reserved)
{
    kpm_info("Shutting down...\n");
    
    if (module_initialized) {
        memory_cleanup();
        module_initialized = false;
    }
    
    kpm_info("UNLOADED SAFELY !!!\n");
    return 0;
}

KPM_INIT(kpm_memory_init);
KPM_EXIT(kpm_memory_exit);
KPM_CTL0(kpm_memory_ctl0_handler);
