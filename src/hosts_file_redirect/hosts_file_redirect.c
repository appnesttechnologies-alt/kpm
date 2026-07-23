/* SPDX-License-Identifier: GPL-2.0-or-later */
/*
 * Copyright (C) 2026 Surajit. All Rights Reserved.
 * Single-File Self-Contained KPM Memory Debugger Module
 */

#include <compiler.h>
#include <hook.h>
#include <kpmodule.h>
#include <kputils.h>
#include <ksyms.h>
#include <linux/sched.h>
#include <linux/sched/mm.h>
#include <linux/slab.h>
#include <linux/errno.h>
#include <linux/printk.h>
#include <linux/string.h>

KPM_NAME("hosts_file_redirect");
KPM_VERSION(HFR_VERSION);
KPM_LICENSE("GPL v2");
KPM_AUTHOR("Surajit");
KPM_DESCRIPTION("Single-file self-contained kernel memory read/write debugger.");

#define KPM_PREFIX             "HFR_MEM"
#define kpm_info(fmt, ...)     pr_info(KPM_PREFIX ": " fmt, ##__VA_ARGS__)
#define kpm_err(fmt, ...)      pr_err(KPM_PREFIX ": " fmt, ##__VA_ARGS__)

/* Manual defines */
#define GFP_KERNEL  0xcc0
#define PAGE_SIZE   4096

/* Safety limits */
#define MAX_TRANSFER_SIZE     0x100000

/* Operation Codes */
#define OP_RESOLVE_BASE       0x1000
#define OP_READ_VM            0x2000
#define OP_WRITE_VM           0x3000
#define OP_QUERY_PHYS         0x4000

/* Status Codes */
#define STATUS_SUCCESS        0x0000
#define STATUS_INVALID_PID    0x1001
#define STATUS_INVALID_ADDR   0x1002
#define STATUS_ACCESS_DENIED  0x1003
#define STATUS_PAGE_FAULT     0x1004
#define STATUS_INVALID_SIZE   0x1005
#define STATUS_MMAP_LOCK_FAIL 0x1006
#define STATUS_PAGE_WALK_FAIL 0x1007
#define STATUS_MEM_ALLOC_FAIL 0x1008
#define STATUS_COPY_FAIL      0x1009
#define STATUS_MODULE_BUSY    0x1010

struct k_packet {
    uint32_t op_code;
    uint32_t target_pid;
    uint64_t user_buffer;
    uint64_t target_addr;
    uint64_t target_addr_end;
    uint32_t size;
    uint32_t status;
    uint64_t physical_addr;
    uint64_t resolved_base;
    uint32_t page_count;
    uint32_t reserved;
} __attribute__((aligned(8), packed));

/* Kernel function pointers */
typedef int (*access_process_vm_t)(struct task_struct *tsk, unsigned long addr,
                                   void *buf, int len, int write);
typedef struct task_struct *(*get_task_struct_t)(struct task_struct *t);
typedef void (*put_task_struct_t)(struct task_struct *t);

static access_process_vm_t access_process_vm_fn;
static get_task_struct_t get_task_struct_fn;
static put_task_struct_t put_task_struct_fn;

#define lookup_sym(func) \
    kfunc_lookup_name(func); \
    if (!kfunc(func)) { \
        kpm_err("Failed to resolve: " #func); \
        return -EFAULT; \
    }

static int read_process_memory(pid_t pid, unsigned long addr, void *buf, size_t size)
{
    struct task_struct *task;
    int ret;

    if (!buf || size == 0 || size > MAX_TRANSFER_SIZE)
        return -EINVAL;

    task = find_task_by_vpid(pid);
    if (!task)
        return -ESRCH;

    get_task_struct_fn(task);
    ret = access_process_vm_fn(task, addr, buf, size, 0);
    put_task_struct_fn(task);

    if (ret == 0) return -EFAULT;
    if (ret < 0) return ret;
    if (ret != size) return -EFAULT;
    return 0;
}

static int write_process_memory(pid_t pid, unsigned long addr, const void *buf, size_t size)
{
    struct task_struct *task;
    int ret;

    if (!buf || size == 0 || size > MAX_TRANSFER_SIZE)
        return -EINVAL;

    task = find_task_by_vpid(pid);
    if (!task)
        return -ESRCH;

    get_task_struct_fn(task);
    ret = access_process_vm_fn(task, addr, (void *)buf, size, 1);
    put_task_struct_fn(task);

    if (ret == 0) return -EFAULT;
    if (ret < 0) return ret;
    if (ret != size) return -EFAULT;
    return 0;
}

int handle_resolve_base(struct k_packet *pkt)
{
    pkt->status = STATUS_PAGE_WALK_FAIL;
    pkt->resolved_base = 0;
    return -ENOSYS;
}

int handle_memory_read(struct k_packet *pkt)
{
    void *kbuf;
    int ret;

    if (pkt->size == 0 || pkt->size > MAX_TRANSFER_SIZE) {
        pkt->status = STATUS_INVALID_SIZE;
        return -EINVAL;
    }

    kbuf = kmalloc(pkt->size, GFP_KERNEL);
    if (!kbuf) {
        pkt->status = STATUS_MEM_ALLOC_FAIL;
        return -ENOMEM;
    }

    ret = read_process_memory(pkt->target_pid, pkt->target_addr, kbuf, pkt->size);
    if (ret < 0) {
        if (ret == -ESRCH) pkt->status = STATUS_INVALID_PID;
        else if (ret == -EFAULT) pkt->status = STATUS_PAGE_FAULT;
        else pkt->status = STATUS_ACCESS_DENIED;
        kfree(kbuf);
        return ret;
    }

    if (compat_copy_to_user((void __user *)(unsigned long)pkt->user_buffer, kbuf, pkt->size)) {
        pkt->status = STATUS_COPY_FAIL;
        kfree(kbuf);
        return -EFAULT;
    }

    kfree(kbuf);
    pkt->status = STATUS_SUCCESS;
    pkt->page_count = (pkt->size + PAGE_SIZE - 1) / PAGE_SIZE;
    return 0;
}

int handle_memory_write(struct k_packet *pkt)
{
    void *kbuf;
    int ret;

    if (pkt->size == 0 || pkt->size > MAX_TRANSFER_SIZE) {
        pkt->status = STATUS_INVALID_SIZE;
        return -EINVAL;
    }

    kbuf = kmalloc(pkt->size, GFP_KERNEL);
    if (!kbuf) {
        pkt->status = STATUS_MEM_ALLOC_FAIL;
        return -ENOMEM;
    }

    if (compat_copy_to_user(kbuf, (void __user *)(unsigned long)pkt->user_buffer, pkt->size)) {
        pkt->status = STATUS_COPY_FAIL;
        kfree(kbuf);
        return -EFAULT;
    }

    ret = write_process_memory(pkt->target_pid, pkt->target_addr, kbuf, pkt->size);
    kfree(kbuf);

    if (ret < 0) {
        if (ret == -ESRCH) pkt->status = STATUS_INVALID_PID;
        else if (ret == -EFAULT) pkt->status = STATUS_PAGE_FAULT;
        else pkt->status = STATUS_ACCESS_DENIED;
        return ret;
    }

    pkt->status = STATUS_SUCCESS;
    pkt->page_count = (pkt->size + PAGE_SIZE - 1) / PAGE_SIZE;
    return 0;
}

int handle_query_phys(struct k_packet *pkt)
{
    pkt->status = STATUS_PAGE_WALK_FAIL;
    pkt->physical_addr = 0;
    return -ENOSYS;
}

static long hfr_control0(const char *ctl_args, char __user *out_msg, int outlen)
{
    struct k_packet *pkt;
    int ret = 0;

    if (!ctl_args || outlen < sizeof(struct k_packet))
        return -EINVAL;

    pkt = (struct k_packet *)ctl_args;

    switch (pkt->op_code) {
    case OP_RESOLVE_BASE:
        ret = handle_resolve_base(pkt);
        break;
    case OP_READ_VM:
        ret = handle_memory_read(pkt);
        break;
    case OP_WRITE_VM:
        ret = handle_memory_write(pkt);
        break;
    case OP_QUERY_PHYS:
        ret = handle_query_phys(pkt);
        break;
    default:
        pkt->status = STATUS_MODULE_BUSY;
        ret = -EINVAL;
        break;
    }

    if (compat_copy_to_user(out_msg, pkt, sizeof(struct k_packet)))
        return -EFAULT;

    return ret;
}

static long hfr_memory_init(const char *args, const char *event, void __user *reserved)
{
    /* Resolve all kfunc symbols that KPM framework needs */
    lookup_sym(kmalloc);
    lookup_sym(__kmalloc);
    lookup_sym(find_task_by_vpid);
    lookup_sym(kfree);

    /* Resolve other symbols via kallsyms directly */
    access_process_vm_fn = (access_process_vm_t)kallsyms_lookup_name("access_process_vm");
    get_task_struct_fn = (get_task_struct_t)kallsyms_lookup_name("get_task_struct");
    put_task_struct_fn = (put_task_struct_t)kallsyms_lookup_name("put_task_struct");

    if (!access_process_vm_fn || !get_task_struct_fn || !put_task_struct_fn) {
        kpm_err("Failed to resolve required kernel symbols\n");
        return -EFAULT;
    }

    kpm_info("HFR Memory Debugger Module Loaded Successfully!");
    return 0;
}

static long hfr_memory_exit(void __user *reserved)
{
    kpm_info("HFR Memory Debugger Module Unloaded Safely!");
    return 0;
}

KPM_INIT(hfr_memory_init);
KPM_CTL0(hfr_control0);
KPM_EXIT(hfr_memory_exit);
