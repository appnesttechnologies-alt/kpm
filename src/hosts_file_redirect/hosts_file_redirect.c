/* SPDX-License-Identifier: GPL-2.0-or-later */
/*
 * Copyright (C) 2026 Surajit. All Rights Reserved.
 * Single-File Self-Contained KPM Memory Debugger Module
 * Uses access_process_vm, kallsyms, and manual definitions.
 */

#include <string.h>               /* strlen() for kpm_utils.h */
#include <linux/printk.h>         /* pr_info, pr_err */
#include <linux/slab.h>           /* kmalloc, kfree */
#include <linux/mm.h>             /* struct page? not used directly */
#include <linux/mm_types.h>       /* struct mm_struct (opaque) */
#include <linux/sched.h>          /* task_struct (partial) */
#include <linux/pid.h>            /* pid_t */
#include <linux/kallsyms.h>       /* kallsyms_lookup_name */
#include <linux/errno.h>          /* EFAULT, ESRCH, EINVAL, ENOMEM, ENOSYS */
#include <linux/stddef.h>         /* NULL */
#include <kpm_utils.h>            /* KPM macros */

/* ---------- Manual definitions for missing constants ---------- */
#ifndef GFP_KERNEL
#define GFP_KERNEL  0xcc0
#endif

#ifndef PAGE_SIZE
#define PAGE_SIZE   (1UL << 12)    /* 4 KiB, standard for ARM64 */
#endif

#ifndef __user
#define __user
#endif

/* Module details for APatch framework */
KPM_NAME("hosts_file_redirect");
KPM_VERSION("1.1.8");
KPM_LICENSE("GPL v2");
KPM_AUTHOR("Surajit");
KPM_DESCRIPTION("Single-file self-contained kernel memory read/write debugger.");

#define KPM_PREFIX             "HFR_MEM"
#define kpm_info(fmt, ...)     pr_info(KPM_PREFIX ": " fmt, ##__VA_ARGS__)
#define kpm_err(fmt, ...)      pr_err(KPM_PREFIX ": " fmt, ##__VA_ARGS__)

/* Safety limits */
#define MAX_TRANSFER_SIZE     0x100000   /* 1 MiB */

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

/**
 * struct k_packet - Universal Data Packet
 */
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

/* ---------- Kernel function pointers resolved via kallsyms ---------- */
typedef struct task_struct *(*find_task_by_vpid_t)(pid_t nr);
typedef struct task_struct *(*get_task_struct_t)(struct task_struct *t);
typedef void                (*put_task_struct_t)(struct task_struct *t);
typedef struct mm_struct   *(*get_task_mm_t)(struct task_struct *task);
typedef void                (*mmput_t)(struct mm_struct *);
typedef int (*access_process_vm_t)(struct task_struct *tsk, unsigned long addr,
                                   void *buf, int len, int write);
typedef unsigned long (*copy_to_user_t)(void __user *to, const void *from, unsigned long n);
typedef unsigned long (*copy_from_user_t)(void *to, const void __user *from, unsigned long n);

static find_task_by_vpid_t   find_task_by_vpid_fn;
static get_task_struct_t     get_task_struct_fn;
static put_task_struct_t     put_task_struct_fn;
static get_task_mm_t         get_task_mm_fn;
static mmput_t               mmput_fn;
static access_process_vm_t   access_process_vm_fn;
static copy_to_user_t        copy_to_user_fn;
static copy_from_user_t      copy_from_user_fn;

/* ---------- Initialization ---------- */
static int init_kallsyms_pointers(void)
{
    find_task_by_vpid_fn = (find_task_by_vpid_t)
        kallsyms_lookup_name("find_task_by_vpid");
    get_task_struct_fn = (get_task_struct_t)
        kallsyms_lookup_name("get_task_struct");
    put_task_struct_fn = (put_task_struct_t)
        kallsyms_lookup_name("put_task_struct");
    get_task_mm_fn = (get_task_mm_t)
        kallsyms_lookup_name("get_task_mm");
    mmput_fn = (mmput_t)
        kallsyms_lookup_name("mmput");
    access_process_vm_fn = (access_process_vm_t)
        kallsyms_lookup_name("access_process_vm");
    copy_to_user_fn = (copy_to_user_t)
        kallsyms_lookup_name("copy_to_user");
    copy_from_user_fn = (copy_from_user_t)
        kallsyms_lookup_name("copy_from_user");

    if (!find_task_by_vpid_fn || !get_task_struct_fn ||
        !put_task_struct_fn || !get_task_mm_fn ||
        !mmput_fn || !access_process_vm_fn ||
        !copy_to_user_fn || !copy_from_user_fn) {
        kpm_err("Failed to resolve all required kernel symbols\n");
        return -EFAULT;
    }
    return 0;
}

/* ---------- Core memory operations ---------- */

/**
 * read_process_memory – read remote memory using access_process_vm.
 * Returns 0 on success, -ESRCH, -EFAULT, etc.
 */
static int read_process_memory(pid_t pid, unsigned long addr, void *buf, size_t size)
{
    struct task_struct *task;
    int ret;

    if (!buf || size == 0 || size > MAX_TRANSFER_SIZE)
        return -EINVAL;

    task = find_task_by_vpid_fn(pid);
    if (!task)
        return -ESRCH;

    get_task_struct_fn(task);
    ret = access_process_vm_fn(task, addr, buf, size, 0); /* 0 = read */
    put_task_struct_fn(task);

    if (ret == 0)
        return -EFAULT;   /* complete failure */
    if (ret < 0)
        return ret;
    if (ret != size)
        return -EFAULT;   /* partial read */

    return 0;
}

/**
 * write_process_memory – write remote memory using access_process_vm.
 * Returns 0 on success.
 */
static int write_process_memory(pid_t pid, unsigned long addr, const void *buf, size_t size)
{
    struct task_struct *task;
    int ret;

    if (!buf || size == 0 || size > MAX_TRANSFER_SIZE)
        return -EINVAL;

    task = find_task_by_vpid_fn(pid);
    if (!task)
        return -ESRCH;

    get_task_struct_fn(task);
    ret = access_process_vm_fn(task, addr, (void *)buf, size, 1); /* 1 = write */
    put_task_struct_fn(task);

    if (ret == 0)
        return -EFAULT;
    if (ret < 0)
        return ret;
    if (ret != size)
        return -EFAULT;

    return 0;
}

/* ---------- Handlers for each opcode ---------- */

int handle_resolve_base(struct k_packet *pkt)
{
    /* mm->start_code not accessible in this environment; stub */
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
        if (ret == -ESRCH)
            pkt->status = STATUS_INVALID_PID;
        else if (ret == -EFAULT)
            pkt->status = STATUS_PAGE_FAULT;
        else
            pkt->status = STATUS_ACCESS_DENIED;
        kfree(kbuf);
        return ret;
    }

    /* Copy to caller's user-space buffer */
    if (copy_to_user_fn((void __user *)(unsigned long)pkt->user_buffer, kbuf, pkt->size)) {
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

    /* Get data from caller's buffer */
    if (copy_from_user_fn(kbuf, (void __user *)(unsigned long)pkt->user_buffer, pkt->size)) {
        pkt->status = STATUS_COPY_FAIL;
        kfree(kbuf);
        return -EFAULT;
    }

    ret = write_process_memory(pkt->target_pid, pkt->target_addr, kbuf, pkt->size);
    kfree(kbuf);

    if (ret < 0) {
        if (ret == -ESRCH)
            pkt->status = STATUS_INVALID_PID;
        else if (ret == -EFAULT)
            pkt->status = STATUS_PAGE_FAULT;
        else
            pkt->status = STATUS_ACCESS_DENIED;
        return ret;
    }

    pkt->status = STATUS_SUCCESS;
    pkt->page_count = (pkt->size + PAGE_SIZE - 1) / PAGE_SIZE;
    return 0;
}

int handle_query_phys(struct k_packet *pkt)
{
    /* Physical address query not supported without pgtable types */
    pkt->status = STATUS_PAGE_WALK_FAIL;
    pkt->physical_addr = 0;
    return -ENOSYS;
}

/* ---------- KPM Init & Exit ---------- */

static long hfr_memory_init(const char *args, const char *event, void __user *reserved)
{
    int ret = init_kallsyms_pointers();
    if (ret) {
        kpm_err("Symbol resolution failed, module not loaded\n");
        return ret;
    }
    kpm_info("HFR Memory Debugger Module Loaded Successfully!\n");
    return 0;
}

static long hfr_memory_exit(void __user *reserved)
{
    kpm_info("HFR Memory Debugger Module Unloaded Safely!\n");
    return 0;
}

KPM_INIT(hfr_memory_init);
KPM_EXIT(hfr_memory_exit);
