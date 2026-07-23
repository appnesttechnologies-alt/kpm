/* SPDX-License-Identifier: GPL-2.0-or-later */
/*
 * Copyright (C) 2026 Surajit. All Rights Reserved.
 * Single-File Self-Contained KPM Memory Debugger Module
 * Fully self-contained – no conflicting kernel headers.
 */

#include <string.h>           /* strlen for kpm_utils */
#include <kpm_utils.h>        /* KPM macros */

/* ---------- Manual definitions (no system types) ---------- */
typedef unsigned long size_t;
typedef int pid_t;

#define NULL ((void*)0)

/* Error codes */
#define EFAULT    14
#define ESRCH      3
#define EINVAL    22
#define ENOMEM    12
#define ENOSYS    38

/* Flags for kmalloc */
#define GFP_KERNEL   0xcc0

/* Page size (4 KiB standard) */
#define PAGE_SIZE    4096

/* Forward declare kernel structures (only pointers used) */
struct task_struct;
struct mm_struct;

/* Module details for APatch framework */
KPM_NAME("hosts_file_redirect");
KPM_VERSION("1.1.8");
KPM_LICENSE("GPL v2");
KPM_AUTHOR("Surajit");
KPM_DESCRIPTION("Single-file self-contained kernel memory read/write debugger.");

/* Logging macros using resolved printk */
typedef int (*printk_t)(const char *fmt, ...);
static printk_t printk_fn;

#define kpm_info(fmt, ...)  printk_fn("HFR_MEM: " fmt "\n", ##__VA_ARGS__)
#define kpm_err(fmt, ...)   printk_fn("HFR_MEM: " fmt "\n", ##__VA_ARGS__)

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

/* ---------- Kernel function pointers (all via kallsyms) ---------- */
typedef struct task_struct *(*find_task_by_vpid_t)(pid_t nr);
typedef struct task_struct *(*get_task_struct_t)(struct task_struct *t);
typedef void                (*put_task_struct_t)(struct task_struct *t);
typedef struct mm_struct   *(*get_task_mm_t)(struct task_struct *task);
typedef void                (*mmput_t)(struct mm_struct *);
typedef int (*access_process_vm_t)(struct task_struct *tsk, unsigned long addr,
                                   void *buf, int len, int write);
typedef unsigned long (*copy_to_user_t)(void __user *to, const void *from, unsigned long n);
typedef unsigned long (*copy_from_user_t)(void *to, const void __user *from, unsigned long n);
typedef void *(*kmalloc_t)(size_t size, unsigned flags);
typedef void  (*kfree_t)(const void *);

static find_task_by_vpid_t   find_task_by_vpid_fn;
static get_task_struct_t     get_task_struct_fn;
static put_task_struct_t     put_task_struct_fn;
static get_task_mm_t         get_task_mm_fn;
static mmput_t               mmput_fn;
static access_process_vm_t   access_process_vm_fn;
static copy_to_user_t        copy_to_user_fn;
static copy_from_user_t      copy_from_user_fn;
static kmalloc_t             kmalloc_fn;
static kfree_t               kfree_fn;

/* ---------- Init: resolve symbols ---------- */
static int init_kallsyms_pointers(void)
{
    printk_fn = (printk_t) kallsyms_lookup_name("printk");
    find_task_by_vpid_fn = (find_task_by_vpid_t) kallsyms_lookup_name("find_task_by_vpid");
    get_task_struct_fn = (get_task_struct_t) kallsyms_lookup_name("get_task_struct");
    put_task_struct_fn = (put_task_struct_t) kallsyms_lookup_name("put_task_struct");
    get_task_mm_fn = (get_task_mm_t) kallsyms_lookup_name("get_task_mm");
    mmput_fn = (mmput_t) kallsyms_lookup_name("mmput");
    access_process_vm_fn = (access_process_vm_t) kallsyms_lookup_name("access_process_vm");
    copy_to_user_fn = (copy_to_user_t) kallsyms_lookup_name("copy_to_user");
    copy_from_user_fn = (copy_from_user_t) kallsyms_lookup_name("copy_from_user");
    kmalloc_fn = (kmalloc_t) kallsyms_lookup_name("kmalloc");
    kfree_fn = (kfree_t) kallsyms_lookup_name("kfree");

    if (!printk_fn || !find_task_by_vpid_fn || !get_task_struct_fn ||
        !put_task_struct_fn || !get_task_mm_fn || !mmput_fn ||
        !access_process_vm_fn || !copy_to_user_fn || !copy_from_user_fn ||
        !kmalloc_fn || !kfree_fn) {
        /* printk not resolved yet, but we'll try anyway */
        return -EFAULT;
    }
    return 0;
}

/* ---------- Memory helpers ---------- */
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
        return -EFAULT;
    if (ret < 0)
        return ret;
    if (ret != size)
        return -EFAULT;

    return 0;
}

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

/* ---------- Handlers ---------- */
int handle_resolve_base(struct k_packet *pkt)
{
    /* Base resolution disabled (no mm->start_code access) */
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

    kbuf = kmalloc_fn(pkt->size, GFP_KERNEL);
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
        kfree_fn(kbuf);
        return ret;
    }

    if (copy_to_user_fn((void *)(unsigned long)pkt->user_buffer, kbuf, pkt->size)) {
        pkt->status = STATUS_COPY_FAIL;
        kfree_fn(kbuf);
        return -EFAULT;
    }

    kfree_fn(kbuf);
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

    kbuf = kmalloc_fn(pkt->size, GFP_KERNEL);
    if (!kbuf) {
        pkt->status = STATUS_MEM_ALLOC_FAIL;
        return -ENOMEM;
    }

    if (copy_from_user_fn(kbuf, (void *)(unsigned long)pkt->user_buffer, pkt->size)) {
        pkt->status = STATUS_COPY_FAIL;
        kfree_fn(kbuf);
        return -EFAULT;
    }

    ret = write_process_memory(pkt->target_pid, pkt->target_addr, kbuf, pkt->size);
    kfree_fn(kbuf);

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
    pkt->status = STATUS_PAGE_WALK_FAIL;
    pkt->physical_addr = 0;
    return -ENOSYS;
}

/* ---------- KPM Init & Exit ---------- */
static long hfr_memory_init(const char *args, const char *event, void __user *reserved)
{
    int ret = init_kallsyms_pointers();
    if (ret) {
        /* Printk might be unavailable yet, but we try */
        return ret;
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
KPM_EXIT(hfr_memory_exit);
