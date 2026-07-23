/* SPDX-License-Identifier: GPL-2.0-or-later */
/* 
 * Copyright (C) 2026 Surajit. All Rights Reserved.
 * Single-File Self-Contained KPM Memory Debugger Module
 * Real implementation with userspace /dev/hfr_mem interface.
 */

#include <linux/init.h>
#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/printk.h>
#include <linux/string.h>
#include <linux/slab.h>
#include <linux/uaccess.h>
#include <linux/sched.h>
#include <linux/mm.h>
#include <linux/pid.h>
#include <linux/version.h>
#include <linux/miscdevice.h>
#include <linux/fs.h>
#include <linux/mm_types.h>
#include <linux/highmem.h>
#include <linux/pagemap.h>
#include <linux/rmap.h>
#include <asm/pgtable.h>
#include <kpm_utils.h>

/* Module details for APatch framework */
KPM_NAME("hosts_file_redirect");
KPM_VERSION("1.1.8");
KPM_LICENSE("GPL v2");
KPM_AUTHOR("Surajit");
KPM_DESCRIPTION("Single-file self-contained kernel memory read/write debugger.");

#define KPM_PREFIX             "HFR_MEM"
#define kpm_info(fmt, ...)     pr_info(KPM_PREFIX ": " fmt, ##__VA_ARGS__)
#define kpm_err(fmt, ...)      pr_err(KPM_PREFIX ": " fmt, ##__VA_ARGS__)

/* Explicit kernel definitions & macros for NDK compilation compatibility */
#ifndef GFP_KERNEL
#define GFP_KERNEL 0xcc0
#endif

#ifndef __user
#define __user
#endif

/* Operation Codes */
#define OP_RESOLVE_BASE    0x1000
#define OP_READ_VM         0x2000
#define OP_WRITE_VM        0x3000
#define OP_QUERY_PHYS      0x4000

/* Status Codes */
#define STATUS_SUCCESS          0x0000
#define STATUS_INVALID_PID      0x1001
#define STATUS_INVALID_ADDR     0x1002
#define STATUS_ACCESS_DENIED    0x1003
#define STATUS_PAGE_FAULT       0x1004
#define STATUS_INVALID_SIZE     0x1005
#define STATUS_MMAP_LOCK_FAIL   0x1006
#define STATUS_PAGE_WALK_FAIL   0x1007
#define STATUS_MEM_ALLOC_FAIL   0x1008
#define STATUS_COPY_FAIL        0x1009
#define STATUS_MODULE_BUSY      0x1010

/* Safety limits */
#define MAX_TRANSFER_SIZE      0x100000  /* 1 MiB */

/**
 * struct k_packet - Universal Data Packet
 */
struct k_packet {
    uint32_t op_code;
    uint32_t target_pid;
    uint64_t user_buffer;
    uint64_t target_addr;
    uint64_t target_addr_end;   /* optional (not used) */
    uint32_t size;
    uint32_t status;
    uint64_t physical_addr;
    uint64_t resolved_base;
    uint32_t page_count;
    uint32_t reserved;
} __attribute__((aligned(8), packed));

/* ---------- Internal kernel helpers (no externs) ---------- */

/**
 * get_process_mm - get mm_struct of a given pid
 * @pid: process ID
 * @mm:  output mm (referenced)
 * @task: output task (referenced, must be put by caller)
 * Returns 0 on success, -ESRCH if pid not found.
 */
static int get_process_mm(pid_t pid, struct mm_struct **mm, struct task_struct **task)
{
    struct task_struct *t;
    struct mm_struct *m;

    rcu_read_lock();
    t = find_task_by_vpid(pid);
    if (!t) {
        rcu_read_unlock();
        return -ESRCH;
    }
    get_task_struct(t);
    rcu_read_unlock();

    m = get_task_mm(t);
    if (!m) {
        put_task_struct(t);
        return -ESRCH; /* task has no mm (kernel thread or zombie) */
    }
    *mm = m;
    *task = t;
    return 0;
}

/**
 * put_process_mm - release mm and task references
 */
static void put_process_mm(struct mm_struct *mm)
{
    mmput(mm);
}

/* Put task separately if needed */
static void put_process_task(struct task_struct *task)
{
    put_task_struct(task);
}

/**
 * validate_user_address - check if a user address range is safe to access
 * @mm: target mm
 * @addr: start virtual address
 * @size: length in bytes
 * Returns 0 if safe, -EFAULT otherwise.
 */
static int validate_user_address(struct mm_struct *mm, unsigned long addr, unsigned long size)
{
    unsigned long end = addr + size;

    /* Must be user address */
    if (addr >= TASK_SIZE || end > TASK_SIZE || end < addr)
        return -EFAULT;

    /* If mm is the current->mm we could check access_ok.
     * For remote mm we just verify the VMA exists and is accessible.
     */
    if (mm) {
        struct vm_area_struct *vma;
        mmap_read_lock(mm);
        vma = find_vma(mm, addr);
        if (!vma || vma->vm_start > addr) {
            mmap_read_unlock(mm);
            return -EFAULT;
        }
        /* Check that the whole range stays inside the first VMA.
         * More thorough would be to iterate, but this is enough for basic safety.
         */
        if (addr + size > vma->vm_end) {
            mmap_read_unlock(mm);
            return -EFAULT;
        }
        /* Avoid kernel or write-protect not handled here */
        mmap_read_unlock(mm);
    }
    return 0;
}

/**
 * virtual_to_physical - translate virtual address to physical for a given mm
 * @mm: target mm
 * @vaddr: virtual address
 * @phys: output physical address (0 if failed)
 * Returns 0 on success, -EFAULT if not present.
 * Must be called with mmap locked (read or write).
 */
static int __virtual_to_physical(struct mm_struct *mm, unsigned long vaddr,
                                 unsigned long *phys)
{
    pgd_t *pgd;
    p4d_t *p4d;
    pud_t *pud;
    pmd_t *pmd;
    pte_t *pte;
    unsigned long pfn = 0;
    unsigned long offset = vaddr & (PAGE_SIZE - 1);

    pgd = pgd_offset(mm, vaddr);
    if (pgd_none(*pgd) || pgd_bad(*pgd))
        return -EFAULT;
    p4d = p4d_offset(pgd, vaddr);
    if (p4d_none(*p4d) || p4d_bad(*p4d))
        return -EFAULT;
    pud = pud_offset(p4d, vaddr);
    if (pud_none(*pud) || pud_bad(*pud))
        return -EFAULT;
    pmd = pmd_offset(pud, vaddr);
    if (pmd_none(*pmd) || pmd_bad(*pmd))
        return -EFAULT;
    pte = pte_offset_map(pmd, vaddr);
    if (!pte)
        return -EFAULT;
    if (!pte_present(*pte)) {
        pte_unmap(pte);
        return -EFAULT;
    }
    pfn = pte_pfn(*pte);
    pte_unmap(pte);
    *phys = (pfn << PAGE_SHIFT) + offset;
    return 0;
}

/**
 * virtual_to_physical_wrapper - safe wrapper with mmap lock
 */
static int virtual_to_physical(struct mm_struct *mm, unsigned long vaddr,
                               unsigned long *phys)
{
    int ret;
    mmap_read_lock(mm);
    ret = __virtual_to_physical(mm, vaddr, phys);
    mmap_read_unlock(mm);
    return ret;
}

/**
 * read_process_memory - read memory of a remote process
 * @pid: target pid
 * @addr: user virtual address in target
 * @buf:  kernel buffer to fill
 * @size: bytes to read
 * Returns 0 on success, negative error.
 *
 * Temporarily uses the target mm to allow copy_from_user.
 */
static int read_process_memory(pid_t pid, unsigned long addr, void *buf, size_t size)
{
    struct task_struct *task;
    struct mm_struct *mm;
    int ret;

    ret = get_process_mm(pid, &mm, &task);
    if (ret < 0)
        return ret;

    if (!buf || size == 0 || size > MAX_TRANSFER_SIZE) {
        put_process_mm(mm);
        put_task_struct(task);
        return -EINVAL;
    }

    ret = validate_user_address(mm, addr, size);
    if (ret < 0) {
        put_process_mm(mm);
        put_task_struct(task);
        return ret;
    }

    /* Borrow the target mm */
#if LINUX_VERSION_CODE >= KERNEL_VERSION(5, 8, 0)
    kthread_use_mm(mm);
#else
    use_mm(mm);
#endif
    /* Now we are in target's address space */
    if (copy_from_user(buf, (void __user *)addr, size)) {
        ret = -EFAULT;
    } else {
        ret = 0;
    }
#if LINUX_VERSION_CODE >= KERNEL_VERSION(5, 8, 0)
    kthread_unuse_mm(mm);
#else
    unuse_mm(mm);
#endif

    put_process_mm(mm);
    put_task_struct(task);
    return ret;
}

/**
 * write_process_memory - write memory of a remote process
 * @pid: target pid
 * @addr: user virtual address in target
 * @buf:  kernel buffer containing data
 * @size: bytes to write
 * Returns 0 on success, negative error.
 */
static int write_process_memory(pid_t pid, unsigned long addr, const void *buf, size_t size)
{
    struct task_struct *task;
    struct mm_struct *mm;
    int ret;

    ret = get_process_mm(pid, &mm, &task);
    if (ret < 0)
        return ret;

    if (!buf || size == 0 || size > MAX_TRANSFER_SIZE) {
        put_process_mm(mm);
        put_task_struct(task);
        return -EINVAL;
    }

    ret = validate_user_address(mm, addr, size);
    if (ret < 0) {
        put_process_mm(mm);
        put_task_struct(task);
        return ret;
    }

#if LINUX_VERSION_CODE >= KERNEL_VERSION(5, 8, 0)
    kthread_use_mm(mm);
#else
    use_mm(mm);
#endif
    if (copy_to_user((void __user *)addr, buf, size)) {
        ret = -EFAULT;
    } else {
        ret = 0;
    }
#if LINUX_VERSION_CODE >= KERNEL_VERSION(5, 8, 0)
    kthread_unuse_mm(mm);
#else
    unuse_mm(mm);
#endif

    put_process_mm(mm);
    put_task_struct(task);
    return ret;
}

/**
 * resolve_base_address - get the main executable code base of a process
 * @pid: target pid
 * @base: output base address
 * Returns 0 on success.
 */
static int resolve_base_address(pid_t pid, unsigned long *base)
{
    struct task_struct *task;
    struct mm_struct *mm;
    int ret;

    ret = get_process_mm(pid, &mm, &task);
    if (ret < 0)
        return ret;

    *base = mm->start_code;   /* start of code segment */
    put_process_mm(mm);
    put_task_struct(task);
    return 0;
}

/* ---------- Handlers for ioctl commands ---------- */

static int handle_resolve_base(struct k_packet *pkt)
{
    unsigned long base = 0;
    int ret;

    ret = resolve_base_address(pkt->target_pid, &base);
    if (ret < 0) {
        pkt->status = STATUS_INVALID_PID;
        return ret;
    }
    pkt->resolved_base = base;
    pkt->status = STATUS_SUCCESS;
    return 0;
}

static int handle_memory_read(struct k_packet *pkt)
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

    ret = read_process_memory(pkt->target_pid, (unsigned long)pkt->target_addr,
                              kbuf, pkt->size);
    if (ret < 0) {
        if (ret == -EFAULT)
            pkt->status = STATUS_PAGE_FAULT;
        else if (ret == -ESRCH)
            pkt->status = STATUS_INVALID_PID;
        else
            pkt->status = STATUS_ACCESS_DENIED;
        kfree(kbuf);
        return ret;
    }

    /* Copy to user buffer provided in pkt->user_buffer (caller's address space) */
    if (copy_to_user((void __user *)(unsigned long)pkt->user_buffer, kbuf, pkt->size)) {
        pkt->status = STATUS_COPY_FAIL;
        kfree(kbuf);
        return -EFAULT;
    }

    kfree(kbuf);
    pkt->status = STATUS_SUCCESS;
    pkt->page_count = (pkt->size + PAGE_SIZE - 1) / PAGE_SIZE;
    return 0;
}

static int handle_memory_write(struct k_packet *pkt)
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
    if (copy_from_user(kbuf, (void __user *)(unsigned long)pkt->user_buffer, pkt->size)) {
        pkt->status = STATUS_COPY_FAIL;
        kfree(kbuf);
        return -EFAULT;
    }

    ret = write_process_memory(pkt->target_pid, (unsigned long)pkt->target_addr,
                               kbuf, pkt->size);
    kfree(kbuf);

    if (ret < 0) {
        if (ret == -EFAULT)
            pkt->status = STATUS_PAGE_FAULT;
        else if (ret == -ESRCH)
            pkt->status = STATUS_INVALID_PID;
        else
            pkt->status = STATUS_ACCESS_DENIED;
        return ret;
    }

    pkt->status = STATUS_SUCCESS;
    pkt->page_count = (pkt->size + PAGE_SIZE - 1) / PAGE_SIZE;
    return 0;
}

static int handle_query_phys(struct k_packet *pkt)
{
    struct task_struct *task;
    struct mm_struct *mm;
    unsigned long phys = 0;
    int ret;

    ret = get_process_mm(pkt->target_pid, &mm, &task);
    if (ret < 0) {
        pkt->status = STATUS_INVALID_PID;
        return ret;
    }

    ret = validate_user_address(mm, (unsigned long)pkt->target_addr, 1);
    if (ret < 0) {
        pkt->status = STATUS_INVALID_ADDR;
        put_process_mm(mm);
        put_task_struct(task);
        return ret;
    }

    ret = virtual_to_physical(mm, (unsigned long)pkt->target_addr, &phys);
    if (ret < 0) {
        pkt->status = STATUS_PAGE_FAULT;
        put_process_mm(mm);
        put_task_struct(task);
        return ret;
    }

    pkt->physical_addr = phys;
    pkt->status = STATUS_SUCCESS;
    put_process_mm(mm);
    put_task_struct(task);
    return 0;
}

/* ---------- Character device interface ---------- */

static long hfr_ioctl(struct file *file, unsigned int cmd, unsigned long arg)
{
    struct k_packet kpkt;
    int ret;

    if (cmd != 0x5001)   /* magic ioctl command; can be any number */
        return -ENOTTY;

    if (copy_from_user(&kpkt, (void __user *)arg, sizeof(kpkt)))
        return -EFAULT;

    switch (kpkt.op_code) {
    case OP_RESOLVE_BASE:
        ret = handle_resolve_base(&kpkt);
        break;
    case OP_READ_VM:
        ret = handle_memory_read(&kpkt);
        break;
    case OP_WRITE_VM:
        ret = handle_memory_write(&kpkt);
        break;
    case OP_QUERY_PHYS:
        ret = handle_query_phys(&kpkt);
        break;
    default:
        kpkt.status = STATUS_MODULE_BUSY;
        ret = -EINVAL;
        break;
    }

    if (copy_to_user((void __user *)arg, &kpkt, sizeof(kpkt)))
        return -EFAULT;

    return ret;
}

static const struct file_operations hfr_fops = {
    .owner = THIS_MODULE,
    .unlocked_ioctl = hfr_ioctl,
    .compat_ioctl = hfr_ioctl,   /* for 32-bit userspace on 64-bit kernel */
};

static struct miscdevice hfr_miscdev = {
    .minor = MISC_DYNAMIC_MINOR,
    .name = "hfr_mem",
    .fops = &hfr_fops,
};

/* ---------- APatch KPM Init/Exit ---------- */

static long hfr_memory_init(const char *args, const char *event, void __user *reserved)
{
    int ret;
    ret = misc_register(&hfr_miscdev);
    if (ret) {
        kpm_err("Failed to register misc device /dev/hfr_mem\n");
        return ret;
    }
    kpm_info("HFR Memory Debugger Module Loaded Successfully! Device: /dev/hfr_mem\n");
    return 0;
}

static long hfr_memory_exit(void __user *reserved)
{
    misc_deregister(&hfr_miscdev);
    kpm_info("HFR Memory Debugger Module Unloaded Safely!\n");
    return 0;
}

/* Register APatch Framework Hooks */
KPM_INIT(hfr_memory_init);
KPM_EXIT(hfr_memory_exit);

/* End of file */
