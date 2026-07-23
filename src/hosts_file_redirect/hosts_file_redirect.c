/* SPDX-License-Identifier: GPL-2.0-or-later */
/*
 * Copyright (C) 2026 Surajit. All Rights Reserved.
 * Single-File Self-Contained KPM Memory Debugger Module
 * Real implementation using page-table walk, kmap, and kallsyms.
 */

#include <linux/printk.h>      /* pr_info, pr_err */
#include <linux/slab.h>        /* kmalloc, kfree */
#include <linux/gfp.h>         /* GFP_KERNEL */
#include <linux/mm.h>          /* struct page, get_page, put_page, vm_area_struct */
#include <linux/mm_types.h>    /* mm_struct, pgd_t, p4d_t, pud_t, pmd_t, pte_t */
#include <pgtable.h>     /* pgd_offset, p4d_offset, pud_offset, pmd_offset, pte_offset_map */
#include <linux/sched.h>       /* struct task_struct (partial) */
#include <linux/pid.h>         /* pid_t */
#include <linux/kallsyms.h>    /* kallsyms_lookup_name */
#include <linux/err.h>         /* IS_ERR, PTR_ERR */
#include <linux/stddef.h>      /* offsetof */
#include <kpm_utils.h>         /* KPM macros, maybe kpm_utils.h or kpmodule.h – adjust if needed */

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

/* ---------- Kernel function pointers obtained via kallsyms ---------- */
typedef struct task_struct *(*find_task_by_vpid_t)(pid_t nr);
typedef struct mm_struct   *(*get_task_mm_t)(struct task_struct *task);
typedef void                (*mmput_t)(struct mm_struct *);
typedef void                (*mmap_read_lock_t)(struct mm_struct *);
typedef void                (*mmap_read_unlock_t)(struct mm_struct *);
typedef struct vm_area_struct *(*find_vma_t)(struct mm_struct *, unsigned long addr);
typedef void                (*set_page_dirty_t)(struct page *page);
typedef void                (*flush_dcache_page_t)(struct page *page);

static find_task_by_vpid_t   find_task_by_vpid_fn;
static get_task_mm_t         get_task_mm_fn;
static mmput_t               mmput_fn;
static mmap_read_lock_t      mmap_read_lock_fn;
static mmap_read_unlock_t    mmap_read_unlock_fn;
static find_vma_t            find_vma_fn;
static set_page_dirty_t      set_page_dirty_fn;
static flush_dcache_page_t   flush_dcache_page_fn;

/* ---------- Internal helpers ---------- */

/**
 * init_kallsyms_pointers - resolve all needed kernel symbols at init.
 */
static int init_kallsyms_pointers(void)
{
    find_task_by_vpid_fn = (find_task_by_vpid_t)
        kallsyms_lookup_name("find_task_by_vpid");
    get_task_mm_fn = (get_task_mm_t)
        kallsyms_lookup_name("get_task_mm");
    mmput_fn = (mmput_t)
        kallsyms_lookup_name("mmput");
    mmap_read_lock_fn = (mmap_read_lock_t)
        kallsyms_lookup_name("mmap_read_lock");
    mmap_read_unlock_fn = (mmap_read_unlock_t)
        kallsyms_lookup_name("mmap_read_unlock");
    find_vma_fn = (find_vma_t)
        kallsyms_lookup_name("find_vma");
    set_page_dirty_fn = (set_page_dirty_t)
        kallsyms_lookup_name("set_page_dirty");
    flush_dcache_page_fn = (flush_dcache_page_t)
        kallsyms_lookup_name("flush_dcache_page");

    if (!find_task_by_vpid_fn || !get_task_mm_fn || !mmput_fn ||
        !mmap_read_lock_fn || !mmap_read_unlock_fn || !find_vma_fn ||
        !set_page_dirty_fn || !flush_dcache_page_fn) {
        kpm_err("Failed to resolve all required kernel symbols\n");
        return -EFAULT;
    }
    return 0;
}

/**
 * get_process_mm - obtain mm and task references for a pid.
 * Returns 0 on success, -ESRCH if not found.
 */
static int get_process_mm(pid_t pid, struct mm_struct **mm, struct task_struct **task)
{
    struct task_struct *t;

    t = find_task_by_vpid_fn(pid);
    if (!t)
        return -ESRCH;

    get_task_struct(t);   /* we still need the built-in get_task_struct */
    *task = t;

    *mm = get_task_mm_fn(t);
    if (!*mm) {
        put_task_struct(t);
        return -ESRCH;
    }
    return 0;
}

static void put_process_mm(struct mm_struct *mm)
{
    mmput_fn(mm);
}

static void put_process_task(struct task_struct *task)
{
    put_task_struct(task);
}

/**
 * validate_user_address - check that the whole [addr, addr+size) lies inside a
 * single user VMA and is accessible.
 * Returns 0 if valid, -EFAULT otherwise.
 */
static int validate_user_address(struct mm_struct *mm, unsigned long addr, size_t size)
{
    struct vm_area_struct *vma;
    unsigned long end = addr + size;

    if (addr >= TASK_SIZE || end > TASK_SIZE || end < addr)
        return -EFAULT;

    mmap_read_lock_fn(mm);
    vma = find_vma_fn(mm, addr);
    if (!vma || vma->vm_start > addr || addr + size > vma->vm_end) {
        mmap_read_unlock_fn(mm);
        return -EFAULT;
    }
    mmap_read_unlock_fn(mm);
    return 0;
}

/**
 * walk_and_access_memory – read or write memory in a remote mm using kmap.
 * @mm:      target mm (must already be locked with mmap_read_lock)
 * @vaddr:   user virtual address in target
 * @buf:     kernel buffer (src for write, dst for read)
 * @size:    bytes to transfer
 * @write:   1 for write, 0 for read
 * Returns 0 on success, -EFAULT on error.
 *
 * CAUTION: mmap_read_lock() must be held by the caller.
 */
static int walk_and_access_memory(struct mm_struct *mm, unsigned long vaddr,
                                  void *buf, size_t size, int write)
{
    unsigned long offset = vaddr & ~PAGE_MASK;
    unsigned long remaining = size;
    unsigned char *kern_buf = buf;

    while (remaining > 0) {
        pgd_t *pgd;
        p4d_t *p4d;
        pud_t *pud;
        pmd_t *pmd;
        pte_t *pte;
        struct page *page;
        void *kaddr;
        unsigned long chunk = min(remaining, PAGE_SIZE - offset);

        /* Walk the page tables */
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
        if (!pte || !pte_present(*pte)) {
            if (pte)
                pte_unmap(pte);
            return -EFAULT;
        }

        page = pte_page(*pte);
        get_page(page);   /* pin it */

        kaddr = kmap(page);
        if (!kaddr) {
            put_page(page);
            pte_unmap(pte);
            return -EFAULT;
        }

        if (write) {
            memcpy(kaddr + offset, kern_buf, chunk);
            flush_dcache_page_fn(page);
            set_page_dirty_fn(page);
        } else {
            memcpy(kern_buf, kaddr + offset, chunk);
        }

        kunmap(page);
        put_page(page);
        pte_unmap(pte);

        kern_buf += chunk;
        vaddr += chunk;
        remaining -= chunk;
        offset = 0;  /* after the first chunk we are page-aligned */
    }
    return 0;
}

/**
 * memory_read_write – high-level read or write from a remote process.
 * @pid:   target process id
 * @addr:  user virtual address in target
 * @buf:   kernel buffer
 * @size:  bytes
 * @write: 1 for write, 0 for read
 * Returns 0 or negative error.
 */
static int memory_read_write(pid_t pid, unsigned long addr, void *buf,
                             size_t size, int write)
{
    struct task_struct *task;
    struct mm_struct *mm;
    int ret;

    ret = get_process_mm(pid, &mm, &task);
    if (ret < 0)
        return ret;

    if (size == 0 || size > MAX_TRANSFER_SIZE) {
        ret = -EINVAL;
        goto out_put;
    }

    ret = validate_user_address(mm, addr, size);
    if (ret < 0)
        goto out_put;

    mmap_read_lock_fn(mm);
    ret = walk_and_access_memory(mm, addr, buf, size, write);
    mmap_read_unlock_fn(mm);

out_put:
    put_process_mm(mm);
    put_process_task(task);
    return ret;
}

static int read_process_memory(pid_t pid, unsigned long addr, void *buf, size_t size)
{
    return memory_read_write(pid, addr, buf, size, 0);
}

static int write_process_memory(pid_t pid, unsigned long addr, const void *buf, size_t size)
{
    return memory_read_write(pid, addr, (void *)buf, size, 1);
}

/**
 * resolve_base_address – returns the code segment start (start_code).
 */
static int resolve_base_address(pid_t pid, unsigned long *base)
{
    struct task_struct *task;
    struct mm_struct *mm;
    int ret;

    ret = get_process_mm(pid, &mm, &task);
    if (ret < 0)
        return ret;
    *base = mm->start_code;
    put_process_mm(mm);
    put_process_task(task);
    return 0;
}

/**
 * virtual_to_physical – obtain the physical address behind a user virtual address.
 */
static int virtual_to_physical(pid_t pid, unsigned long vaddr, unsigned long *phys)
{
    struct task_struct *task;
    struct mm_struct *mm;
    pgd_t *pgd;
    p4d_t *p4d;
    pud_t *pud;
    pmd_t *pmd;
    pte_t *pte;
    int ret = -EFAULT;

    ret = get_process_mm(pid, &mm, &task);
    if (ret < 0)
        return ret;

    ret = validate_user_address(mm, vaddr, 1);
    if (ret < 0)
        goto out_put;

    mmap_read_lock_fn(mm);
    pgd = pgd_offset(mm, vaddr);
    if (pgd_none(*pgd) || pgd_bad(*pgd))
        goto unlock;
    p4d = p4d_offset(pgd, vaddr);
    if (p4d_none(*p4d) || p4d_bad(*p4d))
        goto unlock;
    pud = pud_offset(p4d, vaddr);
    if (pud_none(*pud) || pud_bad(*pud))
        goto unlock;
    pmd = pmd_offset(pud, vaddr);
    if (pmd_none(*pmd) || pmd_bad(*pmd))
        goto unlock;
    pte = pte_offset_map(pmd, vaddr);
    if (!pte || !pte_present(*pte)) {
        if (pte) pte_unmap(pte);
        goto unlock;
    }
    *phys = (pte_pfn(*pte) << PAGE_SHIFT) + (vaddr & ~PAGE_MASK);
    pte_unmap(pte);
    ret = 0;
unlock:
    mmap_read_unlock_fn(mm);
out_put:
    put_process_mm(mm);
    put_process_task(task);
    return ret;
}

/* ---------- Handler functions (called by the APatch framework) ---------- */

int handle_resolve_base(struct k_packet *pkt)
{
    unsigned long base = 0;
    int ret = resolve_base_address(pkt->target_pid, &base);
    if (ret < 0) {
        pkt->status = (ret == -ESRCH) ? STATUS_INVALID_PID : STATUS_ACCESS_DENIED;
        return ret;
    }
    pkt->resolved_base = base;
    pkt->status = STATUS_SUCCESS;
    return 0;
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

    /* Copy to userspace buffer (provided by the APatch caller – already in user context) */
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
    if (copy_from_user(kbuf, (void __user *)(unsigned long)pkt->user_buffer, pkt->size)) {
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
    unsigned long phys = 0;
    int ret = virtual_to_physical(pkt->target_pid, pkt->target_addr, &phys);
    if (ret < 0) {
        if (ret == -ESRCH)
            pkt->status = STATUS_INVALID_PID;
        else
            pkt->status = STATUS_PAGE_FAULT;
        return ret;
    }
    pkt->physical_addr = phys;
    pkt->status = STATUS_SUCCESS;
    return 0;
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

/* Register with APatch framework */
KPM_INIT(hfr_memory_init);
KPM_EXIT(hfr_memory_exit);
