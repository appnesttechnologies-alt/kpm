/* SPDX-License-Identifier: GPL-2.0-or-later */
/*
 * Copyright (C) 2026 Surajit. All Rights Reserved.
 * Single-File Self-Contained KPM Memory Debugger Module
 * Creates /dev/hfr_mem node for direct panel communication
 */

#include <compiler.h>
#include <hook.h>
#include <kpmodule.h>
#include <kputils.h>
#include <linux/sched.h>
#include <linux/errno.h>
#include <linux/printk.h>
#include <linux/string.h>
#include <linux/miscdevice.h>
#include <linux/fs.h>
#include <linux/uaccess.h>

KPM_NAME("hosts_file_redirect");
KPM_VERSION(HFR_VERSION);
KPM_LICENSE("GPL v2");
KPM_AUTHOR("Surajit");
KPM_DESCRIPTION("Single-file self-contained kernel memory read/write debugger.");

#define KPM_PREFIX             "HFR_MEM"
#define kpm_info(fmt, ...)     pr_info(KPM_PREFIX ": " fmt, ##__VA_ARGS__)
#define kpm_err(fmt, ...)      pr_err(KPM_PREFIX ": " fmt, ##__VA_ARGS__)

#define GFP_KERNEL  0xcc0
#define PAGE_SIZE   4096
#define MAX_TRANSFER_SIZE     0x100000
#define MAX_INLINE_DATA       256

#define OP_RESOLVE_BASE       0x1000
#define OP_READ_VM            0x2000
#define OP_WRITE_VM           0x3000
#define OP_QUERY_PHYS         0x4000

#define STATUS_SUCCESS        0x0000
#define STATUS_INVALID_PID    0x1001
#define STATUS_INVALID_ADDR   0x1002
#define STATUS_ACCESS_DENIED  0x1003
#define STATUS_PAGE_FAULT     0x1004
#define STATUS_INVALID_SIZE   0x1005
#define STATUS_MEM_ALLOC_FAIL 0x1008
#define STATUS_COPY_FAIL      0x1009
#define STATUS_MODULE_BUSY    0x1010

struct k_packet {
    uint32_t op_code;
    uint32_t target_pid;
    uint64_t target_addr;
    uint32_t size;
    uint32_t status;
    uint64_t resolved_base;
    uint64_t physical_addr;
    uint32_t page_count;
    uint32_t reserved;
    uint8_t inline_data[MAX_INLINE_DATA];
} __attribute__((aligned(8), packed));

/* Function pointers */
typedef int (*access_process_vm_t)(struct task_struct *tsk, unsigned long addr,
                                   void *buf, int len, int write);
typedef struct task_struct *(*get_task_struct_t)(struct task_struct *t);
typedef void (*put_task_struct_t)(struct task_struct *t);
typedef struct task_struct *(*find_task_by_vpid_t)(pid_t nr);
typedef void *(*kmalloc_t)(unsigned long size, unsigned int flags);
typedef void (*kfree_t)(const void *objp);

static access_process_vm_t access_process_vm_fn;
static get_task_struct_t get_task_struct_fn;
static put_task_struct_t put_task_struct_fn;
static find_task_by_vpid_t find_task_by_vpid_fn;
static kmalloc_t kmalloc_fn;
static kfree_t kfree_fn;

/* Forward decl */
static long hfr_dev_ioctl(struct file *filp, unsigned int cmd, unsigned long arg);
static ssize_t hfr_dev_write(struct file *filp, const char __user *buf, size_t len, loff_t *off);
static ssize_t hfr_dev_read(struct file *filp, char __user *buf, size_t len, loff_t *off);
static int hfr_dev_open(struct inode *inode, struct file *filp);

static struct file_operations hfr_fops = {
    .owner = THIS_MODULE,
    .open = hfr_dev_open,
    .read = hfr_dev_read,
    .write = hfr_dev_write,
    .unlocked_ioctl = hfr_dev_ioctl,
};

static struct miscdevice hfr_misc = {
    .minor = MISC_DYNAMIC_MINOR,
    .name = "hfr_mem",
    .fops = &hfr_fops,
};

static struct k_packet g_last_result;
static bool g_result_ready = false;

static int hfr_dev_open(struct inode *inode, struct file *filp) { return 0; }

static ssize_t hfr_dev_write(struct file *filp, const char __user *buf, size_t len, loff_t *off)
{
    struct k_packet pkt;
    int ret;

    if (len != sizeof(struct k_packet)) return -EINVAL;
    if (copy_from_user(&pkt, buf, len)) return -EFAULT;

    g_result_ready = false;

    switch (pkt.op_code) {
    case OP_READ_VM: {
        void *kbuf;
        if (pkt.size == 0 || pkt.size > MAX_TRANSFER_SIZE) {
            pkt.status = STATUS_INVALID_SIZE;
            break;
        }
        kbuf = kmalloc_fn(pkt.size, GFP_KERNEL);
        if (!kbuf) { pkt.status = STATUS_MEM_ALLOC_FAIL; break; }

        struct task_struct *task = find_task_by_vpid_fn(pkt.target_pid);
        if (!task) { pkt.status = STATUS_INVALID_PID; kfree_fn(kbuf); break; }

        get_task_struct_fn(task);
        ret = access_process_vm_fn(task, pkt.target_addr, kbuf, pkt.size, 0);
        put_task_struct_fn(task);

        if (ret == pkt.size) {
            memcpy(pkt.inline_data, kbuf, pkt.size);
            pkt.status = STATUS_SUCCESS;
        } else {
            pkt.status = STATUS_PAGE_FAULT;
        }
        kfree_fn(kbuf);
        break;
    }
    case OP_WRITE_VM: {
        if (pkt.size == 0 || pkt.size > MAX_INLINE_DATA) {
            pkt.status = STATUS_INVALID_SIZE;
            break;
        }

        struct task_struct *task = find_task_by_vpid_fn(pkt.target_pid);
        if (!task) { pkt.status = STATUS_INVALID_PID; break; }

        get_task_struct_fn(task);
        ret = access_process_vm_fn(task, pkt.target_addr, pkt.inline_data, pkt.size, 1);
        put_task_struct_fn(task);

        if (ret == pkt.size) pkt.status = STATUS_SUCCESS;
        else pkt.status = STATUS_PAGE_FAULT;
        break;
    }
    default:
        pkt.status = STATUS_MODULE_BUSY;
        break;
    }

    g_last_result = pkt;
    g_result_ready = true;
    return len;
}

static ssize_t hfr_dev_read(struct file *filp, char __user *buf, size_t len, loff_t *off)
{
    if (!g_result_ready) return 0;
    if (len < sizeof(struct k_packet)) return -EINVAL;
    if (copy_to_user(buf, &g_last_result, sizeof(struct k_packet))) return -EFAULT;
    g_result_ready = false;
    return sizeof(struct k_packet);
}

static long hfr_dev_ioctl(struct file *filp, unsigned int cmd, unsigned long arg)
{
    // Alternative: ioctl interface
    return -ENOTTY;
}

/* ---------- Init & Exit ---------- */

static long hfr_memory_init(const char *args, const char *event, void __user *reserved)
{
    access_process_vm_fn = (access_process_vm_t)kallsyms_lookup_name("access_process_vm");
    get_task_struct_fn = (get_task_struct_t)kallsyms_lookup_name("get_task_struct");
    put_task_struct_fn = (put_task_struct_t)kallsyms_lookup_name("put_task_struct");
    find_task_by_vpid_fn = (find_task_by_vpid_t)kallsyms_lookup_name("find_task_by_vpid");
    kmalloc_fn = (kmalloc_t)kallsyms_lookup_name("__kmalloc");
    kfree_fn = (kfree_t)kallsyms_lookup_name("kfree");

    if (!access_process_vm_fn || !get_task_struct_fn || !put_task_struct_fn ||
        !find_task_by_vpid_fn || !kmalloc_fn || !kfree_fn) {
        kpm_err("Failed to resolve required kernel symbols\n");
        return -EFAULT;
    }

    if (misc_register(&hfr_misc)) {
        kpm_err("Failed to register /dev/hfr_mem\n");
        return -EFAULT;
    }

    kpm_info("HFR Memory Debugger Module Loaded Successfully! Node: /dev/hfr_mem\n");
    return 0;
}

static long hfr_memory_exit(void __user *reserved)
{
    misc_deregister(&hfr_misc);
    kpm_info("HFR Memory Debugger Module Unloaded Safely!\n");
    return 0;
}

KPM_INIT(hfr_memory_init);
KPM_EXIT(hfr_memory_exit);
