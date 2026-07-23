/* SPDX-License-Identifier: GPL-2.0-or-later */
/*
 * Copyright (C) 2026 Surajit. All Rights Reserved.
 * /dev/hfr_mem via register_chrdev - fully kallsyms resolved
 */

#include <compiler.h>
#include <hook.h>
#include <kpmodule.h>
#include <kputils.h>
#include <linux/sched.h>
#include <linux/errno.h>
#include <linux/printk.h>
#include <linux/string.h>

KPM_NAME("hosts_file_redirect");
KPM_VERSION(HFR_VERSION);
KPM_LICENSE("GPL v2");
KPM_AUTHOR("Surajit");
KPM_DESCRIPTION("Kernel memory read/write via /dev/hfr_mem");

#define KPM_PREFIX             "HFR_MEM"
#define kpm_info(fmt, ...)     pr_info(KPM_PREFIX ": " fmt, ##__VA_ARGS__)
#define kpm_err(fmt, ...)      pr_err(KPM_PREFIX ": " fmt, ##__VA_ARGS__)

#define GFP_KERNEL  0xcc0
#define PAGE_SIZE   4096
#define MAX_TRANSFER_SIZE     0x100000
#define MAX_INLINE_DATA       256

#define OP_READ_VM            0x2000
#define OP_WRITE_VM           0x3000

#define STATUS_SUCCESS        0x0000
#define STATUS_INVALID_PID    0x1001
#define STATUS_PAGE_FAULT     0x1004
#define STATUS_INVALID_SIZE   0x1005
#define STATUS_MEM_ALLOC_FAIL 0x1008
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

/* All via kallsyms */
typedef int (*access_process_vm_t)(struct task_struct *, unsigned long, void *, int, int);
typedef struct task_struct *(*get_task_struct_t)(struct task_struct *);
typedef void (*put_task_struct_t)(struct task_struct *);
typedef struct task_struct *(*find_task_by_vpid_t)(pid_t);
typedef void *(*kmalloc_t)(unsigned long, unsigned int);
typedef void (*kfree_t)(const void *);
typedef unsigned long (*copy_to_user_t)(void __user *, const void *, unsigned long);
typedef unsigned long (*copy_from_user_t)(void *, const void __user *, unsigned long);
typedef int (*register_chrdev_t)(unsigned int, const char *, const void *);
typedef void (*unregister_chrdev_t)(unsigned int, const char *);
typedef struct class *(*class_create_t)(const void *, const char *);
typedef void (*class_destroy_t)(struct class *);
typedef struct device *(*device_create_t)(struct class *, struct device *, dev_t, void *, const char *, ...);
typedef void (*device_destroy_t)(struct class *, dev_t);

static access_process_vm_t access_process_vm_fn;
static get_task_struct_t get_task_struct_fn;
static put_task_struct_t put_task_struct_fn;
static find_task_by_vpid_t find_task_by_vpid_fn;
static kmalloc_t kmalloc_fn;
static kfree_t kfree_fn;
static copy_to_user_t copy_to_user_fn;
static copy_from_user_t copy_from_user_fn;
static register_chrdev_t register_chrdev_fn;
static unregister_chrdev_t unregister_chrdev_fn;
static class_create_t class_create_fn;
static class_destroy_t class_destroy_fn;
static device_create_t device_create_fn;
static device_destroy_t device_destroy_fn;

static struct k_packet g_pkt;
static bool g_ready = false;
static int g_major;
static struct class *g_class;
static struct device *g_device;

static DEFINE_MUTEX(g_lock);

static int hfr_dev_open(struct inode *inode, struct file *filp) { return 0; }

static ssize_t hfr_dev_write(struct file *filp, const char __user *buf, size_t len, loff_t *off)
{
    struct k_packet pkt;
    int ret;

    if (len != sizeof(struct k_packet)) return -EINVAL;
    if (copy_from_user_fn(&pkt, buf, len)) return -EFAULT;

    mutex_lock(&g_lock);
    g_ready = false;

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

        pkt.status = (ret == pkt.size) ? STATUS_SUCCESS : STATUS_PAGE_FAULT;
        break;
    }
    default:
        pkt.status = STATUS_MODULE_BUSY;
        break;
    }

    g_pkt = pkt;
    g_ready = true;
    mutex_unlock(&g_lock);
    return len;
}

static ssize_t hfr_dev_read(struct file *filp, char __user *buf, size_t len, loff_t *off)
{
    if (!g_ready) return 0;
    if (len < sizeof(struct k_packet)) return -EINVAL;

    mutex_lock(&g_lock);
    if (copy_to_user_fn(buf, &g_pkt, sizeof(struct k_packet))) {
        mutex_unlock(&g_lock);
        return -EFAULT;
    }
    g_ready = false;
    mutex_unlock(&g_lock);
    return sizeof(struct k_packet);
}

static struct file_operations hfr_fops = {
    .owner = THIS_MODULE,
    .open = hfr_dev_open,
    .read = hfr_dev_read,
    .write = hfr_dev_write,
};

/* ---------- Init & Exit ---------- */

static long hfr_memory_init(const char *args, const char *event, void __user *reserved)
{
    /* Resolve all functions */
    access_process_vm_fn = (access_process_vm_t)kallsyms_lookup_name("access_process_vm");
    get_task_struct_fn = (get_task_struct_t)kallsyms_lookup_name("get_task_struct");
    put_task_struct_fn = (put_task_struct_t)kallsyms_lookup_name("put_task_struct");
    find_task_by_vpid_fn = (find_task_by_vpid_t)kallsyms_lookup_name("find_task_by_vpid");
    kmalloc_fn = (kmalloc_t)kallsyms_lookup_name("__kmalloc");
    kfree_fn = (kfree_t)kallsyms_lookup_name("kfree");
    copy_to_user_fn = (copy_to_user_t)kallsyms_lookup_name("copy_to_user");
    copy_from_user_fn = (copy_from_user_t)kallsyms_lookup_name("copy_from_user");
    register_chrdev_fn = (register_chrdev_t)kallsyms_lookup_name("__register_chrdev");
    unregister_chrdev_fn = (unregister_chrdev_t)kallsyms_lookup_name("__unregister_chrdev");
    class_create_fn = (class_create_t)kallsyms_lookup_name("class_create");
    class_destroy_fn = (class_destroy_t)kallsyms_lookup_name("class_destroy");
    device_create_fn = (device_create_t)kallsyms_lookup_name("device_create");
    device_destroy_fn = (device_destroy_t)kallsyms_lookup_name("device_destroy");

    if (!access_process_vm_fn || !find_task_by_vpid_fn || !kmalloc_fn || !kfree_fn ||
        !copy_to_user_fn || !copy_from_user_fn || !register_chrdev_fn || !class_create_fn || !device_create_fn) {
        kpm_err("Failed to resolve symbols\n");
        return -EFAULT;
    }

    /* Register char device */
    g_major = register_chrdev_fn(0, "hfr_mem", &hfr_fops);
    if (g_major < 0) {
        kpm_err("register_chrdev failed\n");
        return -EFAULT;
    }

    /* Create device node */
    g_class = class_create_fn(THIS_MODULE, "hfr_mem");
    if (IS_ERR(g_class)) {
        unregister_chrdev_fn(g_major, "hfr_mem");
        kpm_err("class_create failed\n");
        return -EFAULT;
    }

    g_device = device_create_fn(g_class, NULL, MKDEV(g_major, 0), NULL, "hfr_mem");
    if (IS_ERR(g_device)) {
        class_destroy_fn(g_class);
        unregister_chrdev_fn(g_major, "hfr_mem");
        kpm_err("device_create failed\n");
        return -EFAULT;
    }

    kpm_info("Loaded! /dev/hfr_mem (major %d)\n", g_major);
    return 0;
}

static long hfr_memory_exit(void __user *reserved)
{
    if (g_device) device_destroy_fn(g_class, MKDEV(g_major, 0));
    if (g_class) class_destroy_fn(g_class);
    if (g_major >= 0) unregister_chrdev_fn(g_major, "hfr_mem");
    kpm_info("Unloaded!\n");
    return 0;
}

KPM_INIT(hfr_memory_init);
KPM_EXIT(hfr_memory_exit);
