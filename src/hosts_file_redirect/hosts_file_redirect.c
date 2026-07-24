/* SPDX-License-Identifier: GPL-2.0-or-later */
/*
 * self_mem_kpm.c
 *
 * A minimal KPM demonstrating a userspace <-> kernel module proc interface.
 * The module exposes ONLY its own internal buffer for read/write via a
 * proc file. There is no PID targeting, no access_process_vm, and no
 * cross-process memory access of any kind.
 *
 * Purpose: learn the proc_ops + copy_from_user/copy_to_user mechanics
 * safely, without touching memory you don't own.
 */

#include <compiler.h>
#include <hook.h>
#include <kpmodule.h>
#include <kputils.h>
#include <linux/errno.h>
#include <linux/printk.h>
#include <linux/string.h>

KPM_NAME("self_mem_kpm");
KPM_VERSION("1.0");
KPM_LICENSE("GPL v2");
KPM_AUTHOR("Surajit");
KPM_DESCRIPTION("Safe self-contained proc interface: read/write module's own memory only");

#define KPM_PREFIX "SELF_MEM"
#define kpm_info(fmt, ...) pr_info(KPM_PREFIX ": " fmt, ##__VA_ARGS__)
#define kpm_err(fmt, ...)  pr_err(KPM_PREFIX ": " fmt, ##__VA_ARGS__)

#define MAX_INLINE     256
#define SELF_BUF_SIZE  4096

#define OP_READ_SELF   0x2000
#define OP_WRITE_SELF  0x3000

#define STATUS_SUCCESS        0x0000
#define STATUS_INVALID_SIZE   0x1005
#define STATUS_OUT_OF_RANGE   0x1006
#define STATUS_BAD_OPCODE     0x1007

/* ---- proc_ops layout must match this kernel's include/linux/proc_fs.h ----
 * Verify field order against your target kernel version before building.
 * Kernels >= 5.6 use proc_ops; older kernels use file_operations instead.
 */
struct file { void *private_data; };

struct proc_ops {
    unsigned int proc_flags;
    int (*proc_open)(struct inode *, struct file *);
    ssize_t (*proc_read)(struct file *, char __user *, size_t, loff_t *);
    ssize_t (*proc_write)(struct file *, const char __user *, size_t, loff_t *);
    loff_t (*proc_lseek)(struct file *, loff_t, int);
    int (*proc_release)(struct inode *, struct file *);
    unsigned long (*proc_get_unmapped_area)(struct file *, unsigned long, unsigned long, unsigned long, unsigned long);
} __attribute__((packed));

struct k_packet {
    uint32_t op_code;
    uint32_t target_offset;   /* offset into self_buffer, NOT a raw address */
    uint32_t size;
    uint32_t status;
    uint8_t  inline_data[MAX_INLINE];
} __attribute__((aligned(8), packed));

typedef void *(*proc_create_data_t)(const char *, uint16_t, void *, const struct proc_ops *, void *);
typedef void (*remove_proc_entry_t)(const char *, void *);
typedef unsigned long (*copy_from_user_t)(void *to, const void __user *from, unsigned long n);
typedef unsigned long (*copy_to_user_t)(void __user *to, const void *from, unsigned long n);

static proc_create_data_t   p_proc_create_data;
static remove_proc_entry_t  p_remove_proc_entry;
static copy_from_user_t     p_copy_from_user;
static copy_to_user_t       p_copy_to_user;

static const char *proc_filename = "self_mem_kpm";
static void *proc_entry = NULL;

/* The module's own memory. This is the ONLY memory this module ever touches. */
static uint8_t self_buffer[SELF_BUF_SIZE];

static void process_packet(struct k_packet *pkt)
{
    if (pkt->op_code != OP_READ_SELF && pkt->op_code != OP_WRITE_SELF) {
        pkt->status = STATUS_BAD_OPCODE;
        return;
    }

    if (!pkt->size || pkt->size > MAX_INLINE) {
        pkt->status = STATUS_INVALID_SIZE;
        return;
    }

    /* Bounds check against our own buffer - reject anything out of range */
    if ((uint64_t)pkt->target_offset + pkt->size > SELF_BUF_SIZE) {
        pkt->status = STATUS_OUT_OF_RANGE;
        return;
    }

    if (pkt->op_code == OP_READ_SELF) {
        memcpy(pkt->inline_data, self_buffer + pkt->target_offset, pkt->size);
        pkt->status = STATUS_SUCCESS;
    } else { /* OP_WRITE_SELF */
        memcpy(self_buffer + pkt->target_offset, pkt->inline_data, pkt->size);
        pkt->status = STATUS_SUCCESS;
    }
}

static ssize_t proc_write_handler(struct file *file, const char __user *buffer, size_t count, loff_t *pos)
{
    struct k_packet local_pkt;

    if (count < sizeof(struct k_packet))
        return -EINVAL;

    /* Proper user-copy in: never dereference __user pointers directly */
    if (p_copy_from_user(&local_pkt, buffer, sizeof(struct k_packet)))
        return -EFAULT;

    process_packet(&local_pkt);

    /* Proper user-copy out */
    if (p_copy_to_user((void __user *)buffer, &local_pkt, sizeof(struct k_packet)))
        return -EFAULT;

    return count;
}

static const struct proc_ops p_ops = {
    .proc_flags = 0,
    .proc_open = NULL,
    .proc_read = NULL,
    .proc_write = proc_write_handler,
    .proc_lseek = NULL,
    .proc_release = NULL,
};

static long self_mem_init(const char *args, const char *event, void __user *reserved)
{
    p_proc_create_data  = (proc_create_data_t)kallsyms_lookup_name("proc_create_data");
    p_remove_proc_entry = (remove_proc_entry_t)kallsyms_lookup_name("remove_proc_entry");
    p_copy_from_user    = (copy_from_user_t)kallsyms_lookup_name("_copy_from_user");
    p_copy_to_user      = (copy_to_user_t)kallsyms_lookup_name("_copy_to_user");

    if (!p_proc_create_data || !p_remove_proc_entry) {
        kpm_err("Failed to resolve proc_fs symbols\n");
        return -EFAULT;
    }
    if (!p_copy_from_user || !p_copy_to_user) {
        kpm_err("Failed to resolve user-copy symbols\n");
        return -EFAULT;
    }

    memset(self_buffer, 0, SELF_BUF_SIZE);

    /* 0660: owner/group only, not world-writable */
    proc_entry = p_proc_create_data(proc_filename, 0660, NULL, &p_ops, NULL);
    if (!proc_entry) {
        kpm_err("Proc registration failed\n");
        return -EFAULT;
    }

    kpm_info("Initialized. Proc file: /proc/%s\n", proc_filename);
    return 0;
}

static long self_mem_exit(void __user *reserved)
{
    if (proc_entry && p_remove_proc_entry) {
        p_remove_proc_entry(proc_filename, NULL);
    }
    kpm_info("Unloaded, proc entry removed.\n");
    return 0;
}

KPM_INIT(self_mem_init);
KPM_EXIT(self_mem_exit);
