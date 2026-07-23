/* SPDX-License-Identifier: GPL-2.0-or-later */
/* ROBUST /dev/hfr_mem - Direct Panel Communication */
/* register_chrdev + string.h memcpy - NO redefinition */

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
KPM_DESCRIPTION("Kernel memory r/w via /dev/hfr_mem");

#define KPM_PREFIX "HFR_MEM"
#define kpm_info(fmt, ...) pr_info(KPM_PREFIX ": " fmt, ##__VA_ARGS__)
#define kpm_err(fmt, ...) pr_err(KPM_PREFIX ": " fmt, ##__VA_ARGS__)

#define GFP_KERNEL 0xcc0
#define PAGE_SIZE 4096
#define MAX_INLINE_DATA 256

#define OP_READ_VM 0x2000
#define OP_WRITE_VM 0x3000

#define STATUS_SUCCESS 0x0000
#define STATUS_INVALID_PID 0x1001
#define STATUS_PAGE_FAULT 0x1004
#define STATUS_INVALID_SIZE 0x1005
#define STATUS_MEM_ALLOC_FAIL 0x1008
#define STATUS_MODULE_BUSY 0x1010

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

typedef int (*access_process_vm_t)(struct task_struct *, unsigned long, void *, int, int);
typedef struct task_struct *(*get_task_struct_t)(struct task_struct *);
typedef void (*put_task_struct_t)(struct task_struct *);
typedef struct task_struct *(*find_task_by_vpid_t)(pid_t);
typedef void *(*kmalloc_t)(unsigned long, unsigned int);
typedef void (*kfree_t)(const void *);
typedef int (*register_chrdev_t)(unsigned int, const char *, void *);
typedef void (*unregister_chrdev_t)(unsigned int, const char *);

static access_process_vm_t p_access_process_vm;
static get_task_struct_t p_get_task_struct;
static put_task_struct_t p_put_task_struct;
static find_task_by_vpid_t p_find_task_by_vpid;
static kmalloc_t p_kmalloc;
static kfree_t p_kfree;
static register_chrdev_t p_register_chrdev;
static unregister_chrdev_t p_unregister_chrdev;

static struct k_packet g_pkt;
static int g_ready = 0;
static int g_major = -1;

static int hfr_open(void *inode, void *filp) { return 0; }

static ssize_t hfr_write(void *filp, const char __user *buf, size_t len, void *off)
{
    struct k_packet pkt;
    if (len != sizeof(pkt)) return -EINVAL;
    {
        const unsigned char *s = (const unsigned char *)buf;
        unsigned char *d = (unsigned char *)&pkt;
        unsigned long i;
        for (i = 0; i < len; i++) d[i] = s[i];
    }
    g_ready = 0;
    pkt.status = STATUS_MODULE_BUSY;

    if (pkt.op_code == OP_READ_VM) {
        void *kbuf;
        if (!pkt.size || pkt.size > MAX_INLINE_DATA) { pkt.status = STATUS_INVALID_SIZE; goto done; }
        kbuf = p_kmalloc(pkt.size, GFP_KERNEL);
        if (!kbuf) { pkt.status = STATUS_MEM_ALLOC_FAIL; goto done; }
        struct task_struct *task = p_find_task_by_vpid(pkt.target_pid);
        if (!task) { p_kfree(kbuf); pkt.status = STATUS_INVALID_PID; goto done; }
        p_get_task_struct(task);
        int ret = p_access_process_vm(task, pkt.target_addr, kbuf, pkt.size, 0);
        p_put_task_struct(task);
        if (ret == pkt.size) {
            memcpy(pkt.inline_data, kbuf, pkt.size);
            pkt.status = STATUS_SUCCESS;
            pkt.page_count = (pkt.size + PAGE_SIZE - 1) / PAGE_SIZE;
        } else pkt.status = STATUS_PAGE_FAULT;
        p_kfree(kbuf);
    }
    else if (pkt.op_code == OP_WRITE_VM) {
        if (!pkt.size || pkt.size > MAX_INLINE_DATA) { pkt.status = STATUS_INVALID_SIZE; goto done; }
        struct task_struct *task = p_find_task_by_vpid(pkt.target_pid);
        if (!task) { pkt.status = STATUS_INVALID_PID; goto done; }
        p_get_task_struct(task);
        int ret = p_access_process_vm(task, pkt.target_addr, pkt.inline_data, pkt.size, 1);
        p_put_task_struct(task);
        if (ret == pkt.size) {
            pkt.status = STATUS_SUCCESS;
            pkt.page_count = (pkt.size + PAGE_SIZE - 1) / PAGE_SIZE;
        } else pkt.status = STATUS_PAGE_FAULT;
    }

done:
    memcpy(&g_pkt, &pkt, sizeof(pkt));
    g_ready = 1;
    return len;
}

static ssize_t hfr_read(void *filp, char __user *buf, size_t len, void *off)
{
    if (!g_ready) return 0;
    if (len < sizeof(g_pkt)) return -EINVAL;
    if (compat_copy_to_user(buf, &g_pkt, sizeof(g_pkt))) return -EFAULT;
    g_ready = 0;
    return sizeof(g_pkt);
}

struct my_file_operations {
    void *owner;
    void *open;
    void *read;
    void *write;
    void *unlocked_ioctl;
    void *compat_ioctl;
};

static struct my_file_operations hfr_fops = {
    .owner = NULL,
    .open = (void *)hfr_open,
    .read = (void *)hfr_read,
    .write = (void *)hfr_write,
    .unlocked_ioctl = NULL,
    .compat_ioctl = NULL,
};

static long hfr_memory_init(const char *args, const char *event, void __user *reserved)
{
    p_access_process_vm  = (access_process_vm_t) kallsyms_lookup_name("access_process_vm");
    p_get_task_struct    = (get_task_struct_t)   kallsyms_lookup_name("get_task_struct");
    p_put_task_struct    = (put_task_struct_t)   kallsyms_lookup_name("put_task_struct");
    p_find_task_by_vpid  = (find_task_by_vpid_t) kallsyms_lookup_name("find_task_by_vpid");
    p_kmalloc            = (kmalloc_t)           kallsyms_lookup_name("__kmalloc");
    p_kfree              = (kfree_t)             kallsyms_lookup_name("kfree");
    p_register_chrdev    = (register_chrdev_t)   kallsyms_lookup_name("__register_chrdev");
    p_unregister_chrdev  = (unregister_chrdev_t) kallsyms_lookup_name("__unregister_chrdev");

    if (!p_access_process_vm || !p_find_task_by_vpid || !p_kmalloc ||
        !p_kfree || !p_register_chrdev || !p_get_task_struct || !p_put_task_struct) {
        kpm_err("Symbol resolution failed\n");
        return -EFAULT;
    }

    g_major = p_register_chrdev(0, "hfr_mem", &hfr_fops);
    if (g_major < 0) {
        kpm_err("register_chrdev failed: %d\n", g_major);
        return -EFAULT;
    }

    kpm_info("LOADED /dev/hfr_mem (major=%d) - mknod /dev/hfr_mem c %d 0\n", g_major, g_major);
    return 0;
}

static long hfr_memory_exit(void __user *reserved)
{
    if (g_major >= 0 && p_unregister_chrdev) p_unregister_chrdev(g_major, "hfr_mem");
    kpm_info("Unloaded\n");
    return 0;
}

KPM_INIT(hfr_memory_init);
KPM_EXIT(hfr_memory_exit);
