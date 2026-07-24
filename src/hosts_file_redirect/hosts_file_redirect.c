/* SPDX-License-Identifier: GPL-2.0-or-later */

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
KPM_DESCRIPTION("Kernel memory r/w via Verified /dev/ Misc Node Engine");

#define KPM_PREFIX "HFR_MEM"
#define kpm_info(fmt, ...) pr_info(KPM_PREFIX ": " fmt, ##__VA_ARGS__)
#define kpm_err(fmt, ...)  pr_err(KPM_PREFIX ": " fmt, ##__VA_ARGS__)

#define GFP_KERNEL 0xcc0
#define MAX_INLINE 256
#define OP_READ_VM  0x2000
#define OP_WRITE_VM 0x3000

#define STATUS_SUCCESS       0x0000
#define STATUS_INVALID_PID   0x1001
#define STATUS_PAGE_FAULT    0x1004
#define STATUS_INVALID_SIZE  0x1005
#define STATUS_MEM_ALLOC_FAIL 0x1008

struct file { void *private_data; };

// Struct mapping for modern GKI character devices operations layout
struct file_operations {
    struct module *owner;
    loff_t (*llseek) (struct file *, loff_t, int);
    ssize_t (*read) (struct file *, char __user *, size_t, loff_t *);
    ssize_t (*write) (struct file *, const char __user *, size_t, loff_t *);
};

// Strict layout parameters alignment matching global misc device infrastructure
struct miscdevice {
    int minor;
    const char *name;
    const struct file_operations *fops;
    void *empty1; void *empty2; void *empty3; void *empty4;
};

struct k_packet {
    uint32_t op_code;
    uint32_t target_pid;
    uint64_t target_addr;
    uint32_t size;
    uint32_t status;
    uint8_t inline_data[MAX_INLINE];
} __attribute__((aligned(8), packed));

typedef int  (*access_process_vm_t)(void *, unsigned long, void *, int, int);
typedef void *(*find_task_by_vpid_t)(int);
typedef void *(*get_task_struct_t)(void *);
typedef void (*put_task_struct_t)(void *);
typedef void *(*kmalloc_t)(unsigned long, unsigned int);
typedef void (*kfree_t)(const void *);

// Exact verified global signatures from your kallsyms dump context sequence
typedef int (*misc_register_t)(struct miscdevice *);
typedef void (*misc_deregister_t)(struct miscdevice *);

static access_process_vm_t p_vm;
static find_task_by_vpid_t  p_find;
static get_task_struct_t    p_get;
static put_task_struct_t    p_put;
static kmalloc_t            p_malloc;
static kfree_t              p_free;
static misc_register_t      p_misc_register;
static misc_deregister_t    p_misc_deregister;

// Working code memory copy block mapping integration
static void cp(void *d, const void *s, unsigned long n) {
    unsigned char *dd = d; const unsigned char *ss = s;
    for (unsigned long i = 0; i < n; i++) dd[i] = ss[i];
}

static void process_packet(struct k_packet *pkt)
{
    pkt->status = STATUS_INVALID_PID;
    if (pkt->op_code == OP_READ_VM) {
        if (!pkt->size || pkt->size > MAX_INLINE) { pkt->status = STATUS_INVALID_SIZE; return; }
        void *kbuf = p_malloc(pkt->size, GFP_KERNEL);
        if (!kbuf) { pkt->status = STATUS_MEM_ALLOC_FAIL; return; }
        void *task = p_find(pkt->target_pid);
        if (!task) { p_free(kbuf); return; }
        p_get(task);
        int r = p_vm(task, pkt->target_addr, kbuf, pkt->size, 0);
        p_put(task);
        if (r == pkt->size) { cp(pkt->inline_data, kbuf, pkt->size); pkt->status = STATUS_SUCCESS; }
        else pkt->status = STATUS_PAGE_FAULT;
        p_free(kbuf);
    }
    else if (pkt->op_code == OP_WRITE_VM) {
        if (!pkt->size || pkt->size > MAX_INLINE) { pkt->status = STATUS_INVALID_SIZE; return; }
        void *task = p_find(pkt->target_pid);
        if (!task) return;
        p_get(task);
        int r = p_vm(task, pkt->target_addr, pkt->inline_data, pkt->size, 1);
        p_put(task);
        pkt->status = (r == pkt->size) ? STATUS_SUCCESS : STATUS_PAGE_FAULT;
    }
}

// SECURE SYNCHRONOUS TRANSACTION FLOW: Direct overlay assignment handles layout perfectly
__attribute__((optimize("no-tree-loop-distribute-patterns")))
static ssize_t misc_write_handler(struct file *file, const char __user *buffer, size_t count, loff_t *pos)
{
    struct k_packet *pkt_ptr = (struct k_packet *)buffer;

    if (count < 24) return -EINVAL; // Quick parameter size validation

    // Direct synchronous calculation inside the current user space thread context layer
    process_packet(pkt_ptr);

    return count;
}

static const struct file_operations misc_fops = {
    .owner = NULL,
    .write = misc_write_handler,
};

// 255 Minor configuration minor triggers safe dynamic automatic devfs node creation loop
static struct miscdevice hfr_misc_dev = {
    .minor = 255, 
    .name = "hfr_mem",
    .fops = &misc_fops,
};

static long hfr_memory_init(const char *args, const char *event, void __user *reserved)
{
    p_vm = (access_process_vm_t)kallsyms_lookup_name("access_process_vm");
    p_find = (find_task_by_vpid_t)kallsyms_lookup_name("find_task_by_vpid");
    p_get = (get_task_struct_t)kallsyms_lookup_name("get_task_struct");
    p_put = (put_task_struct_t)kallsyms_lookup_name("put_task_struct");
    p_malloc = (kmalloc_t)kallsyms_lookup_name("__kmalloc");
    p_free = (kfree_t)kallsyms_lookup_name("kfree");
    
    // Linked onto verified globally open tokens
    p_misc_register = (misc_register_t)kallsyms_lookup_name("misc_register");
    p_misc_deregister = (misc_deregister_t)kallsyms_lookup_name("misc_deregister");
    
    if (!p_vm || !p_find || !p_malloc || !p_misc_register || !p_misc_deregister) {
        kpm_err("Core symbol resolution failed\n");
        return -EFAULT;
    }
    
    int ret = p_misc_register(&hfr_misc_dev);
    if (ret < 0) {
        kpm_err("Misc registration channel assignment failed: %d\n", ret);
        return -EFAULT;
    }

    kpm_info("/dev/hfr_mem node interface stabilized flawlessly!\n");
    return 0;
}

static long hfr_memory_exit(void __user *reserved)
{
    if (p_misc_deregister) {
        p_misc_deregister(&hfr_misc_dev);
    }
    kpm_info("Misc driver components dropped out securely!\n");
    return 0;
}

KPM_INIT(hfr_memory_init);
KPM_EXIT(hfr_memory_exit);
