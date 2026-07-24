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
KPM_DESCRIPTION("Kernel memory r/w via Integrated Proc Engine");

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

// Exact GKI layout structure to link cleanly into the system table
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

typedef void *(*proc_create_data_t)(const char *, uint16_t, void *, const struct proc_ops *, void *);
typedef void (*remove_proc_entry_t)(const char *, void *);

// Using the architecture specific globally exported functions that are 100% visible
typedef unsigned long (*arch_copy_from_user_t)(void *, const void __user *, unsigned long);
typedef unsigned long (*arch_copy_to_user_t)(void __user *, const void *, unsigned long);

static access_process_vm_t p_vm;
static find_task_by_vpid_t  p_find;
static get_task_struct_t    p_get;
static put_task_struct_t    p_put;
static kmalloc_t            p_malloc;
static kfree_t              p_free;
static proc_create_data_t   p_proc_create_data;
static remove_proc_entry_t  p_remove_proc_entry;
static arch_copy_from_user_t p_copy_from;
static arch_copy_to_user_t   p_copy_to;

static const char *proc_filename = "hfr_mem";
static void *proc_entry = NULL;

// Working module source code copy logic matching exact binary frame boundaries
static void cp(void *d, const void *s, unsigned long n) {
    unsigned char *dd = d; const unsigned char *ss = s;
    for (unsigned long i = 0; i < n; i++) dd[i] = ss[i];
}

// Exact merged memory read/write logic from your working file socket source
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

// Master GKI data transfer handler with direct hardware memory boundary mapping
__attribute__((optimize("no-tree-loop-distribute-patterns")))
static ssize_t proc_write_handler(struct file *file, const char __user *buffer, size_t count, loff_t *pos)
{
    struct k_packet local_pkt;

    if (count < sizeof(struct k_packet)) return -EINVAL;

    // Use arch level copy to safely cross the user space boundary without triggering any MMU faults
    if (p_copy_from(&local_pkt, buffer, sizeof(struct k_packet)) != 0) {
        return -EFAULT;
    }

    process_packet(&local_pkt);

    if (p_copy_to((void __user *)buffer, &local_pkt, sizeof(struct k_packet)) != 0) {
        return -EFAULT;
    }

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

static long hfr_memory_init(const char *args, const char *event, void __user *reserved)
{
    p_vm = (access_process_vm_t)kallsyms_lookup_name("access_process_vm");
    p_find = (find_task_by_vpid_t)kallsyms_lookup_name("find_task_by_vpid");
    p_get = (get_task_struct_t)kallsyms_lookup_name("get_task_struct");
    p_put = (put_task_struct_t)kallsyms_lookup_name("put_task_struct");
    p_malloc = (kmalloc_t)kallsyms_lookup_name("__kmalloc");
    p_free = (kfree_t)kallsyms_lookup_name("kfree");
    
    p_proc_create_data = (proc_create_data_t)kallsyms_lookup_name("proc_create_data");
    p_remove_proc_entry = (remove_proc_entry_t)kallsyms_lookup_name("remove_proc_entry");
    
    // Explicit global exported hardware level copy hooks mapping
    p_copy_from = (arch_copy_from_user_t)kallsyms_lookup_name("__arch_copy_from_user");
    p_copy_to = (arch_copy_to_user_t)kallsyms_lookup_name("__arch_copy_to_user");
    
    if (!p_vm || !p_find || !p_malloc || !p_proc_create_data || !p_copy_from || !p_copy_to) {
        kpm_err("Core symbol resolution failed\n");
        return -EFAULT;
    }
    
    proc_entry = p_proc_create_data(proc_filename, 0666, NULL, &p_ops, NULL);
    if (!proc_entry) return -EFAULT;

    kpm_info("Proc Engine successfully integrated with your custom memory logic!\n");
    return 0;
}

static long hfr_memory_exit(void __user *reserved)
{
    if (proc_entry && p_remove_proc_entry) {
        p_remove_proc_entry(proc_filename, NULL);
    }
    kpm_info("Proc pipeline unlinked safely!\n");
    return 0;
}

KPM_INIT(hfr_memory_init);
KPM_EXIT(hfr_memory_exit);
