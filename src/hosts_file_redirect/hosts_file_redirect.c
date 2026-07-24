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
KPM_DESCRIPTION("Kernel memory r/w via Volatile Proc Engine");

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

static access_process_vm_t p_vm;
static find_task_by_vpid_t  p_find;
static get_task_struct_t    p_get;
static put_task_struct_t    p_put;
static kmalloc_t            p_malloc;
static kfree_t              p_free;
static proc_create_data_t   p_proc_create_data;
static remove_proc_entry_t  p_remove_proc_entry;

typedef void (*rcu_read_lock_t)(void);
typedef void (*rcu_read_unlock_t)(void);
static rcu_read_lock_t   p_rcu_lock;
static rcu_read_unlock_t p_rcu_unlock;

static const char *proc_filename = "hfr_mem";
static void *proc_entry = NULL;

// MASTER FIX 1: Enforcing absolute volatile boundaries to block Clang from generating implicit 'memcpy' calls
__attribute__((optimize("no-tree-loop-distribute-patterns")))
static void strict_cp(void *d, const void *s, unsigned long n) {
    volatile unsigned char *dd = (volatile unsigned char *)d; 
    const volatile unsigned char *ss = (const volatile unsigned char *)s;
    unsigned long i;
    for (i = 0; i < n; i++) {
        dd[i] = ss[i];
    }
}

static void process_packet(struct k_packet *pkt)
{
    pkt->status = STATUS_INVALID_PID;
    if (pkt->op_code == OP_READ_VM) {
        if (!pkt->size || pkt->size > MAX_INLINE) { pkt->status = STATUS_INVALID_SIZE; return; }
        void *kbuf = p_malloc(pkt->size, GFP_KERNEL);
        if (!kbuf) { pkt->status = STATUS_MEM_ALLOC_FAIL; return; }
        
        if (p_rcu_lock) p_rcu_lock();
        void *task = p_find(pkt->target_pid);
        if (!task) { if (p_rcu_unlock) p_rcu_unlock(); p_free(kbuf); return; }
        p_get(task);
        if (p_rcu_unlock) p_rcu_unlock();
        
        int r = p_vm(task, pkt->target_addr, kbuf, pkt->size, 0);
        p_put(task);
        
        if (r == pkt->size) {
            strict_cp(pkt->inline_data, kbuf, pkt->size);
            pkt->status = STATUS_SUCCESS;
        }
        else pkt->status = STATUS_PAGE_FAULT;
        p_free(kbuf);
    }
    else if (pkt->op_code == OP_WRITE_VM) {
        if (!pkt->size || pkt->size > MAX_INLINE) { pkt->status = STATUS_INVALID_SIZE; return; }
        
        if (p_rcu_lock) p_rcu_lock();
        void *task = p_find(pkt->target_pid);
        if (!task) { if (p_rcu_unlock) p_rcu_unlock(); return; }
        p_get(task);
        if (p_rcu_unlock) p_rcu_unlock();
        
        int r = p_vm(task, pkt->target_addr, pkt->inline_data, pkt->size, 1);
        p_put(task);
        pkt->status = (r == pkt->size) ? STATUS_SUCCESS : STATUS_PAGE_FAULT;
    }
}

__attribute__((optimize("no-tree-loop-distribute-patterns")))
static ssize_t proc_write_handler(struct file *file, const char __user *buffer, size_t count, loff_t *pos)
{
    struct k_packet local_pkt;

    if (count < sizeof(struct k_packet)) return -EINVAL;

    // Strict non-optimized loop copy execution
    strict_cp(&local_pkt, (const void *)buffer, sizeof(struct k_packet));

    process_packet(&local_pkt);

    strict_cp((void *)buffer, &local_pkt, sizeof(struct k_packet));

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
    
    p_rcu_lock = (rcu_read_lock_t)kallsyms_lookup_name("rcu_read_lock");
    p_rcu_unlock = (rcu_read_unlock_t)kallsyms_lookup_name("rcu_read_unlock");
    
    if (!p_vm || !p_find || !p_malloc || !p_proc_create_data) {
        kpm_err("Core symbol resolution failed\n");
        return -EFAULT;
    }
    
    proc_entry = p_proc_create_data(proc_filename, 0666, NULL, &p_ops, NULL);
    if (!proc_entry) {
        kpm_err("Proc registration node failure.\n");
        return -EFAULT;
    }

    kpm_info("Proc Synchronous Bridge initialized safely without implicit optimizations!\n");
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
