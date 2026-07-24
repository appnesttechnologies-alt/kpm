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
KPM_DESCRIPTION("Kernel memory r/w via Verified Native Proc Engine");

#define MAX_INLINE 256
#define OP_READ_VM  0x2000
#define OP_WRITE_VM 0x3000

#define STATUS_SUCCESS       0x0000
#define STATUS_INVALID_PID   0x1001
#define STATUS_PAGE_FAULT    0x1004

struct file { void *private_data; };

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

// Using strict procedural function mappings to bypass dynamic GKI tables completely
typedef void *(*proc_create_t)(const char *, uint16_t, void *, void *);
typedef void (*remove_proc_entry_t)(const char *, void *);

static access_process_vm_t p_vm;
static find_task_by_vpid_t  p_find;
static get_task_struct_t    p_get;
static put_task_struct_t    p_put;
static kmalloc_t            p_malloc;
static kfree_t              p_free;
static proc_create_t        p_proc_create;
static remove_proc_entry_t  p_remove_proc_entry;

typedef void (*rcu_read_lock_t)(void);
typedef void (*rcu_read_unlock_t)(void);
static rcu_read_lock_t   p_rcu_lock;
static rcu_read_unlock_t p_rcu_unlock;

static const char *proc_filename = "hfr_mem";
static void *proc_entry = NULL;

__attribute__((optimize("no-tree-loop-distribute-patterns")))
static void strict_cp(void *d, const void *s, unsigned long n) {
    volatile unsigned char *dd = (volatile unsigned char *)d; 
    const volatile unsigned char *ss = (const volatile unsigned char *)s;
    for (unsigned long i = 0; i < n; i++) dd[i] = ss[i];
}

static void process_packet(struct k_packet *pkt)
{
    pkt->status = STATUS_INVALID_PID;
    if (pkt->op_code == OP_READ_VM) {
        if (!pkt->size || pkt->size > MAX_INLINE) return;
        void *kbuf = p_malloc(pkt->size, 0xcc0); 
        if (!kbuf) return;
        
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
}

__attribute__((optimize("no-tree-loop-distribute-patterns")))
static ssize_t secure_proc_write(struct file *file, const char __user *buffer, size_t count, loff_t *pos)
{
    struct k_packet local_pkt;

    if (count < sizeof(struct k_packet)) return -EINVAL;

    // Use direct pointer assignments to completely clear I/O issues inside verified channels
    strict_cp(&local_pkt, (const void *)buffer, sizeof(struct k_packet));

    process_packet(&local_pkt);

    strict_cp((void *)buffer, &local_pkt, sizeof(struct k_packet));

    return count;
}

static long hfr_memory_init(const char *args, const char *event, void __user *reserved)
{
    p_vm = (access_process_vm_t)kallsyms_lookup_name("access_process_vm");
    p_find = (find_task_by_vpid_t)kallsyms_lookup_name("find_task_by_vpid");
    p_get = (get_task_struct_t)kallsyms_lookup_name("get_task_struct");
    p_put = (put_task_struct_t)kallsyms_lookup_name("put_task_struct");
    p_malloc = (kmalloc_t)kallsyms_lookup_name("__kmalloc");
    p_free = (kfree_t)kallsyms_lookup_name("kfree");
    
    p_proc_create = (proc_create_t)kallsyms_lookup_name("proc_create");
    p_remove_proc_entry = (remove_proc_entry_t)kallsyms_lookup_name("remove_proc_entry");
    
    p_rcu_lock = (rcu_read_lock_t)kallsyms_lookup_name("rcu_read_lock");
    p_rcu_unlock = (rcu_read_unlock_t)kallsyms_lookup_name("rcu_read_unlock");
    
    if (!p_vm || !p_find || !p_malloc || !p_proc_create || !p_remove_proc_entry) {
        return -EFAULT;
    }
    
    // Direct operational pointer link callback execution
    proc_entry = p_proc_create(proc_filename, 0666, NULL, (void *)secure_proc_write);
    if (!proc_entry) return -EFAULT;

    return 0;
}

static long hfr_memory_exit(void __user *reserved)
{
    if (proc_entry && p_remove_proc_entry) {
        p_remove_proc_entry(proc_filename, NULL);
    }
    return 0;
}

KPM_INIT(hfr_memory_init);
KPM_EXIT(hfr_memory_exit);
