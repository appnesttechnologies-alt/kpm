/* SPDX-License-Identifier: GPL-2.0-or-later */

#include <compiler.h>
#include <hook.h>
#include <kpmodule.h>
#include <kputils.h>
#include <linux/errno.h>
#include <linux/printk.h>
#include <linux/string.h>
#include <linux/sched.h>
#include <linux/mm.h>
#include <linux/pid.h>
#include <linux/slab.h>
#include <linux/version.h>
#include <linux/shmem_fs.h>
#include <linux/mman.h>

KPM_NAME("hosts_file_redirect");
KPM_VERSION(HFR_VERSION);
KPM_LICENSE("GPL v2");
KPM_AUTHOR("Surajit");
KPM_DESCRIPTION("KPM Shared Memory Bridge via access_process_vm");

#define HFR_DEBUG
#ifdef HFR_DEBUG
#define kpm_info(fmt, ...) pr_info("HFR: " fmt, ##__VA_ARGS__)
#define kpm_err(fmt, ...)  pr_err("HFR: " fmt, ##__VA_ARGS__)
#else
#define kpm_info(fmt, ...)
#define kpm_err(fmt, ...)
#endif

// ============================================================
// SHARED MEMORY STRUCTURE
// ============================================================

#define SHM_SIZE         4096
#define MAX_OPS          64
#define PAGE_SIZE_4K     4096

#define OP_READ_VM       0x2000
#define OP_WRITE_VM      0x3000

struct shm_op {
    uint64_t addr;
    uint32_t size;
    uint32_t op;           // OP_READ_VM or OP_WRITE_VM
    int32_t  result;       // 0=success, negative=error
} __attribute__((aligned(8), packed));

struct shm_header {
    uint32_t magic;         // 0x4846524D ("HFRM")
    uint32_t target_pid;
    uint32_t op_count;      // Number of operations to process
    uint32_t version;       // Version for cache invalidation
    uint32_t result_count;  // Completed operations
    uint32_t pad[3];
} __attribute__((aligned(8), packed));

// Layout: [shm_header][shm_op array][data buffer]
// data_offset = sizeof(shm_header) + (MAX_OPS * sizeof(shm_op))

typedef void *(*proc_create_data_t)(const char *, uint16_t, void *, const struct proc_ops *, void *);
typedef void  (*remove_proc_entry_t)(const char *, void *);
typedef int (*access_process_vm_t)(struct task_struct *, unsigned long, void *, int, unsigned int);
typedef struct task_struct *(*find_task_by_vpid_t)(pid_t);
typedef struct mm_struct *(*get_task_mm_t)(struct task_struct *);
typedef void (*mmput_t)(struct mm_struct *);
typedef struct task_struct *(*get_task_struct_t)(struct task_struct *);
typedef void (*put_task_struct_t)(struct task_struct *);
typedef pid_t (*task_pid_nr_ns_t)(struct task_struct *, enum pid_type, struct pid_namespace *);
typedef void (*rcu_read_lock_t)(void);
typedef void (*rcu_read_unlock_t)(void);

static proc_create_data_t    p_proc_create_data;
static remove_proc_entry_t   p_remove_proc_entry;
static access_process_vm_t   p_access_process_vm;
static find_task_by_vpid_t   p_find_task_by_vpid;
static get_task_mm_t         p_get_task_mm;
static mmput_t               p_mmput;
static get_task_struct_t     p_get_task_struct;
static put_task_struct_t     p_put_task_struct;
static task_pid_nr_ns_t      p_task_pid_nr_ns;
static rcu_read_lock_t       p_rcu_read_lock;
static rcu_read_unlock_t     p_rcu_read_unlock;

static const char *proc_filename = "hfr_mem";
static void       *proc_entry    = NULL;
static struct shm_header *shm_base = NULL;
static size_t       shm_size = 0;

static inline struct task_struct *hfr_get_current(void)
{
    struct task_struct *tsk;
    asm volatile("mrs %0, sp_el0" : "=r" (tsk));
    return tsk;
}

// ============================================================
// BATCH PROCESSING - Process all ops in one shot
// ============================================================

static void process_batch(struct shm_header *hdr, pid_t caller_pid)
{
    struct task_struct *task = NULL;
    struct mm_struct *mm = NULL;
    pid_t target_pid;
    int i;
    uint32_t count;

    if (!hdr || hdr->magic != 0x4846524D) {
        kpm_err("Invalid magic: 0x%x\n", hdr ? hdr->magic : 0);
        return;
    }

    count = hdr->op_count;
    if (count > MAX_OPS) count = MAX_OPS;
    if (count == 0) return;

    hdr->result_count = 0;

    target_pid = hdr->target_pid ? (pid_t)hdr->target_pid : caller_pid;
    if (target_pid <= 0) {
        // Mark all as failed
        struct shm_op *ops = (struct shm_op *)(hdr + 1);
        for (i = 0; i < count; i++) {
            ops[i].result = -EINVAL;
        }
        hdr->result_count = count;
        return;
    }

    // Find target task
    if (p_rcu_read_lock) p_rcu_read_lock();
    task = p_find_task_by_vpid(target_pid);
    
    if (!task) {
        if (p_rcu_read_unlock) p_rcu_read_unlock();
        struct shm_op *ops = (struct shm_op *)(hdr + 1);
        for (i = 0; i < count; i++) {
            ops[i].result = -ESRCH;
        }
        hdr->result_count = count;
        return;
    }

    if (p_get_task_struct) p_get_task_struct(task);
    mm = p_get_task_mm(task);
    if (p_rcu_read_unlock) p_rcu_read_unlock();

    if (!mm) {
        if (p_put_task_struct && task) p_put_task_struct(task);
        struct shm_op *ops = (struct shm_op *)(hdr + 1);
        for (i = 0; i < count; i++) {
            ops[i].result = -ESRCH;
        }
        hdr->result_count = count;
        return;
    }

    // Calculate data buffer base
    struct shm_op *ops = (struct shm_op *)(hdr + 1);
    uint8_t *data_base = (uint8_t *)ops + (MAX_OPS * sizeof(struct shm_op));
    uint32_t data_offset = 0;

    // Process all operations
    for (i = 0; i < count; i++) {
        struct shm_op *op = &ops[i];
        
        if (op->size == 0 || op->size > 256) {
            op->result = -EINVAL;
            hdr->result_count++;
            continue;
        }

        if (op->addr < 0x1000) {
            op->result = -EINVAL;
            hdr->result_count++;
            continue;
        }

        void *data_ptr = data_base + data_offset;
        unsigned int gup_flags = (op->op == OP_WRITE_VM) ? 0x01 : 0x00; // FOLL_WRITE if write

        int transferred = p_access_process_vm(task, (unsigned long)op->addr, 
                                               data_ptr, (int)op->size, gup_flags);
        
        if (transferred < 0) {
            op->result = transferred;
            op->size = 0;
        } else {
            op->result = 0;
            if (op->op == OP_READ_VM) {
                op->size = (uint32_t)transferred;
            }
        }

        data_offset += op->size;
        if (data_offset >= SHM_SIZE - sizeof(struct shm_header) - (MAX_OPS * sizeof(struct shm_op))) {
            break; // Prevent overflow
        }
        
        hdr->result_count++;
    }

    if (mm) p_mmput(mm);
    if (p_put_task_struct && task) p_put_task_struct(task);
    
    // Increment version for userspace cache invalidation
    hdr->version++;
}

// ============================================================
// MMAP HANDLER - Map shared memory to userspace
// ============================================================

static int proc_mmap_handler(struct file *file, struct vm_area_struct *vma)
{
    unsigned long size = vma->vm_end - vma->vm_start;
    
    if (size > SHM_SIZE) {
        return -EINVAL;
    }
    
    // Remap kernel buffer to userspace
    if (remap_pfn_range(vma, vma->vm_start, 
                        virt_to_phys(shm_base) >> PAGE_SHIFT,
                        size, vma->vm_page_prot)) {
        return -EAGAIN;
    }
    
    return 0;
}

static int proc_open_handler(struct inode *inode, struct file *file) 
{ 
    return 0; 
}

static int proc_release_handler(struct inode *inode, struct file *file) 
{ 
    return 0; 
}

static ssize_t proc_read_handler(struct file *file, char __user *buffer, 
                                  size_t count, loff_t *pos) 
{ 
    return 0; 
}

static ssize_t proc_write_handler(struct file *file, const char __user *buffer, 
                                   size_t count, loff_t *pos)
{
    pid_t caller_pid;
    struct task_struct *curr_task;

    if (!shm_base) {
        return -ENOMEM;
    }

    curr_task = hfr_get_current();
    if (!curr_task) {
        return -ESRCH;
    }

    if (!p_task_pid_nr_ns) {
        return -EFAULT;
    }

    caller_pid = p_task_pid_nr_ns(curr_task, PIDTYPE_PID, NULL);
    if (caller_pid <= 0) {
        return -ESRCH;
    }

    // Process batch from shared memory
    process_batch(shm_base, caller_pid);

    return (ssize_t)sizeof(uint32_t); // Signal completion
}

static const struct proc_ops p_ops = {
    .proc_flags   = 0,
    .proc_open    = proc_open_handler,
    .proc_read    = proc_read_handler,
    .proc_read_iter = NULL,
    .proc_write   = proc_write_handler,
    .proc_lseek   = NULL,
    .proc_release = proc_release_handler,
    .proc_poll    = NULL,
    .proc_ioctl   = NULL,
    .proc_mmap    = proc_mmap_handler,
    .proc_get_unmapped_area = NULL,
};

static long hfr_memory_init(const char *args, const char *event, void __user *reserved)
{
    kpm_info("=== INIT START ===\n");
    
    p_proc_create_data = (proc_create_data_t)kallsyms_lookup_name("proc_create_data");
    p_remove_proc_entry = (remove_proc_entry_t)kallsyms_lookup_name("remove_proc_entry");
    p_access_process_vm = (access_process_vm_t)kallsyms_lookup_name("access_process_vm");
    p_find_task_by_vpid = (find_task_by_vpid_t)kallsyms_lookup_name("find_task_by_vpid");
    p_get_task_mm = (get_task_mm_t)kallsyms_lookup_name("get_task_mm");
    p_mmput = (mmput_t)kallsyms_lookup_name("mmput");
    p_get_task_struct = (get_task_struct_t)kallsyms_lookup_name("get_task_struct");
    p_put_task_struct = (put_task_struct_t)kallsyms_lookup_name("put_task_struct");
    p_task_pid_nr_ns = (task_pid_nr_ns_t)kallsyms_lookup_name("__task_pid_nr_ns");
    p_rcu_read_lock = (rcu_read_lock_t)kallsyms_lookup_name("__rcu_read_lock");
    p_rcu_read_unlock = (rcu_read_unlock_t)kallsyms_lookup_name("__rcu_read_unlock");

    if (!p_proc_create_data || !p_access_process_vm || !p_find_task_by_vpid || 
        !p_task_pid_nr_ns || !p_get_task_mm || !p_mmput) {
        kpm_err("CRITICAL SYMBOL MISSING\n");
        return -EFAULT;
    }

    // Allocate shared memory
    shm_size = SHM_SIZE;
    shm_base = (struct shm_header *)kzalloc(shm_size, GFP_KERNEL);
    if (!shm_base) {
        kpm_err("Failed to allocate shared memory\n");
        return -ENOMEM;
    }

    shm_base->magic = 0x4846524D;
    shm_base->version = 0;

    proc_entry = p_proc_create_data(proc_filename, 0666, NULL, &p_ops, NULL);
    if (!proc_entry) {
        kpm_err("proc_create FAILED\n");
        kfree(shm_base);
        shm_base = NULL;
        return -EFAULT;
    }

    kpm_info("=== INIT SUCCESS /proc/%s (SHM: %px, size: %zu) ===\n", 
             proc_filename, shm_base, shm_size);
    return 0;
}

static long hfr_memory_exit(void __user *reserved)
{
    kpm_info("=== EXIT ===\n");
    if (proc_entry && p_remove_proc_entry) {
        p_remove_proc_entry(proc_filename, NULL);
    }
    if (shm_base) {
        kfree(shm_base);
        shm_base = NULL;
    }
    return 0;
}

KPM_INIT(hfr_memory_init);
KPM_EXIT(hfr_memory_exit);
