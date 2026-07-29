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
#include <asm/pgtable.h>

KPM_NAME("hosts_file_redirect");
KPM_VERSION(HFR_VERSION);
KPM_LICENSE("GPL v2");
KPM_AUTHOR("Surajit");
KPM_DESCRIPTION("KPM Shared Memory Bridge via access_process_vm");

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

#define SHM_SIZE         8192    // 2 pages
#define MAX_OPS          128
#define DATA_BUFFER_SIZE 4096

#define OP_READ_VM       0x2000
#define OP_WRITE_VM      0x3000

#define HFR_FOLL_WRITE   0x01
#define FOLL_FORCE       0x10

struct shm_op {
    uint64_t addr;
    uint32_t size;
    uint32_t op;
    int32_t  result;
} __attribute__((aligned(8), packed));

struct shm_header {
    uint32_t magic;         // 0x4846524D
    uint32_t target_pid;
    uint32_t op_count;
    uint32_t version;
    uint32_t result_count;
    uint32_t data_size;
    uint32_t pad[2];
} __attribute__((aligned(8), packed));

// ============================================================
// SYMBOL TYPEDEFS
// ============================================================

typedef void *(*proc_create_data_t)(const char *, uint16_t, void *, const void *, void *);
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

// ============================================================
// FILE OPS STRUCT (KPM-compatible)
// ============================================================

struct inode;
struct file;
struct kiocb;
struct iov_iter;
struct poll_table_struct;
struct vm_area_struct;
typedef unsigned int __poll_t;

struct proc_ops {
    unsigned int proc_flags;
    int      (*proc_open)(struct inode *, struct file *);
    ssize_t  (*proc_read)(struct file *, char __user *, size_t, loff_t *);
    ssize_t  (*proc_read_iter)(struct kiocb *, struct iov_iter *);
    ssize_t  (*proc_write)(struct file *, const char __user *, size_t, loff_t *);
    loff_t   (*proc_lseek)(struct file *, loff_t, int);
    int      (*proc_release)(struct inode *, struct file *);
    __poll_t (*proc_poll)(struct file *, struct poll_table_struct *);
    long     (*proc_ioctl)(struct file *, unsigned int, unsigned long);
    int      (*proc_mmap)(struct file *, struct vm_area_struct *);
    unsigned long (*proc_get_unmapped_area)(struct file *, unsigned long, unsigned long, unsigned long, unsigned long);
};

// ============================================================
// GLOBALS
// ============================================================

static proc_create_data_t    p_proc_create_data = NULL;
static remove_proc_entry_t   p_remove_proc_entry = NULL;
static access_process_vm_t   p_access_process_vm = NULL;
static find_task_by_vpid_t   p_find_task_by_vpid = NULL;
static get_task_mm_t         p_get_task_mm = NULL;
static mmput_t               p_mmput = NULL;
static get_task_struct_t     p_get_task_struct = NULL;
static put_task_struct_t     p_put_task_struct = NULL;
static task_pid_nr_ns_t      p_task_pid_nr_ns = NULL;
static rcu_read_lock_t       p_rcu_read_lock = NULL;
static rcu_read_unlock_t     p_rcu_read_unlock = NULL;

static const char *proc_filename = "hfr_mem";
static void       *proc_entry    = NULL;
static void       *shm_kernel    = NULL;
static size_t      shm_size      = 0;

// ============================================================
// HELPER: Get current task
// ============================================================

static inline struct task_struct *hfr_get_current(void)
{
    struct task_struct *tsk;
    asm volatile("mrs %0, sp_el0" : "=r" (tsk));
    return tsk;
}

// ============================================================
// BATCH PROCESSING
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
    if (count == 0) {
        hdr->result_count = 0;
        return;
    }

    hdr->result_count = 0;
    hdr->data_size = 0;

    target_pid = hdr->target_pid ? (pid_t)hdr->target_pid : caller_pid;
    if (target_pid <= 0) {
        struct shm_op *ops = (struct shm_op *)(hdr + 1);
        for (i = 0; i < (int)count; i++) {
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
        for (i = 0; i < (int)count; i++) {
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
        for (i = 0; i < (int)count; i++) {
            ops[i].result = -ESRCH;
        }
        hdr->result_count = count;
        return;
    }

    // Get pointers
    struct shm_op *ops = (struct shm_op *)(hdr + 1);
    uint8_t *data_base = (uint8_t *)ops + (MAX_OPS * sizeof(struct shm_op));
    uint32_t current_offset = 0;

    // Process all operations
    for (i = 0; i < (int)count; i++) {
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

        if (current_offset + op->size > DATA_BUFFER_SIZE) {
            op->result = -ENOSPC;
            hdr->result_count++;
            break;
        }

        void *data_ptr = data_base + current_offset;
        
        unsigned int gup_flags;
        if (op->op == OP_WRITE_VM) {
            gup_flags = HFR_FOLL_WRITE | FOLL_FORCE;
        } else {
            gup_flags = FOLL_FORCE;
        }

        int transferred = p_access_process_vm(task, (unsigned long)op->addr, 
                                               data_ptr, (int)op->size, gup_flags);
        
        if (transferred < 0) {
            op->result = transferred;
            op->size = 0;
        } else if (transferred == 0 && op->size > 0) {
            op->result = -EACCES;
            op->size = 0;
        } else {
            op->result = 0;
            if (op->op == OP_READ_VM) {
                op->size = (uint32_t)transferred;
            }
            current_offset += op->size;
        }
        
        hdr->result_count++;
    }

    hdr->data_size = current_offset;

    if (mm) p_mmput(mm);
    if (p_put_task_struct && task) p_put_task_struct(task);
    
    // Increment version for userspace polling
    hdr->version++;
}

// ============================================================
// MMAP HANDLER
// ============================================================

static int proc_mmap_handler(struct file *file, struct vm_area_struct *vma)
{
    unsigned long size = vma->vm_end - vma->vm_start;
    unsigned long pfn;
    int ret;

    if (!shm_kernel) {
        kpm_err("mmap: shm_kernel is NULL\n");
        return -ENOMEM;
    }

    if (size > shm_size) {
        kpm_err("mmap: requested %lu > shm_size %zu\n", size, shm_size);
        return -EINVAL;
    }

    // Cast pointer to uint64_t for virt_to_phys
    pfn = virt_to_phys((uint64_t)(unsigned long)shm_kernel) >> PAGE_SHIFT;
    
    // Set VM flags
    vma->vm_flags |= VM_IO | VM_DONTEXPAND | VM_DONTDUMP;
    vma->vm_page_prot = pgprot_noncached(vma->vm_page_prot);

    // Map the physical pages to userspace
    ret = remap_pfn_range(vma, vma->vm_start, pfn, size, vma->vm_page_prot);
    if (ret) {
        kpm_err("mmap: remap_pfn_range failed: %d\n", ret);
        return -EAGAIN;
    }

    kpm_info("mmap: mapped %lu bytes at 0x%lx\n", size, vma->vm_start);
    return 0;
}

// ============================================================
// FILE OPERATIONS
// ============================================================

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

    if (!shm_kernel) {
        kpm_err("write: shm_kernel is NULL\n");
        return -ENOMEM;
    }

    curr_task = hfr_get_current();
    if (!curr_task) {
        kpm_err("write: get_current failed\n");
        return -ESRCH;
    }

    if (!p_task_pid_nr_ns) {
        kpm_err("write: task_pid_nr_ns is NULL\n");
        return -EFAULT;
    }

    caller_pid = p_task_pid_nr_ns(curr_task, PIDTYPE_PID, NULL);
    if (caller_pid <= 0) {
        kpm_err("write: invalid caller_pid: %d\n", caller_pid);
        return -ESRCH;
    }

    // Process batch from shared memory
    process_batch((struct shm_header *)shm_kernel, caller_pid);

    // Return number of ops completed
    struct shm_header *hdr = (struct shm_header *)shm_kernel;
    return (ssize_t)hdr->result_count;
}

// Use const to match KPM's expected proc_ops signature
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

// ============================================================
// INIT / EXIT
// ============================================================

static long hfr_memory_init(const char *args, const char *event, void __user *reserved)
{
    kpm_info("=== INIT START ===\n");
    
    // Resolve all symbols
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

    kpm_info("Symbols: proc=%px vm=%px task=%px mm=%px\n",
             (void *)p_proc_create_data, (void *)p_access_process_vm, 
             (void *)p_find_task_by_vpid, (void *)p_get_task_mm);

    if (!p_proc_create_data || !p_access_process_vm || !p_find_task_by_vpid || 
        !p_task_pid_nr_ns || !p_get_task_mm || !p_mmput) {
        kpm_err("CRITICAL SYMBOL MISSING\n");
        return -EFAULT;
    }

    // Allocate shared memory
    shm_size = SHM_SIZE;
    shm_kernel = kzalloc(shm_size, GFP_KERNEL);
    if (!shm_kernel) {
        kpm_err("Failed to allocate %zu bytes\n", shm_size);
        return -ENOMEM;
    }

    // Initialize header
    struct shm_header *hdr = (struct shm_header *)shm_kernel;
    memset(hdr, 0, sizeof(struct shm_header));
    hdr->magic = 0x4846524D;
    hdr->version = 0;

    kpm_info("SHM allocated at %px (size: %zu)\n", shm_kernel, shm_size);

    // Create proc entry - cast away const for KPM compatibility
    proc_entry = p_proc_create_data(proc_filename, 0666, NULL, (const void *)&p_ops, NULL);
    if (!proc_entry) {
        kpm_err("proc_create FAILED for /proc/%s\n", proc_filename);
        kfree(shm_kernel);
        shm_kernel = NULL;
        return -EFAULT;
    }

    kpm_info("=== INIT SUCCESS /proc/%s ===\n", proc_filename);
    return 0;
}

static long hfr_memory_exit(void __user *reserved)
{
    kpm_info("=== EXIT ===\n");
    
    if (proc_entry && p_remove_proc_entry) {
        p_remove_proc_entry(proc_filename, NULL);
        proc_entry = NULL;
    }
    
    if (shm_kernel) {
        kfree(shm_kernel);
        shm_kernel = NULL;
    }
    
    return 0;
}

KPM_INIT(hfr_memory_init);
KPM_EXIT(hfr_memory_exit);
