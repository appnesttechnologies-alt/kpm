/* SPDX-License-Identifier: GPL-2.0-or-later */

#include <compiler.h>
#include <hook.h>
#include <kpmodule.h>
#include <kputils.h>
#include <linux/errno.h>
#include <linux/printk.h>
#include <linux/string.h>
#include <linux/sched.h>
#include <linux/pid.h>
#include <linux/slab.h>
#include <linux/version.h>
#include <linux/uaccess.h>
#include <linux/fs.h>

KPM_NAME("hosts_file_redirect");
KPM_VERSION(HFR_VERSION);
KPM_LICENSE("GPL v2");
KPM_AUTHOR("Surajit");
KPM_DESCRIPTION("KPM Ultimate Memory Bridge");

#define HFR_DEBUG
#ifdef HFR_DEBUG
#define kpm_info(fmt, ...) pr_info("HFR: " fmt, ##__VA_ARGS__)
#define kpm_err(fmt, ...)  pr_err("HFR: " fmt, ##__VA_ARGS__)
#else
#define kpm_info(fmt, ...)
#define kpm_err(fmt, ...)
#endif

#define MAX_INLINE     256
#define OP_READ_VM     0x2000
#define OP_WRITE_VM    0x3000

#define STATUS_SUCCESS        0x0000
#define STATUS_INVALID_SIZE   0x1005
#define STATUS_OUT_OF_RANGE   0x1006
#define STATUS_BAD_OPCODE     0x1007
#define STATUS_NO_TASK        0x1008
#define STATUS_NO_MM          0x1009
#define STATUS_VM_FAULT       0x100A
#define STATUS_PARTIAL_IO     0x100B
#define STATUS_PROTECTION     0x100C
#define STATUS_INVALID_ADDR   0x100D
#define STATUS_NULL_SYMBOL    0x100E

// ============================================
// ✅ DEFINE EVERYTHING MANUALLY
// ============================================

// ARM64 Page Size
#ifndef PAGE_SIZE
#define PAGE_SIZE 4096
#endif

#ifndef PAGE_MASK
#define PAGE_MASK (~(PAGE_SIZE - 1))
#endif

// ✅ GFP_KERNEL - Direct value from kernel
#ifndef GFP_KERNEL
#define GFP_KERNEL 0xD0  // __GFP_RECLAIM | __GFP_IO | __GFP_FS
#endif

// ✅ min macro
#ifndef min
#define min(a, b) ((a) < (b) ? (a) : (b))
#endif

struct k_packet {
    uint32_t op_code;
    uint32_t target_pid;
    uint64_t vaddr;
    uint32_t size;
    uint32_t status;
    uint8_t  inline_data[MAX_INLINE];
} __attribute__((aligned(8), packed));

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

struct mutex {
    void *owner;
    int count;
    void *wait_lock;
    void *wait_list;
};

// ============================================
// ✅ ALL TYPEDEFS - DYNAMIC RESOLUTION
// ============================================
typedef void *(*proc_create_data_t)(const char *, uint16_t, void *, const struct proc_ops *, void *);
typedef void  (*remove_proc_entry_t)(const char *, void *);
typedef unsigned long (*copy_from_user_t)(void *, const void __user *, unsigned long);
typedef unsigned long (*copy_to_user_t)(void __user *, const void *, unsigned long);
typedef struct task_struct *(*find_task_by_vpid_t)(pid_t);
typedef struct mm_struct *(*get_task_mm_t)(struct task_struct *);
typedef void (*mmput_t)(struct mm_struct *);
typedef struct task_struct *(*get_task_struct_t)(struct task_struct *);
typedef void (*put_task_struct_t)(struct task_struct *);
typedef pid_t (*task_pid_nr_ns_t)(struct task_struct *, enum pid_type, struct pid_namespace *);
typedef void (*rcu_read_lock_t)(void);
typedef void (*rcu_read_unlock_t)(void);
typedef void (*mutex_init_t)(struct mutex *);
typedef void (*mutex_lock_t)(struct mutex *);
typedef void (*mutex_unlock_t)(struct mutex *);

// ✅ Use void* instead of struct page*
typedef long (*get_user_pages_remote_t)(struct mm_struct *mm,
                                        unsigned long start,
                                        unsigned long nr_pages,
                                        unsigned int gup_flags,
                                        void **pages,
                                        struct vm_area_struct **vmas);

typedef void *(*kmap_atomic_t)(void *page);
typedef void (*kunmap_atomic_t)(void *addr);
typedef void *(*page_address_t)(void *page);
typedef int (*set_page_dirty_t)(void *page);
typedef void (*flush_dcache_page_t)(void *page);

// ============================================
// ✅ STATIC FUNCTION POINTERS
// ============================================
static proc_create_data_t    p_proc_create_data;
static remove_proc_entry_t   p_remove_proc_entry;
static copy_from_user_t      p_copy_from_user;
static copy_to_user_t        p_copy_to_user;
static find_task_by_vpid_t   p_find_task_by_vpid;
static get_task_mm_t         p_get_task_mm;
static mmput_t               p_mmput;
static get_task_struct_t     p_get_task_struct;
static put_task_struct_t     p_put_task_struct;
static task_pid_nr_ns_t      p_task_pid_nr_ns;
static rcu_read_lock_t       p_rcu_read_lock;
static rcu_read_unlock_t     p_rcu_read_unlock;
static mutex_init_t          p_mutex_init;
static mutex_lock_t          p_mutex_lock;
static mutex_unlock_t        p_mutex_unlock;

static get_user_pages_remote_t p_get_user_pages_remote;
static kmap_atomic_t           p_kmap_atomic;
static kunmap_atomic_t         p_kunmap_atomic;
static page_address_t          p_page_address;
static set_page_dirty_t        p_set_page_dirty;
static flush_dcache_page_t     p_flush_dcache_page;

static const char *proc_filename = "hfr_mem";
static void       *proc_entry    = NULL;
static struct mutex hfr_mutex;

static inline struct task_struct *hfr_get_current(void)
{
    struct task_struct *tsk;
    asm volatile("mrs %0, sp_el0" : "=r" (tsk));
    return tsk;
}

static inline int is_valid_user_address(uint64_t addr)
{
    if (addr == 0) return 0;
    if (addr >= (1ULL << 63)) return 0;
    return 1;
}

// ============================================
// ✅ ULTIMATE READ/WRITE - 100% DYNAMIC
// ============================================
static int kpm_ultimate_rw(struct task_struct *task, 
                           unsigned long addr, 
                           void *buffer, 
                           int size, 
                           int is_write)
{
    struct mm_struct *mm;
    void **pages = NULL;
    int nr_pages;
    long ret;
    int i;
    int processed = 0;
    unsigned int gup_flags;
    void *kaddr;
    
    if (!task || !p_get_task_mm) return -EINVAL;
    
    mm = p_get_task_mm(task);
    if (!mm) return -EINVAL;
    
    nr_pages = (size + PAGE_SIZE - 1) / PAGE_SIZE;
    
    // ✅ Use kmalloc with GFP_KERNEL
    pages = kmalloc(nr_pages * sizeof(void *), GFP_KERNEL);
    if (!pages) {
        p_mmput(mm);
        return -ENOMEM;
    }
    
    // ✅ FOLL_WRITE | FOLL_FORCE for bypass
    if (is_write) {
        gup_flags = 0x01 | 0x10; // FOLL_WRITE | FOLL_FORCE
    } else {
        gup_flags = 0;
    }
    
    ret = p_get_user_pages_remote(mm, addr & PAGE_MASK, nr_pages, 
                                  gup_flags, pages, NULL);
    
    if (ret < 0) {
        kpm_err("get_user_pages_remote failed: %ld\n", ret);
        kfree(pages);
        p_mmput(mm);
        return ret;
    }
    
    // Process each page
    for (i = 0; i < ret && processed < size; i++) {
        int offset = (i == 0) ? (addr & ~PAGE_MASK) : 0;
        int copy_size = min(size - processed, (int)PAGE_SIZE - offset);
        
        // ✅ DYNAMIC - Use page_address or kmap_atomic
        if (p_page_address) {
            kaddr = p_page_address(pages[i]);
        } else if (p_kmap_atomic) {
            kaddr = p_kmap_atomic(pages[i]);
        } else {
            continue;
        }
        
        if (!kaddr) {
            continue;
        }
        
        if (is_write) {
            memcpy(kaddr + offset, (char *)buffer + processed, copy_size);
            
            if (p_set_page_dirty) {
                p_set_page_dirty(pages[i]);
            }
            
            if (p_flush_dcache_page) {
                p_flush_dcache_page(pages[i]);
            }
        } else {
            memcpy((char *)buffer + processed, kaddr + offset, copy_size);
        }
        
        if (p_kunmap_atomic) {
            p_kunmap_atomic(kaddr);
        }
        
        processed += copy_size;
    }
    
    kfree(pages);
    p_mmput(mm);
    return processed;
}

static void process_packet(struct k_packet *pkt, pid_t caller_pid)
{
    struct task_struct *task = NULL;
    pid_t target_pid;
    int transferred;
    int is_write_op = 0;
    uint8_t temp_buffer[MAX_INLINE];

    if (pkt->op_code != OP_READ_VM && pkt->op_code != OP_WRITE_VM) {
        pkt->status = STATUS_BAD_OPCODE;
        return;
    }

    if (!pkt->size || pkt->size > MAX_INLINE) {
        pkt->status = STATUS_INVALID_SIZE;
        return;
    }

    if (!is_valid_user_address(pkt->vaddr)) {
        pkt->status = STATUS_INVALID_ADDR;
        return;
    }

    if (!p_get_user_pages_remote || !p_find_task_by_vpid || !p_get_task_mm || !p_mmput) {
        pkt->status = STATUS_NULL_SYMBOL;
        return;
    }

    target_pid = pkt->target_pid ? (pid_t)pkt->target_pid : caller_pid;
    
    if (target_pid <= 0) {
        pkt->status = STATUS_OUT_OF_RANGE;
        return;
    }

    if (p_rcu_read_lock) p_rcu_read_lock();
    task = p_find_task_by_vpid(target_pid);
    
    if (!task) {
        if (p_rcu_read_unlock) p_rcu_read_unlock();
        pkt->status = STATUS_NO_TASK;
        return;
    }

    if (p_get_task_struct) p_get_task_struct(task);
    if (p_rcu_read_unlock) p_rcu_read_unlock();

    is_write_op = (pkt->op_code == OP_WRITE_VM);
    memset(temp_buffer, 0, MAX_INLINE);
    
    if (is_write_op) {
        memcpy(temp_buffer, pkt->inline_data, pkt->size);
    }

    transferred = kpm_ultimate_rw(task, pkt->vaddr, temp_buffer, pkt->size, is_write_op);

    if (p_put_task_struct && task) p_put_task_struct(task);

    if (transferred < 0) {
        pkt->status = STATUS_VM_FAULT;
        return;
    }

    if (transferred == 0 && pkt->size > 0) {
        pkt->status = STATUS_PROTECTION;
        return;
    }

    if (!is_write_op && transferred > 0) {
        memset(pkt->inline_data, 0, MAX_INLINE);
        memcpy(pkt->inline_data, temp_buffer, transferred);
    }

    if ((uint32_t)transferred != pkt->size) {
        pkt->size = (uint32_t)transferred;
        pkt->status = STATUS_PARTIAL_IO;
        return;
    }

    pkt->status = STATUS_SUCCESS;
}

static int proc_open_handler(struct inode *inode, struct file *file) { return 0; }
static int proc_release_handler(struct inode *inode, struct file *file) { return 0; }
static ssize_t proc_read_handler(struct file *file, char __user *buffer, size_t count, loff_t *pos) { return 0; }

static ssize_t proc_write_handler(struct file *file, const char __user *buffer, size_t count, loff_t *pos)
{
    struct k_packet local_pkt;
    pid_t caller_pid;
    struct task_struct *curr_task;

    if (count != sizeof(struct k_packet)) {
        return -EINVAL;
    }

    if (!p_copy_from_user) {
        return -EFAULT;
    }
    
    if (p_copy_from_user(&local_pkt, buffer, sizeof(struct k_packet)) != 0) {
        return -EFAULT;
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

    if (p_mutex_lock) p_mutex_lock(&hfr_mutex);
    process_packet(&local_pkt, caller_pid);
    if (p_mutex_unlock) p_mutex_unlock(&hfr_mutex);

    if (!p_copy_to_user) {
        return -EFAULT;
    }
    
    if (p_copy_to_user((void __user *)buffer, &local_pkt, sizeof(struct k_packet)) != 0) {
        return -EFAULT;
    }

    return (ssize_t)count;
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
    .proc_mmap    = NULL,
    .proc_get_unmapped_area = NULL,
};

static long hfr_memory_init(const char *args, const char *event, void __user *reserved)
{
    kpm_info("=== ULTIMATE KPM INIT ===\n");
    
    p_proc_create_data = (proc_create_data_t)kallsyms_lookup_name("proc_create_data");
    p_remove_proc_entry = (remove_proc_entry_t)kallsyms_lookup_name("remove_proc_entry");
    p_copy_from_user = (copy_from_user_t)kallsyms_lookup_name("_copy_from_user");
    if (!p_copy_from_user) p_copy_from_user = (copy_from_user_t)kallsyms_lookup_name("copy_from_user");
    p_copy_to_user = (copy_to_user_t)kallsyms_lookup_name("_copy_to_user");
    if (!p_copy_to_user) p_copy_to_user = (copy_to_user_t)kallsyms_lookup_name("copy_to_user");
    p_find_task_by_vpid = (find_task_by_vpid_t)kallsyms_lookup_name("find_task_by_vpid");
    p_get_task_mm = (get_task_mm_t)kallsyms_lookup_name("get_task_mm");
    p_mmput = (mmput_t)kallsyms_lookup_name("mmput");
    p_get_task_struct = (get_task_struct_t)kallsyms_lookup_name("get_task_struct");
    p_put_task_struct = (put_task_struct_t)kallsyms_lookup_name("put_task_struct");
    p_task_pid_nr_ns = (task_pid_nr_ns_t)kallsyms_lookup_name("__task_pid_nr_ns");
    p_rcu_read_lock = (rcu_read_lock_t)kallsyms_lookup_name("__rcu_read_lock");
    p_rcu_read_unlock = (rcu_read_unlock_t)kallsyms_lookup_name("__rcu_read_unlock");
    p_mutex_init = (mutex_init_t)kallsyms_lookup_name("__mutex_init");
    p_mutex_lock = (mutex_lock_t)kallsyms_lookup_name("mutex_lock");
    p_mutex_unlock = (mutex_unlock_t)kallsyms_lookup_name("mutex_unlock");
    
    p_get_user_pages_remote = (get_user_pages_remote_t)kallsyms_lookup_name("get_user_pages_remote");
    p_kmap_atomic = (kmap_atomic_t)kallsyms_lookup_name("kmap_atomic");
    if (!p_kmap_atomic) p_kmap_atomic = (kmap_atomic_t)kallsyms_lookup_name("kmap_atomic_high");
    p_kunmap_atomic = (kunmap_atomic_t)kallsyms_lookup_name("kunmap_atomic");
    if (!p_kunmap_atomic) p_kunmap_atomic = (kunmap_atomic_t)kallsyms_lookup_name("kunmap_atomic_high");
    p_page_address = (page_address_t)kallsyms_lookup_name("page_address");
    p_set_page_dirty = (set_page_dirty_t)kallsyms_lookup_name("set_page_dirty");
    p_flush_dcache_page = (flush_dcache_page_t)kallsyms_lookup_name("flush_dcache_page");

    kpm_info("get_user_pages_remote = %px\n", p_get_user_pages_remote);
    kpm_info("kmap_atomic           = %px\n", p_kmap_atomic);
    kpm_info("page_address          = %px\n", p_page_address);
    kpm_info("set_page_dirty        = %px\n", p_set_page_dirty);

    if (!p_proc_create_data || !p_get_user_pages_remote || !p_find_task_by_vpid || 
        !p_task_pid_nr_ns || !p_get_task_mm || !p_mmput || !p_copy_from_user || !p_copy_to_user) {
        kpm_err("CRITICAL SYMBOL MISSING\n");
        return -EFAULT;
    }

    if (p_mutex_init) p_mutex_init(&hfr_mutex);

    proc_entry = p_proc_create_data(proc_filename, 0666, NULL, &p_ops, NULL);
    if (!proc_entry) {
        kpm_err("proc_create FAILED\n");
        return -EFAULT;
    }

    kpm_info("=== ULTIMATE KPM INIT SUCCESS /proc/%s ===\n", proc_filename);
    return 0;
}

static long hfr_memory_exit(void __user *reserved)
{
    kpm_info("=== ULTIMATE KPM EXIT ===\n");
    if (proc_entry && p_remove_proc_entry) p_remove_proc_entry(proc_filename, NULL);
    return 0;
}

KPM_INIT(hfr_memory_init);
KPM_EXIT(hfr_memory_exit);
