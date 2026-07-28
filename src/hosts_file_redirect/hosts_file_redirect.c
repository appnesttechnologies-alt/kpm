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

KPM_NAME("hosts_file_redirect");
KPM_VERSION(HFR_VERSION);
KPM_LICENSE("GPL v2");
KPM_AUTHOR("Surajit");
KPM_DESCRIPTION("KPM Zero-Trace PTE Write Bypass via follow_pte");

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
#define STATUS_PTE_ERROR      0x100F
#define STATUS_WRITE_FAULT    0x1010

/* ARM64 PTE bits */
#define ARM64_PTE_VALID       (1UL << 0)
#define ARM64_PTE_RDONLY      (1UL << 7)
#define ARM64_PTE_WRITE       (1UL << 51)
#define ARM64_PAGE_SIZE       4096
#define ARM64_PAGE_MASK       (~(ARM64_PAGE_SIZE - 1))

struct k_packet {
    uint32_t op_code;
    uint32_t target_pid;
    uint64_t vaddr;
    uint32_t size;
    uint32_t status;
    uint8_t  inline_data[MAX_INLINE];
} __attribute__((aligned(8), packed));

/* Forward declarations */
struct inode;
struct file;
struct kiocb;
struct iov_iter;
struct poll_table_struct;
struct vm_area_struct;
struct mm_struct;
struct task_struct;
struct pid_namespace;
struct page;
typedef unsigned int __poll_t;

/* pte_t - NOT in KPM headers, define it here */
typedef unsigned long pte_t;

/* spinlock_t already in linux/spinlock.h - just forward declare */
struct spinlock;

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

struct mutex { void *owner; int count; void *wait_lock; void *wait_list; };

/* Function pointer typedefs */
typedef void *(*proc_create_data_t)(const char *, uint16_t, void *, const struct proc_ops *, void *);
typedef void  (*remove_proc_entry_t)(const char *, void *);
typedef unsigned long (*copy_from_user_t)(void *, const void __user *, unsigned long);
typedef unsigned long (*copy_to_user_t)(void __user *, const void *, unsigned long);
typedef int (*access_process_vm_t)(struct task_struct *, unsigned long, void *, int, unsigned int);
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

/* follow_pte: int follow_pte(struct mm_struct *, unsigned long, pte_t **, spinlock_t **) */
typedef int (*follow_pte_t)(struct mm_struct *, unsigned long, pte_t **, spinlock_t **);
typedef void (*spin_unlock_t)(spinlock_t *);

/* Resolved function pointers */
static proc_create_data_t    p_proc_create_data;
static remove_proc_entry_t   p_remove_proc_entry;
static copy_from_user_t      p_copy_from_user;
static copy_to_user_t        p_copy_to_user;
static access_process_vm_t   p_access_process_vm;
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

/* PTE bypass symbols */
static follow_pte_t     p_follow_pte;
static spin_unlock_t    p_spin_unlock;
static uint64_t        *p_memstart_addr;

static const char *proc_filename = "hfr_mem";
static void       *proc_entry    = NULL;
static struct mutex hfr_mutex;

/* ================================================================
 * ULTIMATE WRITE - follow_pte + PTE manipulation
 * ================================================================ */
static int hfr_pte_force_write(struct mm_struct *mm, unsigned long user_addr,
                                const void *buf, size_t len)
{
    pte_t *ptep = NULL;
    spinlock_t *ptlp = NULL;
    uint64_t pte_val, phys_addr, kern_va;
    uint64_t page_start, offset;
    size_t bytes, total = 0;
    int ret;

    kpm_info(">>> pte_force_write: mm=%px addr=0x%lx len=%zu\n", mm, user_addr, len);

    if (!mm || !buf || len == 0 || !p_follow_pte || !p_memstart_addr)
        return -EINVAL;

    while (total < len) {
        user_addr = (user_addr + total);
        page_start = user_addr & ARM64_PAGE_MASK;
        offset = user_addr & ~ARM64_PAGE_MASK;
        bytes = len - total;
        if (bytes > ARM64_PAGE_SIZE - offset)
            bytes = ARM64_PAGE_SIZE - offset;

        /* Get PTE using follow_pte */
        ret = p_follow_pte(mm, page_start, &ptep, &ptlp);
        if (ret < 0 || !ptep) {
            kpm_err("follow_pte failed at 0x%lx: %d\n", page_start, ret);
            return (total > 0) ? (int)total : -EFAULT;
        }

        pte_val = *ptep;

        if (!(pte_val & ARM64_PTE_VALID)) {
            kpm_err("PTE not valid at 0x%lx\n", page_start);
            if (ptlp && p_spin_unlock) p_spin_unlock(ptlp);
            return (total > 0) ? (int)total : -EFAULT;
        }

        /* Extract physical address (bits 47:12) */
        phys_addr = pte_val & 0x0000FFFFFFFFF000ULL;

        /* Convert to kernel VA: ARM64 linear map */
        kern_va = phys_addr | 0xFFFF000000000000ULL;

        /* Make PTE writable */
        pte_val &= ~ARM64_PTE_RDONLY;
        pte_val |= ARM64_PTE_WRITE;
        *ptep = pte_val;
        asm volatile("dsb ishst" ::: "memory");

        /* Direct write */
        memcpy((void *)(kern_va + offset), (const char *)buf + total, bytes);
        asm volatile("dsb ishst" ::: "memory");

        /* Restore PTE */
        pte_val &= ~ARM64_PTE_WRITE;
        pte_val |= ARM64_PTE_RDONLY;
        *ptep = pte_val;

        if (ptlp && p_spin_unlock)
            p_spin_unlock(ptlp);

        total += bytes;
    }

    kpm_info("<<< pte_force_write SUCCESS: %zu bytes\n", total);
    return (int)total;
}

static inline struct task_struct *hfr_get_current(void)
{
    struct task_struct *tsk;
    asm volatile("mrs %0, sp_el0" : "=r" (tsk));
    return tsk;
}

static inline int is_valid_user_address(uint64_t addr)
{
    return (addr != 0 && addr < (1ULL << 63));
}

static void process_packet(struct k_packet *pkt, pid_t caller_pid)
{
    struct task_struct *task = NULL;
    struct mm_struct *mm = NULL;
    pid_t target_pid;
    int transferred;
    uint8_t temp_buf[MAX_INLINE];

    kpm_info(">>> process_packet: op=0x%x pid=%u addr=0x%llx size=%u\n",
             pkt->op_code, pkt->target_pid, pkt->vaddr, pkt->size);

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

    if (!p_access_process_vm || !p_find_task_by_vpid || !p_get_task_mm || !p_mmput) {
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
    mm = p_get_task_mm(task);
    if (p_rcu_read_unlock) p_rcu_read_unlock();

    if (!mm) {
        pkt->status = STATUS_NO_MM;
        if (p_put_task_struct && task) p_put_task_struct(task);
        return;
    }

    if (pkt->op_code == OP_WRITE_VM) {
        if (p_follow_pte && p_memstart_addr) {
            transferred = hfr_pte_force_write(mm, (unsigned long)pkt->vaddr,
                                               pkt->inline_data, pkt->size);
        } else {
            transferred = p_access_process_vm(task, (unsigned long)pkt->vaddr,
                                               pkt->inline_data, (int)pkt->size,
                                               0x11);
        }

        if (transferred < 0)
            pkt->status = STATUS_VM_FAULT;
        else if ((uint32_t)transferred == pkt->size)
            pkt->status = STATUS_SUCCESS;
        else if (transferred > 0) {
            pkt->size = (uint32_t)transferred;
            pkt->status = STATUS_PARTIAL_IO;
        } else
            pkt->status = STATUS_PROTECTION;
    } else {
        memset(temp_buf, 0, MAX_INLINE);
        transferred = p_access_process_vm(task, (unsigned long)pkt->vaddr,
                                           temp_buf, (int)pkt->size, 0);
        if (transferred < 0)
            pkt->status = STATUS_VM_FAULT;
        else if (transferred == 0 && pkt->size > 0)
            pkt->status = STATUS_PROTECTION;
        else {
            if (transferred > 0)
                memcpy(pkt->inline_data, temp_buf, transferred);
            pkt->status = ((uint32_t)transferred == pkt->size) ?
                           STATUS_SUCCESS : STATUS_PARTIAL_IO;
            if (pkt->status == STATUS_PARTIAL_IO)
                pkt->size = (uint32_t)transferred;
        }
    }

    if (mm) p_mmput(mm);
    if (p_put_task_struct && task) p_put_task_struct(task);

    kpm_info("<<< process_packet status: 0x%x\n", pkt->status);
}

static int proc_open_handler(struct inode *inode, struct file *file) { return 0; }
static int proc_release_handler(struct inode *inode, struct file *file) { return 0; }
static ssize_t proc_read_handler(struct file *file, char __user *buffer, size_t count, loff_t *pos) { return 0; }

static ssize_t proc_write_handler(struct file *file, const char __user *buffer, size_t count, loff_t *pos)
{
    struct k_packet local_pkt;
    pid_t caller_pid;
    struct task_struct *curr_task;

    if (count != sizeof(struct k_packet))
        return -EINVAL;

    if (!p_copy_from_user)
        return -EFAULT;

    if (p_copy_from_user(&local_pkt, buffer, sizeof(struct k_packet)) != 0)
        return -EFAULT;

    curr_task = hfr_get_current();
    if (!curr_task || !p_task_pid_nr_ns)
        return -ESRCH;

    caller_pid = p_task_pid_nr_ns(curr_task, PIDTYPE_PID, NULL);
    if (caller_pid <= 0)
        return -ESRCH;

    if (p_mutex_lock) p_mutex_lock(&hfr_mutex);
    process_packet(&local_pkt, caller_pid);
    if (p_mutex_unlock) p_mutex_unlock(&hfr_mutex);

    if (!p_copy_to_user)
        return -EFAULT;

    if (p_copy_to_user((void __user *)buffer, &local_pkt, sizeof(struct k_packet)) != 0)
        return -EFAULT;

    return (ssize_t)count;
}

static const struct proc_ops p_ops = {
    .proc_open    = proc_open_handler,
    .proc_read    = proc_read_handler,
    .proc_write   = proc_write_handler,
    .proc_release = proc_release_handler,
};

static long hfr_memory_init(const char *args, const char *event, void __user *reserved)
{
    kpm_info("=== HFR ZERO-TRACE INIT ===\n");

    p_proc_create_data = (proc_create_data_t)kallsyms_lookup_name("proc_create_data");
    p_remove_proc_entry = (remove_proc_entry_t)kallsyms_lookup_name("remove_proc_entry");
    p_copy_from_user = (copy_from_user_t)kallsyms_lookup_name("_copy_from_user");
    if (!p_copy_from_user) p_copy_from_user = (copy_from_user_t)kallsyms_lookup_name("copy_from_user");
    p_copy_to_user = (copy_to_user_t)kallsyms_lookup_name("_copy_to_user");
    if (!p_copy_to_user) p_copy_to_user = (copy_to_user_t)kallsyms_lookup_name("copy_to_user");
    p_access_process_vm = (access_process_vm_t)kallsyms_lookup_name("access_process_vm");
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

    p_follow_pte = (follow_pte_t)kallsyms_lookup_name("follow_pte");
    p_spin_unlock = (spin_unlock_t)kallsyms_lookup_name("_raw_spin_unlock");
    if (!p_spin_unlock) p_spin_unlock = (spin_unlock_t)kallsyms_lookup_name("spin_unlock");
    p_memstart_addr = (uint64_t *)kallsyms_lookup_name("memstart_addr");

    kpm_info("Standard: proc=%px vm=%px task=%px mm=%px\n",
             p_proc_create_data, p_access_process_vm,
             p_find_task_by_vpid, p_get_task_mm);
    kpm_info("PTE: follow_pte=%px spin_unlock=%px memstart=%px\n",
             p_follow_pte, p_spin_unlock, p_memstart_addr);

    if (!p_proc_create_data || !p_access_process_vm || !p_find_task_by_vpid ||
        !p_get_task_mm || !p_mmput || !p_copy_from_user || !p_copy_to_user) {
        kpm_err("CRITICAL SYMBOL MISSING\n");
        return -EFAULT;
    }

    if (p_mutex_init) p_mutex_init(&hfr_mutex);

    proc_entry = p_proc_create_data(proc_filename, 0666, NULL, &p_ops, NULL);
    if (!proc_entry) {
        kpm_err("proc_create FAILED\n");
        return -EFAULT;
    }

    kpm_info("=== HFR ZERO-TRACE INIT SUCCESS /proc/%s ===\n", proc_filename);
    kpm_info("Mode: %s\n", (p_follow_pte && p_memstart_addr) ?
             "PTE_DIRECT_WRITE" : "ACCESS_PROCESS_VM_FALLBACK");
    return 0;
}

static long hfr_memory_exit(void __user *reserved)
{
    kpm_info("=== HFR ZERO-TRACE EXIT ===\n");
    if (proc_entry && p_remove_proc_entry) p_remove_proc_entry(proc_filename, NULL);
    return 0;
}

KPM_INIT(hfr_memory_init);
KPM_EXIT(hfr_memory_exit);
