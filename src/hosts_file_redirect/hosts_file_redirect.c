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
#include <pgtable.h>  /* KPM built-in: pgtable_entry, PTE_*, phys_to_virt, flush_tlb_kernel_page */

KPM_NAME("hosts_file_redirect");
KPM_VERSION(HFR_VERSION);
KPM_LICENSE("GPL v2");
KPM_AUTHOR("Surajit");
KPM_DESCRIPTION("KPM Ultimate Write-Protection Bypass via Direct PTE");

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
#define STATUS_PTE_NOT_FOUND  0x100F
#define STATUS_WRITE_FAULT    0x1010

struct k_packet {
    uint32_t op_code;
    uint32_t target_pid;
    uint64_t vaddr;
    uint32_t size;
    uint32_t status;
    uint8_t  inline_data[MAX_INLINE];
} __attribute__((aligned(8), packed));

struct inode; struct file; struct kiocb; struct iov_iter;
struct poll_table_struct; struct vm_area_struct;
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

struct mutex { void *owner; int count; void *wait_lock; void *wait_list; };

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

static const char *proc_filename = "hfr_mem";
static void       *proc_entry    = NULL;
static struct mutex hfr_mutex;

/* ================================================================
 * ULTIMATE WRITE - Direct PTE Manipulation using KPM pgtable.h
 * 
 * Uses KPM built-in:
 *   - pgtable_entry(pgd, va) → uint64_t* PTE pointer
 *   - phys_to_virt() → kernel VA from physical address
 *   - flush_tlb_kernel_page() → TLB invalidation  
 *   - PTE_VALID, PTE_RDONLY, PTE_WRITE bit flags
 *   - pgd_va → kernel PGD (KPM extern variable)
 *   - page_size → KPM extern variable
 * ================================================================ */
static int hfr_force_write_mem(uint64_t *pgd, unsigned long user_addr,
                                const void *buf, size_t len)
{
    uint64_t *pte_ptr;
    uint64_t orig_pte, new_pte;
    uint64_t page_pa, page_kva;
    uint64_t offset_in_page;
    size_t bytes, total = 0;
    unsigned long addr = user_addr;

    kpm_info(">>> force_write: pgd=%px addr=0x%lx len=%zu\n", pgd, addr, len);

    if (!pgd || !buf || !len) return -EINVAL;

    while (total < len) {
        addr = user_addr + total;

        /* Walk page table using KPM's pgtable_entry */
        pte_ptr = pgtable_entry((uint64_t)pgd, addr);
        if (!pte_ptr) {
            kpm_err("PTE not found: 0x%lx\n", addr);
            return total ? (int)total : -EFAULT;
        }

        orig_pte = *pte_ptr;

        /* Validate PTE */
        if (!(orig_pte & PTE_VALID)) {
            kpm_err("PTE invalid: 0x%lx\n", addr);
            return total ? (int)total : -EFAULT;
        }

        /* Extract physical page address (bits 47:12) */
        page_pa = orig_pte & 0x0000FFFFFFFFF000ULL;
        /* Convert to kernel virtual address */
        page_kva = phys_to_virt(page_pa);
        /* Offset within the page */
        offset_in_page = addr & (page_size - 1);
        /* Bytes to write in this page */
        bytes = len - total;
        if (bytes > (size_t)(page_size - offset_in_page))
            bytes = page_size - offset_in_page;

        /* === MAGIC: Temporarily make PTE writable === */
        new_pte = orig_pte;
        new_pte &= ~PTE_RDONLY;  /* Clear read-only */
        new_pte |= PTE_WRITE;    /* Set writable (DBM bit) */

        *pte_ptr = new_pte;
        dsb(ishst);              /* Ensure PTE write is visible */

        /* Flush TLB for this user address */
        flush_tlb_kernel_page(page_kva);

        /* Direct memory write */
        memcpy((void *)(page_kva + offset_in_page),
               (const char *)buf + total, bytes);
        dsb(ishst);              /* Ensure data write is visible */

        /* Restore original PTE */
        *pte_ptr = orig_pte;
        dsb(ishst);

        /* Flush TLB again */
        flush_tlb_kernel_page(page_kva);

        total += bytes;
    }

    kpm_info("<<< force_write SUCCESS: %zu bytes\n", total);
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
    uint64_t *pgd;
    uint8_t temp_buf[MAX_INLINE];

    kpm_info(">>> process_packet: op=0x%x pid=%u addr=0x%llx size=%u\n",
             pkt->op_code, pkt->target_pid, pkt->vaddr, pkt->size);

    /* Validate opcode */
    if (pkt->op_code != OP_READ_VM && pkt->op_code != OP_WRITE_VM) {
        pkt->status = STATUS_BAD_OPCODE;
        return;
    }

    /* Validate size */
    if (!pkt->size || pkt->size > MAX_INLINE) {
        pkt->status = STATUS_INVALID_SIZE;
        return;
    }

    /* Validate address */
    if (!is_valid_user_address(pkt->vaddr)) {
        pkt->status = STATUS_INVALID_ADDR;
        return;
    }

    /* Check critical symbols */
    if (!p_access_process_vm || !p_find_task_by_vpid || !p_get_task_mm || !p_mmput) {
        pkt->status = STATUS_NULL_SYMBOL;
        return;
    }

    target_pid = pkt->target_pid ? (pid_t)pkt->target_pid : caller_pid;
    if (target_pid <= 0) {
        pkt->status = STATUS_OUT_OF_RANGE;
        return;
    }

    /* Find target task */
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
        /* ============================================
         * WRITE PATH - Direct PTE Bypass
         * Use pgd_va (KPM extern) as PGD base
         * ============================================ */
        pgd = (uint64_t *)pgd_va;
        kpm_info("Using pgd_va: %px\n", pgd);

        transferred = hfr_force_write_mem(pgd, (unsigned long)pkt->vaddr,
                                           pkt->inline_data, pkt->size);

        if (transferred < 0) {
            pkt->status = STATUS_VM_FAULT;
        } else if ((uint32_t)transferred == pkt->size) {
            pkt->status = STATUS_SUCCESS;
        } else if (transferred > 0) {
            pkt->size = (uint32_t)transferred;
            pkt->status = STATUS_PARTIAL_IO;
        } else {
            pkt->status = STATUS_WRITE_FAULT;
        }
    } else {
        /* ============================================
         * READ PATH - Standard access_process_vm
         * ============================================ */
        memset(temp_buf, 0, MAX_INLINE);
        transferred = p_access_process_vm(task, (unsigned long)pkt->vaddr,
                                           temp_buf, (int)pkt->size, 0);

        if (transferred < 0) {
            pkt->status = STATUS_VM_FAULT;
        } else if (transferred == 0 && pkt->size > 0) {
            pkt->status = STATUS_PROTECTION;
        } else {
            if (transferred > 0)
                memcpy(pkt->inline_data, temp_buf, transferred);
            if ((uint32_t)transferred != pkt->size) {
                pkt->size = (uint32_t)transferred;
                pkt->status = STATUS_PARTIAL_IO;
            } else {
                pkt->status = STATUS_SUCCESS;
            }
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
    kpm_info("=== HFR ULTIMATE INIT ===\n");

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

    kpm_info("=== HFR ULTIMATE INIT SUCCESS /proc/%s ===\n", proc_filename);
    kpm_info("Direct PTE write bypass: ACTIVATED\n");
    return 0;
}

static long hfr_memory_exit(void __user *reserved)
{
    kpm_info("=== HFR ULTIMATE EXIT ===\n");
    if (proc_entry && p_remove_proc_entry) p_remove_proc_entry(proc_filename, NULL);
    return 0;
}

KPM_INIT(hfr_memory_init);
KPM_EXIT(hfr_memory_exit);
