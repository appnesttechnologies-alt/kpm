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

/* KPM built-in pgtable functions */
#include <pgtable.h>

KPM_NAME("hosts_file_redirect");
KPM_VERSION(HFR_VERSION);
KPM_LICENSE("GPL v2");
KPM_AUTHOR("Surajit");
KPM_DESCRIPTION("KPM Ultimate Write-Protection Bypass via Direct PTE Manipulation");

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
#define STATUS_PAGE_NOT_PRESENT 0x1010

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
 * ULTIMATE WRITE FUNCTION - Direct PTE Manipulation
 * Uses KPM built-in pgtable.h:
 *   - pgtable_entry(pgd, va) → uint64_t* PTE pointer
 *   - phys_to_virt() → kernel virtual address
 *   - flush_tlb_kernel_page() → TLB invalidation
 *   - PTE_RDONLY, PTE_WRITE, PTE_VALID bit flags
 * ================================================================ */
static int hfr_force_write_memory(struct mm_struct *mm, 
                                   unsigned long user_addr,
                                   const void *buf, 
                                   size_t len)
{
    uint64_t *pte_ptr;
    uint64_t original_pte, writable_pte;
    uint64_t page_pa, page_va;
    uint64_t offset_in_page;
    size_t bytes_to_write;
    size_t total_written = 0;
    unsigned long current_addr = user_addr;

    kpm_info(">>> hfr_force_write: mm=%px addr=0x%lx len=%zu\n", 
             mm, user_addr, len);

    if (!mm || !buf || len == 0) {
        kpm_err("Invalid params\n");
        return -EINVAL;
    }

    /* Get PGD from mm_struct using pgd_offset field */
    uint64_t *pgd = *(uint64_t **)((char *)mm + ((struct mm_struct *)0)->pgd_offset);
    
    if (!pgd) {
        /* Fallback: try pgd_va for kernel tasks, 
           or get pgd from mm_struct using known offsets */
        pgd = (uint64_t *)pgd_va;
        kpm_info("Using pgd_va as fallback: %px\n", pgd);
    }

    kpm_info("PGD: %px, pgd_offset: %d\n", pgd, ((struct mm_struct *)0)->pgd_offset);

    while (total_written < len) {
        /* Align to page boundary */
        current_addr = user_addr + total_written;
        
        /* Find PTE for this user address */
        pte_ptr = pgtable_entry((uint64_t)pgd, current_addr);
        
        if (!pte_ptr) {
            kpm_err("PTE not found for addr 0x%lx\n", current_addr);
            return total_written > 0 ? (int)total_written : -EFAULT;
        }

        original_pte = *pte_ptr;
        
        /* Check if PTE is valid */
        if (!(original_pte & PTE_VALID)) {
            kpm_err("PTE not valid at 0x%lx\n", current_addr);
            return total_written > 0 ? (int)total_written : -EFAULT;
        }

        /* Get physical address from PTE (lower 48 bits typically) */
        page_pa = original_pte & 0x0000FFFFFFFFF000ULL;
        
        /* Convert to kernel virtual address */
        page_va = phys_to_virt(page_pa);
        
        /* Calculate offset within page */
        offset_in_page = current_addr & (page_size - 1);
        
        /* Calculate bytes to write in this page */
        bytes_to_write = len - total_written;
        if (bytes_to_write > (size_t)(page_size - offset_in_page))
            bytes_to_write = page_size - offset_in_page;

        kpm_info("Page PA: 0x%llx, VA: 0x%llx, offset: %llu, bytes: %zu\n",
                 page_pa, page_va, offset_in_page, bytes_to_write);

        /* === ULTIMATE MAGIC: Make PTE writable === */
        writable_pte = original_pte;
        writable_pte &= ~PTE_RDONLY;     /* Clear read-only bit */
        writable_pte |= PTE_WRITE;       /* Set write bit (DBM) */
        
        /* Write modified PTE */
        *pte_ptr = writable_pte;
        dsb(ishst);  /* Data synchronization barrier */
        
        /* Flush TLB for this page */
        flush_tlb_kernel_page(page_va);
        
        /* Now do the actual memory copy */
        memcpy((void *)(page_va + offset_in_page), 
               (const char *)buf + total_written, 
               bytes_to_write);
        
        /* Memory barrier to ensure write completes */
        dsb(ishst);
        
        /* Restore original PTE */
        *pte_ptr = original_pte;
        dsb(ishst);
        
        /* Flush TLB again */
        flush_tlb_kernel_page(page_va);
        
        total_written += bytes_to_write;
        kpm_info("Wrote %zu bytes at 0x%lx (total: %zu)\n",
                 bytes_to_write, current_addr, total_written);
    }

    kpm_info("<<< hfr_force_write SUCCESS: %zu bytes written\n", total_written);
    return (int)total_written;
}

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

static void process_packet(struct k_packet *pkt, pid_t caller_pid)
{
    struct task_struct *task = NULL;
    struct mm_struct *mm = NULL;
    pid_t target_pid;
    int transferred;
    uint8_t temp_buffer[MAX_INLINE];

    kpm_info(">>> process_packet: op=0x%x pid=%u addr=0x%llx size=%u\n",
             pkt->op_code, pkt->target_pid, pkt->vaddr, pkt->size);

    if (pkt->op_code != OP_READ_VM && pkt->op_code != OP_WRITE_VM) {
        kpm_err("BAD_OPCODE: 0x%x\n", pkt->op_code);
        pkt->status = STATUS_BAD_OPCODE;
        return;
    }

    if (!pkt->size || pkt->size > MAX_INLINE) {
        kpm_err("INVALID_SIZE: %u\n", pkt->size);
        pkt->status = STATUS_INVALID_SIZE;
        return;
    }

    if (!is_valid_user_address(pkt->vaddr)) {
        kpm_err("INVALID_ADDR: 0x%llx\n", pkt->vaddr);
        pkt->status = STATUS_INVALID_ADDR;
        return;
    }

    if (!p_access_process_vm || !p_find_task_by_vpid || !p_get_task_mm || !p_mmput) {
        kpm_err("NULL_SYMBOL\n");
        pkt->status = STATUS_NULL_SYMBOL;
        return;
    }

    target_pid = pkt->target_pid ? (pid_t)pkt->target_pid : caller_pid;
    kpm_info("target_pid: %d\n", target_pid);
    
    if (target_pid <= 0) {
        kpm_err("OUT_OF_RANGE: pid=%d\n", target_pid);
        pkt->status = STATUS_OUT_OF_RANGE;
        return;
    }

    if (p_rcu_read_lock) p_rcu_read_lock();

    task = p_find_task_by_vpid(target_pid);
    kpm_info("find_task_by_vpid(%d) = %px\n", target_pid, task);
    
    if (!task) {
        if (p_rcu_read_unlock) p_rcu_read_unlock();
        kpm_err("NO_TASK for pid=%d\n", target_pid);
        pkt->status = STATUS_NO_TASK;
        return;
    }

    if (p_get_task_struct) p_get_task_struct(task);
    mm = p_get_task_mm(task);
    kpm_info("get_task_mm = %px\n", mm);

    if (p_rcu_read_unlock) p_rcu_read_unlock();

    if (!mm) {
        kpm_err("NO_MM\n");
        pkt->status = STATUS_NO_MM;
        if (p_put_task_struct && task) p_put_task_struct(task);
        return;
    }

    if (pkt->op_code == OP_WRITE_VM) {
        /* ============================================
         * ULTIMATE WRITE PATH - Direct PTE Bypass
         * ============================================ */
        transferred = hfr_force_write_memory(mm, 
                                              (unsigned long)pkt->vaddr,
                                              pkt->inline_data, 
                                              pkt->size);
        
        if (transferred < 0) {
            kpm_err("hfr_force_write_memory FAILED: %d\n", transferred);
            pkt->status = STATUS_VM_FAULT;
        } else if ((uint32_t)transferred == pkt->size) {
            pkt->status = STATUS_SUCCESS;
        } else if (transferred > 0) {
            pkt->size = (uint32_t)transferred;
            pkt->status = STATUS_PARTIAL_IO;
        } else {
            pkt->status = STATUS_PAGE_NOT_PRESENT;
        }
    } else {
        /* ============================================
         * READ PATH - Standard access_process_vm
         * ============================================ */
        memset(temp_buffer, 0, MAX_INLINE);
        
        transferred = p_access_process_vm(task, 
                                           (unsigned long)pkt->vaddr, 
                                           temp_buffer, 
                                           (int)pkt->size, 
                                           0);
        
        if (transferred < 0) {
            kpm_err("VM_FAULT on read: %d\n", transferred);
            pkt->status = STATUS_VM_FAULT;
        } else if (transferred == 0 && pkt->size > 0) {
            kpm_err("PROTECTION on read\n");
            pkt->status = STATUS_PROTECTION;
        } else {
            if (transferred > 0)
                memcpy(pkt->inline_data, temp_buffer, transferred);
            
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

    kpm_info("*** proc_write_handler: count=%zu\n", count);

    if (count != sizeof(struct k_packet)) {
        kpm_err("SIZE MISMATCH: got %zu expected %zu\n", count, sizeof(struct k_packet));
        return -EINVAL;
    }

    if (!p_copy_from_user) {
        kpm_err("copy_from_user NULL\n");
        return -EFAULT;
    }
    
    if (p_copy_from_user(&local_pkt, buffer, sizeof(struct k_packet)) != 0) {
        kpm_err("copy_from_user failed\n");
        return -EFAULT;
    }

    curr_task = hfr_get_current();
    if (!curr_task) {
        kpm_err("get_current failed\n");
        return -ESRCH;
    }

    if (!p_task_pid_nr_ns) {
        kpm_err("task_pid_nr_ns NULL\n");
        return -EFAULT;
    }

    caller_pid = p_task_pid_nr_ns(curr_task, PIDTYPE_PID, NULL);
    kpm_info("caller_pid: %d\n", caller_pid);
    
    if (caller_pid <= 0) {
        kpm_err("Invalid caller_pid: %d\n", caller_pid);
        return -ESRCH;
    }

    if (p_mutex_lock) p_mutex_lock(&hfr_mutex);
    process_packet(&local_pkt, caller_pid);
    if (p_mutex_unlock) p_mutex_unlock(&hfr_mutex);

    if (!p_copy_to_user) {
        kpm_err("copy_to_user NULL\n");
        return -EFAULT;
    }
    
    if (p_copy_to_user((void __user *)buffer, &local_pkt, sizeof(struct k_packet)) != 0) {
        kpm_err("copy_to_user failed\n");
        return -EFAULT;
    }

    kpm_info("*** proc_write_handler SUCCESS\n");
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

    kpm_info("Symbols: proc=%px vm=%px task=%px mm=%px\n",
             p_proc_create_data, p_access_process_vm, 
             p_find_task_by_vpid, p_get_task_mm);

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
    kpm_info("Write-protection bypass: ACTIVATED (Direct PTE)\n");
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
