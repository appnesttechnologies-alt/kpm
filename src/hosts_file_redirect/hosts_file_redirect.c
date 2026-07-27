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
#include <linux/mm_types.h>
#include <linux/pid.h>
#include <linux/slab.h>
#include <linux/version.h>
#include <linux/irqflags.h>

KPM_NAME("hosts_file_redirect");
KPM_VERSION(HFR_VERSION);
KPM_LICENSE("GPL v2");
KPM_AUTHOR("Surajit");
KPM_DESCRIPTION("ZERO TRACE PTE MODIFICATION");

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

static inline struct task_struct *hfr_get_current(void)
{
    struct task_struct *tsk;
    asm volatile("mrs %0, sp_el0" : "=r" (tsk));
    return tsk;
}

// ARM64 PTE bit definitions
#define PTE_VALID            (1UL << 0)
#define PTE_TYPE_PAGE        (3UL << 0)
#define PTE_TYPE_BLOCK       (1UL << 0)
#define PTE_AP2              (1UL << 6)
#define PTE_ADDR_MASK        0xFFFFFFFFF000ULL

// Convert physical address to kernel virtual using linear map
// Only for accessing page TABLE pages, NOT userspace data!
static unsigned long phys_to_kvirt(unsigned long phys)
{
    return phys + 0xffffff8000000000ULL;
}

// Invalidate TLB for a single address
static inline void flush_tlb_entry(unsigned long addr)
{
    asm volatile(
        "dsb ishst\n"
        "tlbi vaae1is, %0\n"
        "dsb ish\n"
        "isb\n"
        : : "r"(addr) : "memory"
    );
}

// Find PGD in mm_struct
static unsigned long find_pgd_phys(struct mm_struct *mm)
{
    unsigned long possible_offsets[] = {0x40, 0x48, 0x50, 0x58, 0x60, 0x68, 0x70, 0x78, 0x80, 0x88};
    unsigned long val;
    
    for (int i = 0; i < 10; i++) {
        val = *(unsigned long *)((char *)mm + possible_offsets[i]);
        if (val != 0 && (val & 0xFFF) == 0 && val < (1ULL << 40)) {
            if (val < (1ULL << 40)) {
                kpm_info("PGD found at mm+0x%lx = 0x%llx\n", possible_offsets[i], val);
                return val;
            }
        }
    }
    kpm_err("Could not find PGD in mm_struct\n");
    return 0;
}

// ============================================================
// ZERO TRACE PTE MODIFICATION - READ
// ============================================================
static int pte_mod_read(struct mm_struct *mm, unsigned long addr,
                        void *buffer, int size)
{
    unsigned long pgd_phys, pgd_table;
    unsigned long pgd_val, pmd_val, pte_val;
    unsigned long pmd_table, pte_table;
    unsigned long pgd_idx, pmd_idx, pte_idx;
    int ret = -EFAULT;
    
    if (!mm || !buffer || size <= 0 || size > MAX_INLINE)
        return -EINVAL;
    
    pgd_phys = find_pgd_phys(mm);
    if (!pgd_phys)
        return -EFAULT;
    
    pgd_table = phys_to_kvirt(pgd_phys);
    kpm_info("PGD table: virt=0x%llx (from phys=0x%llx)\n", pgd_table, pgd_phys);
    
    pgd_idx = (addr >> 30) & 0x1FF;
    pgd_val = *(volatile unsigned long *)(pgd_table + pgd_idx * 8);
    kpm_info("PGD[%lu] = 0x%llx\n", pgd_idx, pgd_val);
    
    if ((pgd_val & 0x3) != 0x3) {
        kpm_err("Invalid PGD entry (not table descriptor)\n");
        return -EFAULT;
    }
    
    pmd_table = phys_to_kvirt(pgd_val & ~0xFFFULL);
    pmd_idx = (addr >> 21) & 0x1FF;
    pmd_val = *(volatile unsigned long *)(pmd_table + pmd_idx * 8);
    kpm_info("PMD[%lu] = 0x%llx\n", pmd_idx, pmd_val);
    
    if (!(pmd_val & PTE_VALID)) {
        kpm_err("PMD entry not present\n");
        return -EFAULT;
    }
    
    if ((pmd_val & 0x3) == PTE_TYPE_BLOCK) {
        kpm_info("Block mapping detected - reading directly\n");
        unsigned long block_phys = (pmd_val & PTE_ADDR_MASK) | (addr & 0x1FFFFF);
        unsigned long block_virt = phys_to_kvirt(block_phys);
        memcpy(buffer, (void *)block_virt, size);
        return size;
    }
    
    if ((pmd_val & 0x3) != 0x3) {
        kpm_err("Invalid PMD entry type\n");
        return -EFAULT;
    }
    
    pte_table = phys_to_kvirt(pmd_val & ~0xFFFULL);
    pte_idx = (addr >> 12) & 0x1FF;
    pte_val = *(volatile unsigned long *)(pte_table + pte_idx * 8);
    kpm_info("PTE[%lu] = 0x%llx\n", pte_idx, pte_val);
    
    if (!(pte_val & PTE_VALID)) {
        kpm_err("PTE entry not present\n");
        return -EFAULT;
    }
    
    {
        unsigned long phys_addr = (pte_val & PTE_ADDR_MASK) | (addr & 0xFFF);
        unsigned long kvirt_addr = phys_to_kvirt(phys_addr);
        
        if ((addr & 0xFFF) + size > 0x1000) {
            kpm_err("Cross-page access not supported\n");
            return -EFAULT;
        }
        
        memcpy(buffer, (void *)kvirt_addr, size);
        kpm_info("Read %d bytes from 0x%llx\n", size, addr);
        ret = size;
    }
    
    return ret;
}

// ============================================================
// ZERO TRACE PTE MODIFICATION - WRITE
// ============================================================
static int pte_mod_write(struct mm_struct *mm, unsigned long addr,
                          void *buffer, int size)
{
    unsigned long pgd_phys, pgd_table;
    unsigned long pgd_val, pmd_val, pte_val, orig_pte;
    unsigned long pmd_table, pte_table;
    unsigned long pgd_idx, pmd_idx, pte_idx;
    unsigned long *pte_entry_ptr;
    int ret = -EFAULT;
    
    if (!mm || !buffer || size <= 0 || size > MAX_INLINE)
        return -EINVAL;
    
    pgd_phys = find_pgd_phys(mm);
    if (!pgd_phys)
        return -EFAULT;
    
    pgd_table = phys_to_kvirt(pgd_phys);
    
    pgd_idx = (addr >> 30) & 0x1FF;
    pgd_val = *(volatile unsigned long *)(pgd_table + pgd_idx * 8);
    kpm_info("PGD[%lu] = 0x%llx\n", pgd_idx, pgd_val);
    
    if ((pgd_val & 0x3) != 0x3) {
        kpm_err("Invalid PGD entry\n");
        return -EFAULT;
    }
    
    pmd_table = phys_to_kvirt(pgd_val & ~0xFFFULL);
    pmd_idx = (addr >> 21) & 0x1FF;
    pmd_val = *(volatile unsigned long *)(pmd_table + pmd_idx * 8);
    kpm_info("PMD[%lu] = 0x%llx\n", pmd_idx, pmd_val);
    
    if (!(pmd_val & PTE_VALID)) {
        kpm_err("PMD not present\n");
        return -EFAULT;
    }
    
    // Handle 2MB block mapping
    if ((pmd_val & 0x3) == PTE_TYPE_BLOCK) {
        kpm_info("Block mapping write\n");
        
        unsigned long orig_pmd = pmd_val;
        unsigned long *pmd_entry_ptr = (unsigned long *)(pmd_table + pmd_idx * 8);
        unsigned long irq_flags;
        
        local_irq_save(irq_flags);
        
        pmd_val &= ~PTE_AP2;
        *pmd_entry_ptr = pmd_val;
        
        flush_tlb_entry(addr);
        
        memcpy((void *)addr, buffer, size);
        kpm_info("ZERO TRACE WRITE: %d bytes to 0x%llx\n", size, addr);
        
        *pmd_entry_ptr = orig_pmd;
        flush_tlb_entry(addr);
        
        local_irq_restore(irq_flags);
        return size;
    }
    
    if ((pmd_val & 0x3) != 0x3) {
        kpm_err("Invalid PMD type\n");
        return -EFAULT;
    }
    
    pte_table = phys_to_kvirt(pmd_val & ~0xFFFULL);
    pte_idx = (addr >> 12) & 0x1FF;
    pte_entry_ptr = (unsigned long *)(pte_table + pte_idx * 8);
    pte_val = *(volatile unsigned long *)pte_entry_ptr;
    orig_pte = pte_val;
    kpm_info("PTE[%lu] = 0x%llx (AP[2]=%lu)\n", pte_idx, pte_val, (pte_val >> 6) & 1);
    
    if (!(pte_val & PTE_VALID)) {
        kpm_err("PTE not present\n");
        return -EFAULT;
    }
    
    if ((addr & 0xFFF) + size > 0x1000) {
        kpm_err("Cross-page access not supported\n");
        return -EFAULT;
    }
    
    {
        unsigned long irq_flags;
        
        local_irq_save(irq_flags);
        
        pte_val &= ~PTE_AP2;
        *pte_entry_ptr = pte_val;
        
        asm volatile("dsb ishst" ::: "memory");
        flush_tlb_entry(addr);
        
        memcpy((void *)addr, buffer, size);
        kpm_info("ZERO TRACE WRITE: %d bytes to 0x%llx\n", size, addr);
        
        *pte_entry_ptr = orig_pte;
        
        asm volatile("dsb ishst" ::: "memory");
        flush_tlb_entry(addr);
        
        local_irq_restore(irq_flags);
    }
    
    ret = size;
    return ret;
}

// ============================================================
// PROCESS PACKET
// ============================================================
static void process_packet(struct k_packet *pkt, pid_t caller_pid)
{
    struct task_struct *task = NULL;
    struct mm_struct *mm = NULL;
    pid_t target_pid;
    int transferred;
    int is_write_op = 0;
    uint8_t temp_buffer[MAX_INLINE];

    kpm_info(">>> op=0x%x pid=%u addr=0x%llx size=%u caller=%d\n",
             pkt->op_code, pkt->target_pid, pkt->vaddr, pkt->size, caller_pid);

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

    if (pkt->vaddr == 0 || pkt->vaddr >= (1ULL << 39)) {
        kpm_err("INVALID_ADDR: 0x%llx\n", pkt->vaddr);
        pkt->status = STATUS_INVALID_ADDR;
        return;
    }

    if (!p_find_task_by_vpid || !p_get_task_mm || !p_mmput) {
        kpm_err("NULL_SYMBOL\n");
        pkt->status = STATUS_NULL_SYMBOL;
        return;
    }

    target_pid = pkt->target_pid ? (pid_t)pkt->target_pid : caller_pid;
    
    if (target_pid <= 0) {
        kpm_err("OUT_OF_RANGE: pid=%d\n", target_pid);
        pkt->status = STATUS_OUT_OF_RANGE;
        return;
    }

    if (p_rcu_read_lock) p_rcu_read_lock();
    task = p_find_task_by_vpid(target_pid);
    
    if (!task) {
        if (p_rcu_read_unlock) p_rcu_read_unlock();
        kpm_err("NO_TASK for pid=%d\n", target_pid);
        pkt->status = STATUS_NO_TASK;
        return;
    }

    if (p_get_task_struct) p_get_task_struct(task);
    mm = p_get_task_mm(task);
    if (p_rcu_read_unlock) p_rcu_read_unlock();

    if (!mm) {
        kpm_err("NO_MM\n");
        pkt->status = STATUS_NO_MM;
        if (p_put_task_struct && task) p_put_task_struct(task);
        return;
    }

    is_write_op = (pkt->op_code == OP_WRITE_VM);
    memset(temp_buffer, 0, MAX_INLINE);
    
    if (is_write_op) {
        memcpy(temp_buffer, pkt->inline_data, pkt->size);
    }

    if (is_write_op) {
        transferred = pte_mod_write(mm, pkt->vaddr, temp_buffer, pkt->size);
    } else {
        transferred = pte_mod_read(mm, pkt->vaddr, temp_buffer, pkt->size);
    }

    kpm_info("Result: %d\n", transferred);

    if (transferred > 0) {
        pkt->status = STATUS_SUCCESS;
    } else if (transferred == -EFAULT) {
        pkt->status = STATUS_VM_FAULT;
    } else {
        pkt->status = STATUS_PROTECTION;
    }

    if (p_mmput && mm) p_mmput(mm);
    if (p_put_task_struct && task) p_put_task_struct(task);

    if (!is_write_op && transferred > 0) {
        memset(pkt->inline_data, 0, MAX_INLINE);
        memcpy(pkt->inline_data, temp_buffer, transferred);
    }

    if (transferred > 0 && (uint32_t)transferred != pkt->size) {
        pkt->size = (uint32_t)transferred;
        pkt->status = STATUS_PARTIAL_IO;
    }
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
        kpm_err("Invalid write size: %zu\n", count);
        return -EINVAL;
    }

    if (!p_copy_from_user) {
        kpm_err("copy_from_user not available\n");
        return -EFAULT;
    }
    
    if (p_copy_from_user(&local_pkt, buffer, sizeof(struct k_packet)) != 0) {
        kpm_err("copy_from_user failed\n");
        return -EFAULT;
    }

    curr_task = hfr_get_current();
    if (!curr_task) {
        kpm_err("Cannot get current task\n");
        return -ESRCH;
    }

    if (!p_task_pid_nr_ns) {
        kpm_err("task_pid_nr_ns not available\n");
        return -EFAULT;
    }

    caller_pid = p_task_pid_nr_ns(curr_task, PIDTYPE_PID, NULL);
    
    if (caller_pid <= 0) {
        kpm_err("Invalid caller PID\n");
        return -ESRCH;
    }

    if (p_mutex_lock) p_mutex_lock(&hfr_mutex);
    process_packet(&local_pkt, caller_pid);
    if (p_mutex_unlock) p_mutex_unlock(&hfr_mutex);

    if (!p_copy_to_user) {
        kpm_err("copy_to_user not available\n");
        return -EFAULT;
    }
    
    if (p_copy_to_user((void __user *)buffer, &local_pkt, sizeof(struct k_packet)) != 0) {
        kpm_err("copy_to_user failed\n");
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
    kpm_info("=== ZERO TRACE PTE MOD INIT ===\n");
    
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

    kpm_info("Symbols resolved\n");

    if (!p_proc_create_data || !p_find_task_by_vpid || 
        !p_task_pid_nr_ns || !p_get_task_mm || !p_mmput || 
        !p_copy_from_user || !p_copy_to_user) {
        kpm_err("CRITICAL SYMBOL MISSING\n");
        return -EFAULT;
    }

    if (p_mutex_init) p_mutex_init(&hfr_mutex);

    proc_entry = p_proc_create_data(proc_filename, 0666, NULL, &p_ops, NULL);
    if (!proc_entry) {
        kpm_err("proc_create FAILED\n");
        return -EFAULT;
    }

    kpm_info("=== /proc/%s CREATED ===\n", proc_filename);
    kpm_info("=== ZERO TRACE PTE MODIFICATION ACTIVE ===\n");
    return 0;
}

static long hfr_memory_exit(void __user *reserved)
{
    kpm_info("=== EXIT ===\n");
    if (proc_entry && p_remove_proc_entry) {
        p_remove_proc_entry(proc_filename, NULL);
    }
    return 0;
}

KPM_INIT(hfr_memory_init);
KPM_EXIT(hfr_memory_exit);
