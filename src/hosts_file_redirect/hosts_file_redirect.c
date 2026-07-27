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

KPM_NAME("hosts_file_redirect");
KPM_VERSION(HFR_VERSION);
KPM_LICENSE("GPL v2");
KPM_AUTHOR("Surajit");
KPM_DESCRIPTION("ZERO TRACE PTE MOD - CORRECT");

#define HFR_DEBUG
#ifdef HFR_DEBUG
#define hfr_log(fmt, ...) pr_info("HFR: " fmt, ##__VA_ARGS__)
#define hfr_err(fmt, ...)  pr_err("HFR: " fmt, ##__VA_ARGS__)
#else
#define hfr_log(fmt, ...)
#define hfr_err(fmt, ...)
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

// Simple bit definitions (no _AC macro)
#define HFR_PTE_VALID   (1UL << 0)
#define HFR_PTE_USER    (1UL << 6)
#define HFR_PTE_RDONLY  (1UL << 7)
#define HFR_PTE_AF      (1UL << 10)
#define HFR_PTE_DBM     (1UL << 51)
#define HFR_PMD_TYPE_TABLE  (3UL << 0)
#define HFR_PMD_TYPE_BLOCK  (1UL << 0)
#define HFR_PMD_SECT_RDONLY (1UL << 7)

#define PGD_SHIFT   30
#define PMD_SHIFT   21
#define PAGE_SHIFT  12
#define PAGE_MASK   0xFFFFFFFFFFFFF000ULL
#define PMD_MASK    0xFFFFFFFFFFE00000ULL

static unsigned long *get_pgd_from_mm(struct mm_struct *mm)
{
    unsigned long *mm_ptr = (unsigned long *)mm;
    unsigned long possible_offsets[] = {14, 15, 16, 17, 18, 19, 20, 21, 22, 23, 24, 25};
    
    for (int i = 0; i < 12; i++) {
        unsigned long val = mm_ptr[possible_offsets[i]];
        if (val >= 0xffffff8000000000ULL && val < 0xfffffffffffff000ULL && (val & 0xFFF) == 0) {
            hfr_log("Found PGD at mm+%lu = %px", possible_offsets[i] * 8, (void *)val);
            return (unsigned long *)val;
        }
    }
    hfr_err("Cannot find PGD in mm_struct!");
    return NULL;
}

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

static int walk_page_table(struct mm_struct *mm, unsigned long addr,
                           unsigned long **entry_ptr, unsigned long *entry_val,
                           int *is_block)
{
    unsigned long *pgd, *pmd, *pte;
    unsigned long val;
    
    pgd = get_pgd_from_mm(mm);
    if (!pgd)
        return -EFAULT;
    
    // PGD
    unsigned long pgd_idx = (addr >> PGD_SHIFT) & 0x1FF;
    val = *(volatile unsigned long *)(pgd + pgd_idx);
    hfr_log("PGD[%lu] @ %px = 0x%llx", pgd_idx, (void *)(pgd + pgd_idx), val);
    
    if ((val & 0x3) != HFR_PMD_TYPE_TABLE) {
        hfr_err("Invalid PGD entry: type=%llu", val & 0x3);
        return -EFAULT;
    }
    
    // PMD - convert physical to linear map virtual
    pmd = (unsigned long *)((val & ~0xFFFULL) + 0xffffff8000000000ULL);
    unsigned long pmd_idx = (addr >> PMD_SHIFT) & 0x1FF;
    val = *(volatile unsigned long *)(pmd + pmd_idx);
    hfr_log("PMD[%lu] @ %px = 0x%llx", pmd_idx, (void *)(pmd + pmd_idx), val);
    
    if (!(val & HFR_PTE_VALID)) {
        hfr_err("PMD not valid");
        return -EFAULT;
    }
    
    if ((val & 0x3) == HFR_PMD_TYPE_BLOCK) {
        hfr_log("2MB Block mapping");
        *entry_ptr = (unsigned long *)(pmd + pmd_idx);
        *entry_val = val;
        *is_block = 1;
        return 0;
    }
    
    if ((val & 0x3) != HFR_PMD_TYPE_TABLE) {
        hfr_err("Invalid PMD type");
        return -EFAULT;
    }
    
    // PTE
    pte = (unsigned long *)((val & ~0xFFFULL) + 0xffffff8000000000ULL);
    unsigned long pte_idx = (addr >> PAGE_SHIFT) & 0x1FF;
    val = *(volatile unsigned long *)(pte + pte_idx);
    hfr_log("PTE[%lu] @ %px = 0x%llx", pte_idx, (void *)(pte + pte_idx), val);
    
    if (!(val & HFR_PTE_VALID)) {
        hfr_err("PTE not valid");
        return -EFAULT;
    }
    
    *entry_ptr = (unsigned long *)(pte + pte_idx);
    *entry_val = val;
    *is_block = 0;
    return 0;
}

static int pte_mod_read(struct mm_struct *mm, unsigned long addr,
                        void *buffer, int size)
{
    unsigned long *entry, entry_val, phys_addr, kvirt_addr;
    int is_block, ret;
    
    if (!mm || !buffer || size <= 0 || size > MAX_INLINE)
        return -EINVAL;
    
    ret = walk_page_table(mm, addr, &entry, &entry_val, &is_block);
    if (ret < 0)
        return ret;
    
    if (!is_block && (addr & 0xFFF) + size > 4096) {
        hfr_err("Cross-page read not supported");
        return -EFAULT;
    }
    
    if (is_block)
        phys_addr = (entry_val & PMD_MASK) | (addr & ~PMD_MASK);
    else
        phys_addr = (entry_val & PAGE_MASK) | (addr & 0xFFF);
    
    kvirt_addr = phys_addr + 0xffffff8000000000ULL;
    memcpy(buffer, (void *)kvirt_addr, size);
    hfr_log("READ: %d bytes from 0x%llx", size, addr);
    return size;
}

static int pte_mod_write(struct mm_struct *mm, unsigned long addr,
                          void *buffer, int size)
{
    unsigned long *entry, orig_val, new_val, irq_flags;
    int is_block, ret;
    
    if (!mm || !buffer || size <= 0 || size > MAX_INLINE)
        return -EINVAL;
    
    ret = walk_page_table(mm, addr, &entry, &entry_val, &is_block);
    if (ret < 0)
        return ret;
    
    if (!is_block && (addr & 0xFFF) + size > 4096) {
        hfr_err("Cross-page write not supported");
        return -EFAULT;
    }
    
    orig_val = entry_val;
    
    // Check if already writable
    if (is_block) {
        if (!(entry_val & HFR_PMD_SECT_RDONLY)) {
            hfr_log("Block already writable");
            memcpy((void *)addr, buffer, size);
            return size;
        }
    } else {
        if (!(entry_val & HFR_PTE_RDONLY)) {
            hfr_log("Page already writable");
            memcpy((void *)addr, buffer, size);
            return size;
        }
    }
    
    // Disable interrupts
    asm volatile("mrs %0, daif" : "=r"(irq_flags) : : "memory");
    asm volatile("msr daifset, #2" : : : "memory");
    
    // Clear RDONLY bit
    if (is_block) {
        new_val = orig_val & ~HFR_PMD_SECT_RDONLY;
        hfr_log("Block: Clearing RDONLY (0x%llx -> 0x%llx)", orig_val, new_val);
    } else {
        new_val = orig_val & ~HFR_PTE_RDONLY;
        hfr_log("PTE: Clearing RDONLY (0x%llx -> 0x%llx)", orig_val, new_val);
    }
    
    *entry = new_val;
    asm volatile("dsb ishst" ::: "memory");
    flush_tlb_entry(addr);
    
    // Direct write to userspace address
    memcpy((void *)addr, buffer, size);
    hfr_log("WRITE OK: %d bytes to 0x%llx", size, addr);
    
    // Restore
    *entry = orig_val;
    asm volatile("dsb ishst" ::: "memory");
    flush_tlb_entry(addr);
    
    asm volatile("msr daif, %0" : : "r"(irq_flags) : "memory");
    
    return size;
}

static void process_packet(struct k_packet *pkt, pid_t caller_pid)
{
    struct task_struct *task = NULL;
    struct mm_struct *mm = NULL;
    pid_t target_pid;
    int transferred, is_write_op;
    uint8_t temp_buffer[MAX_INLINE];

    if (pkt->op_code != OP_READ_VM && pkt->op_code != OP_WRITE_VM) {
        pkt->status = STATUS_BAD_OPCODE;
        return;
    }
    if (!pkt->size || pkt->size > MAX_INLINE) {
        pkt->status = STATUS_INVALID_SIZE;
        return;
    }
    if (pkt->vaddr == 0 || pkt->vaddr >= (1ULL << 39)) {
        pkt->status = STATUS_INVALID_ADDR;
        return;
    }
    if (!p_find_task_by_vpid || !p_get_task_mm || !p_mmput) {
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

    is_write_op = (pkt->op_code == OP_WRITE_VM);
    memset(temp_buffer, 0, MAX_INLINE);
    if (is_write_op)
        memcpy(temp_buffer, pkt->inline_data, pkt->size);

    if (is_write_op)
        transferred = pte_mod_write(mm, pkt->vaddr, temp_buffer, pkt->size);
    else
        transferred = pte_mod_read(mm, pkt->vaddr, temp_buffer, pkt->size);

    pkt->status = (transferred > 0) ? STATUS_SUCCESS : STATUS_VM_FAULT;

    if (p_mmput && mm) p_mmput(mm);
    if (p_put_task_struct && task) p_put_task_struct(task);

    if (!is_write_op && transferred > 0) {
        memset(pkt->inline_data, 0, MAX_INLINE);
        memcpy(pkt->inline_data, temp_buffer, transferred);
    }
    if (transferred > 0 && (uint32_t)transferred != pkt->size)
        pkt->size = (uint32_t)transferred;
}

static int proc_open_handler(struct inode *inode, struct file *file) { return 0; }
static int proc_release_handler(struct inode *inode, struct file *file) { return 0; }
static ssize_t proc_read_handler(struct file *file, char __user *buffer, size_t count, loff_t *pos) { return 0; }

static ssize_t proc_write_handler(struct file *file, const char __user *buffer, size_t count, loff_t *pos)
{
    struct k_packet local_pkt;
    pid_t caller_pid;
    struct task_struct *curr_task;

    if (count != sizeof(struct k_packet)) return -EINVAL;
    if (!p_copy_from_user) return -EFAULT;
    if (p_copy_from_user(&local_pkt, buffer, sizeof(struct k_packet)) != 0) return -EFAULT;

    curr_task = hfr_get_current();
    if (!curr_task) return -ESRCH;
    if (!p_task_pid_nr_ns) return -EFAULT;

    caller_pid = p_task_pid_nr_ns(curr_task, PIDTYPE_PID, NULL);
    if (caller_pid <= 0) return -ESRCH;

    if (p_mutex_lock) p_mutex_lock(&hfr_mutex);
    process_packet(&local_pkt, caller_pid);
    if (p_mutex_unlock) p_mutex_unlock(&hfr_mutex);

    if (!p_copy_to_user) return -EFAULT;
    if (p_copy_to_user((void __user *)buffer, &local_pkt, sizeof(struct k_packet)) != 0) return -EFAULT;
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
    hfr_log("=== ZERO TRACE PTE MOD INIT ===");
    
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

    if (!p_proc_create_data || !p_find_task_by_vpid || !p_task_pid_nr_ns || 
        !p_get_task_mm || !p_mmput || !p_copy_from_user || !p_copy_to_user) {
        hfr_err("CRITICAL SYMBOL MISSING");
        return -EFAULT;
    }

    if (p_mutex_init) p_mutex_init(&hfr_mutex);
    proc_entry = p_proc_create_data(proc_filename, 0666, NULL, &p_ops, NULL);
    if (!proc_entry) {
        hfr_err("proc_create FAILED");
        return -EFAULT;
    }

    hfr_log("=== /proc/%s CREATED ===", proc_filename);
    return 0;
}

static long hfr_memory_exit(void __user *reserved)
{
    hfr_log("=== EXIT ===");
    if (proc_entry && p_remove_proc_entry)
        p_remove_proc_entry(proc_filename, NULL);
    return 0;
}

KPM_INIT(hfr_memory_init);
KPM_EXIT(hfr_memory_exit);
