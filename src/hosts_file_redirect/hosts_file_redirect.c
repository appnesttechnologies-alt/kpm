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
KPM_DESCRIPTION("3-LEVEL PAGE WALK - CONFIG_PGTABLE_LEVELS=3");

/* ============================================================
 * DEBUG
 * ============================================================ */
#define HFR_DEBUG
#ifdef HFR_DEBUG
#define kpm_info(fmt, ...) pr_info("HFR: " fmt, ##__VA_ARGS__)
#define kpm_err(fmt, ...)  pr_err("HFR: " fmt, ##__VA_ARGS__)
#else
#define kpm_info(fmt, ...)
#define kpm_err(fmt, ...)
#endif

/* ============================================================
 * PHYS_TO_VIRT — memstart_addr resolved at init
 * Used ONLY for final PFN → kernel VA conversion.
 * mm->pgd and all intermediate page table pointers coming
 * out of the walk are already kernel virtual addresses.
 * ============================================================ */
static unsigned long g_memstart_addr = 0;
static unsigned long g_page_offset   = 0xffffffc000000000ULL; /* ARM64 default */

static inline void *phys_to_virt_resolved(unsigned long phys)
{
    return (void *)(phys - g_memstart_addr + g_page_offset);
}

/* ============================================================
 * CONSTANTS
 * ============================================================ */
#define MAX_INLINE      256
#define OP_READ_VM      0x2000
#define OP_WRITE_VM     0x3000

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

/*
 * ARM64, 4KB pages, CONFIG_PGTABLE_LEVELS=3:
 *
 *   VA[38:30] → PGD index  (512 entries, each 8 bytes)
 *   VA[29:21] → PMD index  (512 entries, each 8 bytes)
 *   VA[20:12] → PTE index  (512 entries, each 8 bytes)
 *   VA[11:0]  → page offset
 *
 * PUD level does NOT EXIST — it is folded into PGD.
 * mm->pgd is a kernel virtual address. Walk entries directly.
 * Only the final PFN needs phys_to_virt conversion.
 */
#define PGD_SHIFT   39
#define PMD_SHIFT   21
#define PTE_SHIFT   12
#define IDX_MASK    0x1FFUL
#define PHYS_MASK   (~0xFFFUL)   /* strip low 12 bits to get next table PA */
#define PTE_VALID   (1UL << 0)
#define PMD_TABLE   (1UL << 1)   /* bit1=1 → table, bit1=0 → block (2MB huge) */

/* ============================================================
 * FORWARD DECLARATIONS — kernel fn pointers
 * ============================================================ */
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
    unsigned long (*proc_get_unmapped_area)(struct file *, unsigned long,
                                            unsigned long, unsigned long,
                                            unsigned long);
};

struct k_mutex {
    void *owner;
    int   count;
    void *wait_lock;
    void *wait_list;
};

typedef void *(*proc_create_data_t)(const char *, uint16_t, void *,
                                    const struct proc_ops *, void *);
typedef void  (*remove_proc_entry_t)(const char *, void *);
typedef unsigned long (*copy_from_user_t)(void *, const void __user *, unsigned long);
typedef unsigned long (*copy_to_user_t)(void __user *, const void *, unsigned long);
typedef struct task_struct *(*find_task_by_vpid_t)(pid_t);
typedef struct mm_struct *(*get_task_mm_t)(struct task_struct *);
typedef void (*mmput_t)(struct mm_struct *);
typedef struct task_struct *(*get_task_struct_t)(struct task_struct *);
typedef void (*put_task_struct_t)(struct task_struct *);
typedef pid_t (*task_pid_nr_ns_t)(struct task_struct *, enum pid_type,
                                   struct pid_namespace *);
typedef void (*rcu_read_lock_t)(void);
typedef void (*rcu_read_unlock_t)(void);
typedef void (*mutex_init_t)(struct k_mutex *);
typedef void (*mutex_lock_t)(struct k_mutex *);
typedef void (*mutex_unlock_t)(struct k_mutex *);

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

static const char   *proc_filename = "hfr_mem";
static void         *proc_entry    = NULL;
static struct k_mutex hfr_mutex;

/* ============================================================
 * HELPERS
 * ============================================================ */
static inline struct task_struct *hfr_get_current(void)
{
    struct task_struct *tsk;
    asm volatile("mrs %0, sp_el0" : "=r"(tsk));
    return tsk;
}

static inline int is_valid_user_addr(uint64_t addr)
{
    /* userspace on ARM64 lives below bit 55; reject NULL and kernel VAs */
    return (addr != 0) && (addr < (1ULL << 55));
}

/*
 * safe_read_ulong — read one unsigned long from a kernel virtual address.
 * Returns 0 and sets *ok=0 on any failure.
 */
static inline unsigned long safe_read_ulong(unsigned long kva, int *ok)
{
    /* Basic sanity: must be a kernel VA */
    if (kva < 0xffffffc000000000ULL) {
        *ok = 0;
        return 0;
    }
    *ok = 1;
    return *(volatile unsigned long *)kva;
}

/* ============================================================
 * 3-LEVEL PAGE WALK
 * CONFIG_PGTABLE_LEVELS=3 → PGD folds PUD, walk is PGD→PMD→PTE
 *
 * All intermediate table addresses produced by the walk are
 * physical addresses stored inside page table entries.
 * They must be converted to kernel VAs before dereferencing.
 *
 * mm->pgd itself is already a kernel VA (set by pgd_alloc).
 * ============================================================ */
static int walk_page_table(struct mm_struct *mm, unsigned long addr,
                            void *buffer, int size, int is_write)
{
    unsigned long pgd_kva;   /* kernel VA of PGD table base  */
    unsigned long pgd_entry; /* raw entry read from PGD       */
    unsigned long pmd_phys;  /* physical addr of PMD table    */
    unsigned long pmd_kva;   /* kernel VA of PMD table base   */
    unsigned long pmd_entry; /* raw entry read from PMD       */
    unsigned long pte_phys;  /* physical addr of PTE table    */
    unsigned long pte_kva;   /* kernel VA of PTE table base   */
    unsigned long pte_entry; /* raw entry read from PTE       */
    unsigned long pfn;
    unsigned long phys_addr;
    unsigned long page_kva;
    unsigned long page_offset;
    int ok;

    /* ---- PGD ------------------------------------------------
     * mm->pgd is a kernel virtual address.
     * index = VA[38:30], 9 bits.
     */
    pgd_kva = (unsigned long)mm->pgd;
    if (!pgd_kva) {
        kpm_err("WALK: mm->pgd is NULL\n");
        return -EFAULT;
    }

    {
        unsigned long idx = (addr >> PGD_SHIFT) & IDX_MASK;
        pgd_entry = safe_read_ulong(pgd_kva + idx * 8, &ok);
        if (!ok || !(pgd_entry & PTE_VALID)) {
            kpm_err("WALK: PGD entry invalid (idx=%lu entry=0x%lx)\n",
                    idx, pgd_entry);
            return -EFAULT;
        }
        kpm_info("WALK: PGD[%lu]=0x%lx\n", idx, pgd_entry);
    }

    /* ---- PMD ------------------------------------------------
     * PGD entry bits[47:12] = physical base of PMD table.
     * Convert phys → kernel VA before dereferencing.
     * index = VA[29:21], 9 bits.
     *
     * With PGTABLE_LEVELS=3, PUD is folded: the PGD entry
     * points directly to the PMD table.
     */
    pmd_phys = pgd_entry & PHYS_MASK;
    pmd_kva  = (unsigned long)phys_to_virt_resolved(pmd_phys);
    if (!pmd_kva) {
        kpm_err("WALK: PMD table phys→virt failed (phys=0x%lx)\n", pmd_phys);
        return -EFAULT;
    }

    {
        unsigned long idx = (addr >> PMD_SHIFT) & IDX_MASK;
        pmd_entry = safe_read_ulong(pmd_kva + idx * 8, &ok);
        if (!ok || !(pmd_entry & PTE_VALID)) {
            kpm_err("WALK: PMD entry invalid (idx=%lu entry=0x%lx)\n",
                    idx, pmd_entry);
            return -EFAULT;
        }
        kpm_info("WALK: PMD[%lu]=0x%lx\n", idx, pmd_entry);

        /* 2MB block mapping: bit1=0 in a valid PMD means block, not table */
        if (!(pmd_entry & PMD_TABLE)) {
            kpm_info("WALK: 2MB huge page detected\n");
            pfn      = (pmd_entry & PHYS_MASK) >> PTE_SHIFT;
            phys_addr = (pfn << PTE_SHIFT) | (addr & 0x1FFFFFUL);
            page_kva  = (unsigned long)phys_to_virt_resolved(phys_addr);
            if (!page_kva) return -EFAULT;
            if ((addr & 0x1FFFFFUL) + (unsigned long)size > 0x200000UL) {
                kpm_err("WALK: 2MB page boundary crossed\n");
                return -EFAULT;
            }
            if (is_write)
                memcpy((void *)page_kva, buffer, size);
            else
                memcpy(buffer, (void *)page_kva, size);
            return size;
        }
    }

    /* ---- PTE ------------------------------------------------
     * PMD entry bits[47:12] = physical base of PTE table.
     * Convert phys → kernel VA before dereferencing.
     * index = VA[20:12], 9 bits.
     */
    pte_phys = pmd_entry & PHYS_MASK;
    pte_kva  = (unsigned long)phys_to_virt_resolved(pte_phys);
    if (!pte_kva) {
        kpm_err("WALK: PTE table phys→virt failed (phys=0x%lx)\n", pte_phys);
        return -EFAULT;
    }

    {
        unsigned long idx = (addr >> PTE_SHIFT) & IDX_MASK;
        pte_entry = safe_read_ulong(pte_kva + idx * 8, &ok);
        if (!ok || !(pte_entry & PTE_VALID)) {
            kpm_err("WALK: PTE entry invalid (idx=%lu entry=0x%lx)\n",
                    idx, pte_entry);
            return -EFAULT;
        }
        kpm_info("WALK: PTE[%lu]=0x%lx\n", idx, pte_entry);
    }

    /* ---- Final page access ----------------------------------
     * PTE bits[47:12] = PFN.
     * Physical address = (PFN << 12) | VA[11:0].
     */
    pfn         = (pte_entry & PHYS_MASK) >> PTE_SHIFT;
    page_offset = addr & 0xFFFUL;
    phys_addr   = (pfn << PTE_SHIFT) | page_offset;

    kpm_info("WALK: virt=0x%lx → phys=0x%lx (pfn=0x%lx offset=0x%lx)\n",
             addr, phys_addr, pfn, page_offset);

    page_kva = (unsigned long)phys_to_virt_resolved(phys_addr);
    if (!page_kva) {
        kpm_err("WALK: final phys→virt failed (phys=0x%lx)\n", phys_addr);
        return -EFAULT;
    }

    /* Verify the result is a valid kernel VA before touching it */
    if (page_kva < 0xffffffc000000000ULL) {
        kpm_err("WALK: final kva looks wrong: 0x%lx\n", page_kva);
        return -EFAULT;
    }

    /* Guard page boundary */
    if (page_offset + (unsigned long)size > 0x1000UL) {
        kpm_err("WALK: 4KB page boundary crossed (offset=0x%lx size=%d)\n",
                page_offset, size);
        return -EFAULT;
    }

    if (is_write)
        memcpy((void *)page_kva, buffer, size);
    else
        memcpy(buffer, (void *)page_kva, size);

    kpm_info("WALK: %s %d bytes OK\n", is_write ? "wrote" : "read", size);
    return size;
}

/* ============================================================
 * PROCESS PACKET
 * ============================================================ */
static void process_packet(struct k_packet *pkt, pid_t caller_pid)
{
    struct task_struct *task = NULL;
    struct mm_struct   *mm   = NULL;
    pid_t  target_pid;
    int    transferred;
    int    is_write_op;
    uint8_t temp_buf[MAX_INLINE];

    kpm_info("PKT: op=0x%x pid=%u addr=0x%llx size=%u caller=%d\n",
             pkt->op_code, pkt->target_pid, pkt->vaddr, pkt->size, caller_pid);

    if (pkt->op_code != OP_READ_VM && pkt->op_code != OP_WRITE_VM) {
        pkt->status = STATUS_BAD_OPCODE;
        return;
    }
    if (!pkt->size || pkt->size > MAX_INLINE) {
        pkt->status = STATUS_INVALID_SIZE;
        return;
    }
    if (!is_valid_user_addr(pkt->vaddr)) {
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

    /* ---- task lookup (RCU) ---- */
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
        if (p_put_task_struct) p_put_task_struct(task);
        return;
    }

    /* ---- memory access ---- */
    is_write_op = (pkt->op_code == OP_WRITE_VM);
    memset(temp_buf, 0, MAX_INLINE);
    if (is_write_op)
        memcpy(temp_buf, pkt->inline_data, pkt->size);

    transferred = walk_page_table(mm, (unsigned long)pkt->vaddr,
                                  temp_buf, (int)pkt->size, is_write_op);

    /* mmput and put_task_struct always happen here — single exit point */
    p_mmput(mm);
    if (p_put_task_struct) p_put_task_struct(task);

    if (transferred < 0) {
        pkt->status = STATUS_VM_FAULT;
        return;
    }
    if (transferred == 0) {
        pkt->status = STATUS_PROTECTION;
        return;
    }
    if (!is_write_op) {
        memset(pkt->inline_data, 0, MAX_INLINE);
        memcpy(pkt->inline_data, temp_buf, (size_t)transferred);
    }
    pkt->size   = (uint32_t)transferred;
    pkt->status = ((uint32_t)transferred == pkt->size) ? STATUS_SUCCESS
                                                        : STATUS_PARTIAL_IO;
}

/* ============================================================
 * PROC HANDLERS
 * ============================================================ */
static int proc_open_handler(struct inode *inode, struct file *file)
{
    return 0;
}

static int proc_release_handler(struct inode *inode, struct file *file)
{
    return 0;
}

static ssize_t proc_read_handler(struct file *file, char __user *buf,
                                  size_t count, loff_t *pos)
{
    return 0;
}

static ssize_t proc_write_handler(struct file *file, const char __user *buf,
                                   size_t count, loff_t *pos)
{
    struct k_packet local_pkt;
    struct task_struct *curr;
    pid_t caller_pid;

    if (count != sizeof(struct k_packet))
        return -EINVAL;
    if (!p_copy_from_user)
        return -EFAULT;
    if (p_copy_from_user(&local_pkt, buf, sizeof(struct k_packet)) != 0)
        return -EFAULT;

    curr = hfr_get_current();
    if (!curr)
        return -ESRCH;
    if (!p_task_pid_nr_ns)
        return -EFAULT;

    caller_pid = p_task_pid_nr_ns(curr, PIDTYPE_PID, NULL);
    if (caller_pid <= 0)
        return -ESRCH;

    if (p_mutex_lock)   p_mutex_lock(&hfr_mutex);
    process_packet(&local_pkt, caller_pid);
    if (p_mutex_unlock) p_mutex_unlock(&hfr_mutex);

    if (!p_copy_to_user)
        return -EFAULT;
    if (p_copy_to_user((void __user *)buf, &local_pkt,
                        sizeof(struct k_packet)) != 0)
        return -EFAULT;

    return (ssize_t)count;
}

static const struct proc_ops p_ops = {
    .proc_flags             = 0,
    .proc_open              = proc_open_handler,
    .proc_read              = proc_read_handler,
    .proc_read_iter         = NULL,
    .proc_write             = proc_write_handler,
    .proc_lseek             = NULL,
    .proc_release           = proc_release_handler,
    .proc_poll              = NULL,
    .proc_ioctl             = NULL,
    .proc_mmap              = NULL,
    .proc_get_unmapped_area = NULL,
};

/* ============================================================
 * INIT / EXIT
 * ============================================================ */
static long hfr_memory_init(const char *args, const char *event,
                             void __user *reserved)
{
    unsigned long *memstart_ptr;

    kpm_info("=== INIT START (PGTABLE_LEVELS=3) ===\n");

    /* ---- resolve memstart_addr ---- */
    memstart_ptr = (unsigned long *)kallsyms_lookup_name("memstart_addr");
    if (!memstart_ptr) {
        kpm_err("memstart_addr symbol not found\n");
        return -EFAULT;
    }
    g_memstart_addr = *memstart_ptr;   /* DEREFERENCE — get the actual value */
    kpm_info("memstart_addr = 0x%lx\n", g_memstart_addr);
    kpm_info("PAGE_OFFSET   = 0x%lx\n", g_page_offset);
    kpm_info("phys_to_virt bias = 0x%lx\n", g_page_offset - g_memstart_addr);

    /* ---- symbol resolution ---- */
    p_proc_create_data  = (proc_create_data_t)kallsyms_lookup_name("proc_create_data");
    p_remove_proc_entry = (remove_proc_entry_t)kallsyms_lookup_name("remove_proc_entry");
    p_copy_from_user    = (copy_from_user_t)kallsyms_lookup_name("_copy_from_user");
    if (!p_copy_from_user)
        p_copy_from_user = (copy_from_user_t)kallsyms_lookup_name("copy_from_user");
    p_copy_to_user      = (copy_to_user_t)kallsyms_lookup_name("_copy_to_user");
    if (!p_copy_to_user)
        p_copy_to_user = (copy_to_user_t)kallsyms_lookup_name("copy_to_user");
    p_find_task_by_vpid = (find_task_by_vpid_t)kallsyms_lookup_name("find_task_by_vpid");
    p_get_task_mm       = (get_task_mm_t)kallsyms_lookup_name("get_task_mm");
    p_mmput             = (mmput_t)kallsyms_lookup_name("mmput");
    p_get_task_struct   = (get_task_struct_t)kallsyms_lookup_name("get_task_struct");
    p_put_task_struct   = (put_task_struct_t)kallsyms_lookup_name("put_task_struct");
    p_task_pid_nr_ns    = (task_pid_nr_ns_t)kallsyms_lookup_name("__task_pid_nr_ns");
    p_rcu_read_lock     = (rcu_read_lock_t)kallsyms_lookup_name("__rcu_read_lock");
    p_rcu_read_unlock   = (rcu_read_unlock_t)kallsyms_lookup_name("__rcu_read_unlock");
    p_mutex_init        = (mutex_init_t)kallsyms_lookup_name("__mutex_init");
    p_mutex_lock        = (mutex_lock_t)kallsyms_lookup_name("mutex_lock");
    p_mutex_unlock      = (mutex_unlock_t)kallsyms_lookup_name("mutex_unlock");

    if (!p_proc_create_data || !p_find_task_by_vpid || !p_task_pid_nr_ns ||
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

    kpm_info("=== INIT SUCCESS /proc/%s ===\n", proc_filename);
    kpm_info("3-LEVEL WALK ACTIVE: PGD[38:30]→PMD[29:21]→PTE[20:12]\n");
    return 0;
}

static long hfr_memory_exit(void __user *reserved)
{
    kpm_info("=== EXIT ===\n");
    if (proc_entry && p_remove_proc_entry)
        p_remove_proc_entry(proc_filename, NULL);
    return 0;
}

KPM_INIT(hfr_memory_init);
KPM_EXIT(hfr_memory_exit);
