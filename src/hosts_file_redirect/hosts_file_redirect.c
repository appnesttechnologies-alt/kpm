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
#include <asm/pgtable.h>
#include <asm/processor.h>

KPM_NAME("hosts_file_redirect");
KPM_VERSION(HFR_VERSION);
KPM_LICENSE("GPL v2");
KPM_AUTHOR("Surajit");
KPM_DESCRIPTION("ARM64 userspace memory access using kernel page-table helpers");

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

struct k_packet {
    uint32_t op_code;
    uint32_t target_pid;
    uint64_t vaddr;
    uint32_t size;
    uint32_t status;
    uint8_t  inline_data[MAX_INLINE];
} __attribute__((aligned(8), packed));

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
    return (addr != 0) && (addr < (1ULL << 55));
}

/* ============================================================
 * PAGE ACCESS HELPERS
 * ============================================================ */
static int hfr_copy_pte_page(pte_t *pte, unsigned long addr,
                             void *buffer, int size, int is_write)
{
    struct page *page;
    void *base;
    unsigned long off;

    if (!pte_present(*pte) || !pte_valid(*pte))
        return -EFAULT;

    if (is_write && !pte_write(*pte))
        return -EACCES;

    page = pte_page(*pte);
    if (!page)
        return -EFAULT;

    base = page_address(page);
    if (!base)
        return -EFAULT;

    off = addr & (PAGE_SIZE - 1);
    if (off + (unsigned long)size > PAGE_SIZE)
        return -EFAULT;

    if (is_write)
        memcpy((void *)((unsigned long)base + off), buffer, size);
    else
        memcpy(buffer, (void *)((unsigned long)base + off), size);

    return size;
}

static int hfr_copy_pmd_huge(pmd_t *pmd, unsigned long addr,
                             void *buffer, int size, int is_write)
{
#if defined(PMD_SIZE) && defined(PMD_MASK)
    unsigned long pfn, phys, off;
    void *kaddr;

    if (!pmd_present(*pmd))
        return -EFAULT;

    off = addr & ~PMD_MASK;
    if (off + (unsigned long)size > PMD_SIZE)
        return -EFAULT;

    pfn  = pmd_pfn(*pmd);
    phys = (pfn << PAGE_SHIFT) | off;
    kaddr = phys_to_virt(phys);
    if (!kaddr)
        return -EFAULT;

    if (is_write)
        memcpy(kaddr, buffer, size);
    else
        memcpy(buffer, kaddr, size);

    return size;
#else
    return -EFAULT;
#endif
}

static int hfr_copy_pud_huge(pud_t *pud, unsigned long addr,
                             void *buffer, int size, int is_write)
{
#if defined(PUD_SIZE) && defined(PUD_MASK)
    unsigned long pfn, phys, off;
    void *kaddr;

    if (!pud_present(*pud))
        return -EFAULT;

    off = addr & ~PUD_MASK;
    if (off + (unsigned long)size > PUD_SIZE)
        return -EFAULT;

    pfn  = pud_pfn(*pud);
    phys = (pfn << PAGE_SHIFT) | off;
    kaddr = phys_to_virt(phys);
    if (!kaddr)
        return -EFAULT;

    if (is_write)
        memcpy(kaddr, buffer, size);
    else
        memcpy(buffer, kaddr, size);

    return size;
#else
    return -EFAULT;
#endif
}

/* ============================================================
 * ROBUST PAGE WALK
 * ============================================================ */
static int walk_page_table(struct mm_struct *mm, unsigned long addr,
                           void *buffer, int size, int is_write)
{
    pgd_t *pgd;
    p4d_t *p4d;
    pud_t *pud;
    pmd_t *pmd;
    pte_t *pte;
    spinlock_t *ptl = NULL;
    int ret = -EFAULT;

    if (!mm || !buffer || size <= 0)
        return -EINVAL;

    if (!is_valid_user_addr(addr))
        return -EFAULT;

    if ((addr & (PAGE_SIZE - 1)) + (unsigned long)size > PAGE_SIZE) {
        kpm_err("WALK: page boundary crossed addr=0x%lx size=%d
", addr, size);
        return -EFAULT;
    }

    pgd = pgd_offset(mm, addr);
    if (!pgd) {
        kpm_err("WALK: pgd_offset NULL addr=0x%lx
", addr);
        return -EFAULT;
    }
    if (pgd_none(*pgd) || pgd_bad(*pgd)) {
        kpm_err("WALK: bad/none pgd addr=0x%lx
", addr);
        return -EFAULT;
    }

    p4d = p4d_offset(pgd, addr);
    if (!p4d) {
        kpm_err("WALK: p4d_offset NULL addr=0x%lx
", addr);
        return -EFAULT;
    }
    if (p4d_none(*p4d) || p4d_bad(*p4d)) {
        kpm_err("WALK: bad/none p4d addr=0x%lx
", addr);
        return -EFAULT;
    }

    pud = pud_offset(p4d, addr);
    if (!pud) {
        kpm_err("WALK: pud_offset NULL addr=0x%lx
", addr);
        return -EFAULT;
    }
    if (pud_none(*pud) || pud_bad(*pud) || !pud_present(*pud)) {
        kpm_err("WALK: bad/none pud addr=0x%lx
", addr);
        return -EFAULT;
    }

#ifdef pud_leaf
    if (pud_leaf(*pud)) {
        ret = hfr_copy_pud_huge(pud, addr, buffer, size, is_write);
        if (ret < 0)
            kpm_err("WALK: pud leaf access failed addr=0x%lx ret=%d
", addr, ret);
        return ret;
    }
#endif

    pmd = pmd_offset(pud, addr);
    if (!pmd) {
        kpm_err("WALK: pmd_offset NULL addr=0x%lx
", addr);
        return -EFAULT;
    }
    if (pmd_none(*pmd) || pmd_bad(*pmd) || !pmd_present(*pmd)) {
        kpm_err("WALK: bad/none pmd addr=0x%lx
", addr);
        return -EFAULT;
    }

#if defined(pmd_leaf) || defined(pmd_trans_huge) || defined(pmd_huge)
    if (
#ifdef pmd_leaf
        pmd_leaf(*pmd) ||
#endif
#ifdef pmd_trans_huge
        pmd_trans_huge(*pmd) ||
#endif
#ifdef pmd_huge
        pmd_huge(*pmd) ||
#endif
        0) {
        ret = hfr_copy_pmd_huge(pmd, addr, buffer, size, is_write);
        if (ret < 0)
            kpm_err("WALK: pmd huge access failed addr=0x%lx ret=%d
", addr, ret);
        return ret;
    }
#endif

    pte = pte_offset_map_lock(mm, pmd, addr, &ptl);
    if (!pte) {
        kpm_err("WALK: pte_offset_map_lock failed addr=0x%lx
", addr);
        return -EFAULT;
    }

    ret = hfr_copy_pte_page(pte, addr, buffer, size, is_write);

    pte_unmap_unlock(pte, ptl);

    if (ret < 0)
        kpm_err("WALK: pte access failed addr=0x%lx ret=%d
", addr, ret);
    else
        kpm_info("WALK: %s %d bytes OK addr=0x%lx
",
                 is_write ? "wrote" : "read", ret, addr);

    return ret;
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
    uint32_t requested;
    uint8_t temp_buf[MAX_INLINE];

    if (!pkt) return;

    kpm_info("PKT: op=0x%x pid=%u addr=0x%llx size=%u caller=%d
",
             pkt->op_code, pkt->target_pid, pkt->vaddr, pkt->size, caller_pid);

    pkt->status = STATUS_VM_FAULT;
    requested = pkt->size;

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

    is_write_op = (pkt->op_code == OP_WRITE_VM);
    memset(temp_buf, 0, sizeof(temp_buf));

    if (is_write_op)
        memcpy(temp_buf, pkt->inline_data, requested);

    transferred = walk_page_table(mm, (unsigned long)pkt->vaddr,
                                  temp_buf, (int)requested, is_write_op);

    p_mmput(mm);
    if (p_put_task_struct) p_put_task_struct(task);

    if (transferred < 0) {
        if (transferred == -EACCES)
            pkt->status = STATUS_PROTECTION;
        else
            pkt->status = STATUS_VM_FAULT;
        return;
    }

    if (!is_write_op) {
        memset(pkt->inline_data, 0, MAX_INLINE);
        memcpy(pkt->inline_data, temp_buf, (size_t)transferred);
    }

    pkt->size = (uint32_t)transferred;
    pkt->status = ((uint32_t)transferred == requested) ?
                  STATUS_SUCCESS : STATUS_PARTIAL_IO;
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

    memset(&local_pkt, 0, sizeof(local_pkt));

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
    kpm_info("=== INIT START ===
");

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
        kpm_err("CRITICAL SYMBOL MISSING
");
        return -EFAULT;
    }

    if (p_mutex_init)
        p_mutex_init(&hfr_mutex);

    proc_entry = p_proc_create_data(proc_filename, 0666, NULL, &p_ops, NULL);
    if (!proc_entry) {
        kpm_err("proc_create FAILED
");
        return -EFAULT;
    }

    kpm_info("=== INIT SUCCESS /proc/%s ===
", proc_filename);
    return 0;
}

static long hfr_memory_exit(void __user *reserved)
{
    kpm_info("=== EXIT ===
");
    if (proc_entry && p_remove_proc_entry)
        p_remove_proc_entry(proc_filename, NULL);
    return 0;
}

KPM_INIT(hfr_memory_init);
KPM_EXIT(hfr_memory_exit);
