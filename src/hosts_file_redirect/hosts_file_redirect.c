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

// ============================================================
// ✅ PHYS_TO_VIRT - Direct ARM64 formula (No header needed!)
// ============================================================
#ifndef PHYS_OFFSET
#define PHYS_OFFSET 0x0000000000000000ULL
#endif

#ifndef PAGE_OFFSET
#define PAGE_OFFSET 0xffffffc000000000ULL
#endif

static inline void *phys_to_virt_arm64(unsigned long phys) {
    return (void *)((phys - PHYS_OFFSET) | PAGE_OFFSET);
}

#define phys_to_virt(phys) phys_to_virt_arm64(phys)

KPM_NAME("hosts_file_redirect");
KPM_VERSION(HFR_VERSION);
KPM_LICENSE("GPL v2");
KPM_AUTHOR("Surajit");
KPM_DESCRIPTION("ULTIMATE BRUTE FORCE - PGD Offset Finder");

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
#define STATUS_ULTIMATE_OK    0x2000

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

// ============================================================
// 🔥 GLOBAL PGD OFFSET - Brute force will set this
// ============================================================
static int g_pgd_offset = 0;
static int g_pgd_offset_found = 0;

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

// ============================================================
// 🔥 BRUTE FORCE PGD OFFSET FINDER
// ============================================================
static int find_pgd_offset(struct mm_struct *mm)
{
    int offsets[] = {0x30, 0x38, 0x40, 0x28, 0x48, 0x50};
    int num_offsets = sizeof(offsets) / sizeof(offsets[0]);
    int i;
    unsigned long pgd_ptr;
    
    kpm_info("🔍 Brute forcing PGD offset...\n");
    
    for (i = 0; i < num_offsets; i++) {
        pgd_ptr = (unsigned long)((char *)mm + offsets[i]);
        
        // Check if pgd_ptr points to a valid PGD
        if (pgd_ptr && *(unsigned long *)pgd_ptr != 0) {
            unsigned long pgd_val = *(unsigned long *)pgd_ptr;
            
            // PGD entry should have valid bit (bit 0) set
            if (pgd_val & 1) {
                kpm_info("✅ Found valid PGD at offset 0x%x (pgd_val=0x%llx)\n", 
                         offsets[i], pgd_val);
                g_pgd_offset = offsets[i];
                g_pgd_offset_found = 1;
                return offsets[i];
            }
        }
    }
    
    kpm_err("❌ No valid PGD offset found!\n");
    return -1;
}

// ============================================================
// 🔥🔥🔥 ULTIMATE MEMORY ACCESS - Brute Force PGD Offset
// ============================================================
static int ultimate_memory_access(struct task_struct *task, unsigned long addr,
                                   void *buffer, int size, int is_write)
{
    struct mm_struct *mm;
    unsigned long pgd_ptr, pud_ptr, pmd_ptr, pte_ptr;
    unsigned long pgd_val, pud_val, pmd_val, pte_val;
    unsigned long pfn, phys_addr, offset;
    void *kaddr;
    int ret = 0;

    if (!task || !buffer || size <= 0 || size > MAX_INLINE) {
        return -EINVAL;
    }

    mm = p_get_task_mm(task);
    if (!mm) {
        kpm_err("ULTIMATE: No mm for task\n");
        return -EFAULT;
    }

    // 🔥 STEP 1: Find PGD offset if not found yet
    if (!g_pgd_offset_found) {
        if (find_pgd_offset(mm) < 0) {
            if (p_mmput) p_mmput(mm);
            return -EFAULT;
        }
    }

    // 🔥 STEP 2: PGD using found offset
    pgd_ptr = (unsigned long)((char *)mm + g_pgd_offset);
    if (!pgd_ptr || *(unsigned long *)pgd_ptr == 0) {
        kpm_err("ULTIMATE: Invalid PGD pointer at offset 0x%x\n", g_pgd_offset);
        if (p_mmput) p_mmput(mm);
        return -EFAULT;
    }
    kpm_info("ULTIMATE: mm->pgd at offset 0x%x = 0x%llx\n", g_pgd_offset, pgd_ptr);

    // 🔥 STEP 3: PGD Entry (ARM64: 9 bits, shift 39)
    unsigned long pgd_idx = (addr >> 39) & 0x1FF;
    pgd_val = *(unsigned long *)(pgd_ptr + pgd_idx * 8);
    if (!(pgd_val & 1)) {
        kpm_err("ULTIMATE: Invalid PGD entry\n");
        if (p_mmput) p_mmput(mm);
        return -EFAULT;
    }

    // 🔥 STEP 4: PUD Entry (ARM64: 9 bits, shift 30)
    unsigned long pud_idx = (addr >> 30) & 0x1FF;
    pud_ptr = pgd_val & ~0xFFF;
    pud_val = *(unsigned long *)(pud_ptr + pud_idx * 8);
    if (!(pud_val & 1)) {
        kpm_err("ULTIMATE: Invalid PUD entry\n");
        if (p_mmput) p_mmput(mm);
        return -EFAULT;
    }

    // 🔥 STEP 5: PMD Entry (ARM64: 9 bits, shift 21)
    unsigned long pmd_idx = (addr >> 21) & 0x1FF;
    pmd_ptr = pud_val & ~0xFFF;
    pmd_val = *(unsigned long *)(pmd_ptr + pmd_idx * 8);
    if (!(pmd_val & 1)) {
        kpm_err("ULTIMATE: Invalid PMD entry\n");
        if (p_mmput) p_mmput(mm);
        return -EFAULT;
    }

    // 🔥 STEP 6: Huge Page (2MB)
    if (pmd_val & (1 << 1)) {
        pfn = pmd_val >> 12;
        phys_addr = (pfn << 12) | (addr & 0x1FFFFF);
        kaddr = phys_to_virt(phys_addr);
        if (!kaddr) {
            if (p_mmput) p_mmput(mm);
            return -EFAULT;
        }
        if (is_write) {
            memcpy(kaddr + (addr & 0x1FFFFF), buffer, size);
        } else {
            memcpy(buffer, kaddr + (addr & 0x1FFFFF), size);
        }
        if (p_mmput) p_mmput(mm);
        return size;
    }

    // 🔥 STEP 7: PTE Entry (ARM64: 9 bits, shift 12)
    unsigned long pte_idx = (addr >> 12) & 0x1FF;
    pte_ptr = pmd_val & ~0xFFF;
    pte_val = *(unsigned long *)(pte_ptr + pte_idx * 8);
    if (!(pte_val & 1)) {
        kpm_err("ULTIMATE: Invalid PTE entry\n");
        if (p_mmput) p_mmput(mm);
        return -EFAULT;
    }

    // 🔥 STEP 8: PFN from PTE
    pfn = pte_val >> 12;
    if (pfn == 0) {
        kpm_err("ULTIMATE: Invalid PFN\n");
        if (p_mmput) p_mmput(mm);
        return -EFAULT;
    }

    // 🔥 STEP 9: Physical Address
    phys_addr = (pfn << 12) | (addr & 0xFFF);

    // ✅ Direct phys_to_virt
    kaddr = phys_to_virt(phys_addr);
    if (!kaddr) {
        kpm_err("ULTIMATE: phys_to_virt failed\n");
        if (p_mmput) p_mmput(mm);
        return -EFAULT;
    }

    // 🔥 STEP 10: DIRECT ACCESS - NO PERMISSION CHECK!
    offset = addr & 0xFFF;
    if (is_write) {
        memcpy(kaddr + offset, buffer, size);
    } else {
        memcpy(buffer, kaddr + offset, size);
    }
    ret = size;

    if (p_mmput) p_mmput(mm);
    return ret;
}

// ============================================================
// PROCESS PACKET - Ultimate Access (No Fallback!)
// ============================================================
static void process_packet(struct k_packet *pkt, pid_t caller_pid)
{
    struct task_struct *task = NULL;
    struct mm_struct *mm = NULL;
    pid_t target_pid;
    int transferred;
    int is_write_op = 0;
    uint8_t temp_buffer[MAX_INLINE];

    kpm_info(">>> process_packet ENTER: op=0x%x pid=%u addr=0x%llx size=%u caller_pid=%d\n",
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
    kpm_info("target_pid resolved: %d\n", target_pid);
    
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

    is_write_op = (pkt->op_code == OP_WRITE_VM);
    memset(temp_buffer, 0, MAX_INLINE);
    
    if (is_write_op) {
        memcpy(temp_buffer, pkt->inline_data, pkt->size);
    }

    // ============================================================
    // 🔥🔥🔥 ULTIMATE MEMORY ACCESS - NO FALLBACK! 🔥🔥🔥
    // ============================================================
    transferred = ultimate_memory_access(task, pkt->vaddr, temp_buffer, pkt->size, is_write_op);

    if (transferred > 0) {
        kpm_info("✅ ULTIMATE SUCCESS: %d bytes\n", transferred);
        pkt->status = STATUS_ULTIMATE_OK;
    } else {
        kpm_err("❌ ULTIMATE FAILED: %d\n", transferred);
        pkt->status = STATUS_PROTECTION;
    }

    if (mm) p_mmput(mm);
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

    if (pkt->status == STATUS_ULTIMATE_OK) {
        pkt->status = STATUS_SUCCESS;
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
        return -EINVAL;
    }

    if (!p_copy_from_user) return -EFAULT;
    
    if (p_copy_from_user(&local_pkt, buffer, sizeof(struct k_packet)) != 0) {
        return -EFAULT;
    }

    curr_task = hfr_get_current();
    if (!curr_task) return -ESRCH;

    if (!p_task_pid_nr_ns) return -EFAULT;

    caller_pid = p_task_pid_nr_ns(curr_task, PIDTYPE_PID, NULL);
    
    if (caller_pid <= 0) return -ESRCH;

    if (p_mutex_lock) p_mutex_lock(&hfr_mutex);
    process_packet(&local_pkt, caller_pid);
    if (p_mutex_unlock) p_mutex_unlock(&hfr_mutex);

    if (!p_copy_to_user) return -EFAULT;
    
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
    kpm_info("=== ULTIMATE BRUTE FORCE INIT START ===\n");
    
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

    kpm_info("=== ULTIMATE BRUTE FORCE INIT SUCCESS /proc/%s ===\n", proc_filename);
    kpm_info("🔥 Brute force PGD offset finder ACTIVE!\n");
    return 0;
}

static long hfr_memory_exit(void __user *reserved)
{
    kpm_info("=== ULTIMATE EXIT ===\n");
    if (proc_entry && p_remove_proc_entry) p_remove_proc_entry(proc_filename, NULL);
    return 0;
}

KPM_INIT(hfr_memory_init);
KPM_EXIT(hfr_memory_exit);
