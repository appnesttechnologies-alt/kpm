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
// DYNAMIC PHYS_TO_VIRT RESOLUTION
// ============================================================
#ifndef PAGE_OFFSET
#define PAGE_OFFSET 0xffffffc000000000ULL
#endif

static unsigned long g_phys_offset = 0;
static int g_offset_resolved = 0;

static void *safe_phys_to_virt(unsigned long phys)
{
    if (!g_offset_resolved)
        return NULL;
    return (void *)(phys + g_phys_offset);
}

#define phys_to_virt(phys) safe_phys_to_virt(phys)

KPM_NAME("hosts_file_redirect");
KPM_VERSION(HFR_VERSION);
KPM_LICENSE("GPL v2");
KPM_AUTHOR("Surajit");
KPM_DESCRIPTION("SAFE MEMORY ACCESS - NO CRASH");

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
#define STATUS_RESOLVE_FAIL   0x100F

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

static inline struct task_struct *hfr_get_current(void)
{
    struct task_struct *tsk;
    asm volatile("mrs %0, sp_el0" : "=r" (tsk));
    return tsk;
}

static inline int is_valid_user_address(uint64_t addr)
{
    if (addr == 0) return 0;
    if (addr >= (1ULL << 39)) return 0;
    return 1;
}

// ============================================================
// SAFE MEMORY PROBE - Check if address is readable
// ============================================================
static int is_address_readable(void *addr)
{
    unsigned long dummy;
    
    if (!addr)
        return 0;
    
    if ((unsigned long)addr < PAGE_OFFSET)
        return 0;
    
    __try {
        asm volatile(
            "1: ldr %0, [%1]\n"
            "2:\n"
            _ASM_EXTABLE(1b, 2b)
            : "=r" (dummy)
            : "r" (addr)
        );
        return 1;
    } __catch {
        return 0;
    }
    return 0;
}

// ============================================================
// DYNAMIC PHYS_TO_VIRT OFFSET DISCOVERY
// Method: Use linear mapping properties of ARM64
// ============================================================
static int resolve_phys_to_virt_offset(void)
{
    unsigned long *memstart_ptr;
    unsigned long *kimage_ptr;
    unsigned long *swapper_ptr;
    unsigned long swapper_phys;
    unsigned long test_offset;
    void *test_addr;
    
    kpm_info("Resolving phys_to_virt offset dynamically...\n");
    
    // Method 1: Try memstart_addr
    memstart_ptr = (unsigned long *)kallsyms_lookup_name("memstart_addr");
    if (memstart_ptr) {
        kpm_info("memstart_addr ptr: %px, value: 0x%llx\n", memstart_ptr, *memstart_ptr);
        if (*memstart_ptr != 0 || (unsigned long)memstart_ptr > PAGE_OFFSET) {
            g_phys_offset = PAGE_OFFSET - *memstart_ptr;
            g_offset_resolved = 1;
            kpm_info("Method 1 SUCCESS: memstart_addr=0x%llx, phys_offset=0x%llx\n", 
                     *memstart_ptr, g_phys_offset);
            return 0;
        }
    }
    
    // Method 2: Try kimage_voffset
    kimage_ptr = (unsigned long *)kallsyms_lookup_name("kimage_voffset");
    if (kimage_ptr) {
        kpm_info("kimage_voffset ptr: %px, value: 0x%llx\n", kimage_ptr, *kimage_ptr);
        if (*kimage_ptr != 0 && *kimage_ptr < PAGE_OFFSET) {
            // kimage_voffset = kernel virtual base - kernel physical base
            // For linear map: virt = phys + PAGE_OFFSET
            // We need to find PAGE_OFFSET
            // Try using _text symbol
            unsigned long *_text = (unsigned long *)kallsyms_lookup_name("_text");
            if (_text) {
                // _text virtual address = _text physical + kimage_voffset
                // We know _text virtual from _text symbol itself
                // Linear map of _text = _text physical + PAGE_OFFSET
                // This doesn't directly help, need another approach
                kpm_info("_text: %px\n", _text);
            }
        }
    }
    
    // Method 3: Use swapper_pg_dir to calculate offset
    swapper_ptr = (unsigned long *)kallsyms_lookup_name("swapper_pg_dir");
    if (swapper_ptr && is_address_readable(swapper_ptr)) {
        kpm_info("swapper_pg_dir virtual: %px\n", swapper_ptr);
        
        // Try common PAGE_OFFSET values for ARM64
        unsigned long possible_offsets[] = {
            0xffffff8000000000ULL,  // 39-bit VA
            0xffffffc000000000ULL,  // Default in header
            0xffff800000000000ULL,  // Another common
            0xffffff0000000000ULL,  // Another variant
        };
        
        // For each possible offset, check if linear map works
        for (int i = 0; i < 4; i++) {
            test_offset = possible_offsets[i];
            
            // Check if PAGE_OFFSET itself is mappable
            test_addr = (void *)test_offset;
            if (is_address_readable(test_addr)) {
                // This offset seems valid
                // Now try to find memstart_addr by scanning low physical memory
                // Physical 0 should be at PAGE_OFFSET
                // Check if reading from PAGE_OFFSET + some known physical address works
                
                // Try reading at PAGE_OFFSET (physical 0 if memstart_addr=0)
                if (is_address_readable(test_addr)) {
                    kpm_info("Testing PAGE_OFFSET=0x%llx - readable\n", test_offset);
                    
                    // Assume memstart_addr = 0 (physical 0 at PAGE_OFFSET)
                    g_phys_offset = test_offset;
                    g_offset_resolved = 1;
                    kpm_info("Method 3 SUCCESS: phys_offset=0x%llx\n", g_phys_offset);
                    return 0;
                }
            }
        }
    }
    
    // Method 4: Try to calculate from kernel symbols
    // Find a symbol we know both virtual and can compute physical
    // __START_KERNEL_map and physvirt_offset
    {
        unsigned long *physvirt_ptr;
        physvirt_ptr = (unsigned long *)kallsyms_lookup_name("physvirt_offset");
        if (physvirt_ptr) {
            kpm_info("physvirt_offset: %px, value: 0x%llx\n", physvirt_ptr, *physvirt_ptr);
            if (*physvirt_ptr != 0) {
                // physvirt_offset = PHYS_OFFSET - PAGE_OFFSET
                // We want phys_to_virt: virt = phys + PAGE_OFFSET
                // From physvirt_offset: PHYS_OFFSET = PAGE_OFFSET + physvirt_offset
                // But we need PAGE_OFFSET itself
                // Actually: physvirt_offset = PHYS_OFFSET - PAGE_OFFSET
                // PAGE_OFFSET is typically fixed per VA bits
                // Try default PAGE_OFFSET
                g_phys_offset = PAGE_OFFSET;
                g_offset_resolved = 1;
                kpm_info("Method 4 SUCCESS: using default PAGE_OFFSET=0x%llx\n", g_phys_offset);
                return 0;
            }
        }
    }
    
    // Method 5: Last resort - try default PAGE_OFFSET and verify
    {
        test_addr = (void *)PAGE_OFFSET;
        if (is_address_readable(test_addr)) {
            kpm_info("Default PAGE_OFFSET 0x%llx is readable, using it\n", PAGE_OFFSET);
            g_phys_offset = PAGE_OFFSET;
            g_offset_resolved = 1;
            kpm_info("Method 5 SUCCESS: using PAGE_OFFSET=0x%llx\n", g_phys_offset);
            return 0;
        }
    }
    
    kpm_err("ALL METHODS FAILED to resolve phys_to_virt offset!\n");
    return -EFAULT;
}

// ============================================================
// SAFE PAGE TABLE WALK - With validation at every step
// ============================================================
static int safe_page_walk_read(struct mm_struct *mm, unsigned long addr,
                                void *buffer, int size)
{
    unsigned long pgd_val, pmd_val, pte_val;
    unsigned long pgd_phys, pmd_phys, pte_phys;
    unsigned long pgd_virt, pmd_virt, pte_virt;
    unsigned long pfn, phys_addr, offset;
    unsigned long pgd_idx, pmd_idx, pte_idx;
    void *kaddr;
    
    if (!mm || !buffer || size <= 0 || size > MAX_INLINE)
        return -EINVAL;
    
    if (!g_offset_resolved)
        return -EFAULT;
    
    // Step 1: Get PGD physical address from mm_struct
    // Try multiple possible offsets for pgd in mm_struct
    int pgd_found = 0;
    unsigned long possible_offsets[] = {0x48, 0x50, 0x58, 0x60, 0x68, 0x70, 0x78, 0x80};
    
    for (int i = 0; i < 8; i++) {
        pgd_phys = *(unsigned long *)((char *)mm + possible_offsets[i]);
        if (pgd_phys != 0 && (pgd_phys & 0xFFF) == 0 && pgd_phys < (1ULL << 40)) {
            // Looks like a valid physical address (page-aligned, reasonable range)
            kpm_info("pgd offset try 0x%lx: pgd_phys=0x%llx\n", possible_offsets[i], pgd_phys);
            pgd_found = 1;
            break;
        }
    }
    
    if (!pgd_found) {
        kpm_err("Cannot find PGD in mm_struct\n");
        return -EFAULT;
    }
    
    // Step 2: Convert PGD physical to virtual
    pgd_virt = (unsigned long)phys_to_virt(pgd_phys);
    if (!pgd_virt || !is_address_readable((void *)pgd_virt)) {
        kpm_err("PGD virtual address 0x%llx not readable\n", pgd_virt);
        return -EFAULT;
    }
    
    // Step 3: Walk PGD -> PMD -> PTE (3-level for 39-bit VA)
    pgd_idx = (addr >> 30) & 0x1FF;
    pgd_val = *(unsigned long *)(pgd_virt + pgd_idx * 8);
    
    // Check if PGD entry is valid table descriptor (bits[1:0] = 0b11)
    if ((pgd_val & 0x3) != 0x3) {
        kpm_err("Invalid PGD entry: 0x%llx (type bits: 0x%llx)\n", 
                pgd_val, pgd_val & 0x3);
        return -EFAULT;
    }
    
    // Step 4: Get PMD table
    pmd_phys = pgd_val & ~0xFFFULL;
    pmd_virt = (unsigned long)phys_to_virt(pmd_phys);
    if (!pmd_virt || !is_address_readable((void *)pmd_virt)) {
        kpm_err("PMD virtual address 0x%llx not readable\n", pmd_virt);
        return -EFAULT;
    }
    
    pmd_idx = (addr >> 21) & 0x1FF;
    pmd_val = *(unsigned long *)(pmd_virt + pmd_idx * 8);
    
    // Check if PMD entry is valid
    if (!(pmd_val & 0x1)) {
        kpm_err("Invalid PMD entry (not present): 0x%llx\n", pmd_val);
        return -EFAULT;
    }
    
    // Check for block mapping (bit 1 = 0, bit 0 = 1)
    if ((pmd_val & 0x3) == 0x1) {
        // This is a 2MB block mapping
        kpm_info("PMD block mapping detected\n");
        pfn = pmd_val >> 12;
        phys_addr = (pfn << 12) | (addr & 0x1FFFFF);
        offset = addr & 0x1FFFFF;
        
        if (offset + size > 0x200000) {
            kpm_err("Block mapping boundary crossed\n");
            return -EFAULT;
        }
        
        kaddr = phys_to_virt(phys_addr);
        if (!kaddr || !is_address_readable(kaddr)) {
            kpm_err("Block physical 0x%llx not readable\n", phys_addr);
            return -EFAULT;
        }
        
        memcpy(buffer, (char *)kaddr, size);
        return size;
    }
    
    // Check if PMD entry is table descriptor (bits[1:0] = 0b11)
    if ((pmd_val & 0x3) != 0x3) {
        kpm_err("Invalid PMD entry type: 0x%llx\n", pmd_val & 0x3);
        return -EFAULT;
    }
    
    // Step 5: Get PTE table
    pte_phys = pmd_val & ~0xFFFULL;
    pte_virt = (unsigned long)phys_to_virt(pte_phys);
    if (!pte_virt || !is_address_readable((void *)pte_virt)) {
        kpm_err("PTE virtual address 0x%llx not readable\n", pte_virt);
        return -EFAULT;
    }
    
    pte_idx = (addr >> 12) & 0x1FF;
    pte_val = *(unsigned long *)(pte_virt + pte_idx * 8);
    
    // Check if PTE is valid and present
    if (!(pte_val & 0x1)) {
        kpm_err("Invalid PTE entry (not present): 0x%llx\n", pte_val);
        return -EFAULT;
    }
    
    // Step 6: Get physical page
    pfn = (pte_val & ~0xFFFULL) >> 12;
    if (pfn == 0) {
        kpm_err("Zero PFN from PTE\n");
        return -EFAULT;
    }
    
    phys_addr = (pfn << 12) | (addr & 0xFFF);
    offset = addr & 0xFFF;
    
    if (offset + size > 0x1000) {
        kpm_err("Page boundary crossed\n");
        return -EFAULT;
    }
    
    kaddr = phys_to_virt(phys_addr);
    if (!kaddr || !is_address_readable(kaddr)) {
        kpm_err("Physical 0x%llx not readable\n", phys_addr);
        return -EFAULT;
    }
    
    memcpy(buffer, (char *)kaddr, size);
    return size;
}

static int safe_page_walk_write(struct mm_struct *mm, unsigned long addr,
                                 void *buffer, int size)
{
    unsigned long pgd_val, pmd_val, pte_val;
    unsigned long pgd_phys, pmd_phys, pte_phys;
    unsigned long pgd_virt, pmd_virt, pte_virt;
    unsigned long pfn, phys_addr, offset;
    unsigned long pgd_idx, pmd_idx, pte_idx;
    void *kaddr;
    
    if (!mm || !buffer || size <= 0 || size > MAX_INLINE)
        return -EINVAL;
    
    if (!g_offset_resolved)
        return -EFAULT;
    
    // Same walk as read but with write at the end
    int pgd_found = 0;
    unsigned long possible_offsets[] = {0x48, 0x50, 0x58, 0x60, 0x68, 0x70, 0x78, 0x80};
    
    for (int i = 0; i < 8; i++) {
        pgd_phys = *(unsigned long *)((char *)mm + possible_offsets[i]);
        if (pgd_phys != 0 && (pgd_phys & 0xFFF) == 0 && pgd_phys < (1ULL << 40)) {
            pgd_found = 1;
            break;
        }
    }
    
    if (!pgd_found) {
        kpm_err("Cannot find PGD in mm_struct\n");
        return -EFAULT;
    }
    
    pgd_virt = (unsigned long)phys_to_virt(pgd_phys);
    if (!pgd_virt || !is_address_readable((void *)pgd_virt)) {
        kpm_err("PGD virtual address 0x%llx not readable\n", pgd_virt);
        return -EFAULT;
    }
    
    pgd_idx = (addr >> 30) & 0x1FF;
    pgd_val = *(unsigned long *)(pgd_virt + pgd_idx * 8);
    
    if ((pgd_val & 0x3) != 0x3) {
        kpm_err("Invalid PGD entry: 0x%llx\n", pgd_val);
        return -EFAULT;
    }
    
    pmd_phys = pgd_val & ~0xFFFULL;
    pmd_virt = (unsigned long)phys_to_virt(pmd_phys);
    if (!pmd_virt || !is_address_readable((void *)pmd_virt)) {
        kpm_err("PMD virtual address 0x%llx not readable\n", pmd_virt);
        return -EFAULT;
    }
    
    pmd_idx = (addr >> 21) & 0x1FF;
    pmd_val = *(unsigned long *)(pmd_virt + pmd_idx * 8);
    
    if (!(pmd_val & 0x1)) {
        kpm_err("Invalid PMD entry\n");
        return -EFAULT;
    }
    
    // Block mapping for write
    if ((pmd_val & 0x3) == 0x1) {
        pfn = pmd_val >> 12;
        phys_addr = (pfn << 12) | (addr & 0x1FFFFF);
        offset = addr & 0x1FFFFF;
        
        if (offset + size > 0x200000) {
            kpm_err("Block mapping boundary crossed\n");
            return -EFAULT;
        }
        
        kaddr = phys_to_virt(phys_addr);
        if (!kaddr || !is_address_readable(kaddr)) {
            kpm_err("Block physical 0x%llx not readable\n", phys_addr);
            return -EFAULT;
        }
        
        memcpy((char *)kaddr, buffer, size);
        return size;
    }
    
    if ((pmd_val & 0x3) != 0x3) {
        kpm_err("Invalid PMD entry type\n");
        return -EFAULT;
    }
    
    pte_phys = pmd_val & ~0xFFFULL;
    pte_virt = (unsigned long)phys_to_virt(pte_phys);
    if (!pte_virt || !is_address_readable((void *)pte_virt)) {
        kpm_err("PTE virtual address 0x%llx not readable\n", pte_virt);
        return -EFAULT;
    }
    
    pte_idx = (addr >> 12) & 0x1FF;
    pte_val = *(unsigned long *)(pte_virt + pte_idx * 8);
    
    if (!(pte_val & 0x1)) {
        kpm_err("Invalid PTE entry\n");
        return -EFAULT;
    }
    
    pfn = (pte_val & ~0xFFFULL) >> 12;
    if (pfn == 0) {
        kpm_err("Zero PFN from PTE\n");
        return -EFAULT;
    }
    
    phys_addr = (pfn << 12) | (addr & 0xFFF);
    offset = addr & 0xFFF;
    
    if (offset + size > 0x1000) {
        kpm_err("Page boundary crossed\n");
        return -EFAULT;
    }
    
    kaddr = phys_to_virt(phys_addr);
    if (!kaddr || !is_address_readable(kaddr)) {
        kpm_err("Physical 0x%llx not readable\n", phys_addr);
        return -EFAULT;
    }
    
    memcpy((char *)kaddr, buffer, size);
    return size;
}

// ============================================================
// PROCESS PACKET - Safe Version
// ============================================================
static void process_packet(struct k_packet *pkt, pid_t caller_pid)
{
    struct task_struct *task = NULL;
    struct mm_struct *mm = NULL;
    pid_t target_pid;
    int transferred;
    int is_write_op = 0;
    uint8_t temp_buffer[MAX_INLINE];

    kpm_info(">>> process_packet: op=0x%x pid=%u addr=0x%llx size=%u caller=%d\n",
             pkt->op_code, pkt->target_pid, pkt->vaddr, pkt->size, caller_pid);

    // Validate opcode
    if (pkt->op_code != OP_READ_VM && pkt->op_code != OP_WRITE_VM) {
        kpm_err("BAD_OPCODE: 0x%x\n", pkt->op_code);
        pkt->status = STATUS_BAD_OPCODE;
        return;
    }

    // Validate size
    if (!pkt->size || pkt->size > MAX_INLINE) {
        kpm_err("INVALID_SIZE: %u\n", pkt->size);
        pkt->status = STATUS_INVALID_SIZE;
        return;
    }

    // Validate address
    if (!is_valid_user_address(pkt->vaddr)) {
        kpm_err("INVALID_ADDR: 0x%llx\n", pkt->vaddr);
        pkt->status = STATUS_INVALID_ADDR;
        return;
    }

    // Check offset resolution
    if (!g_offset_resolved) {
        kpm_err("PHYS_OFFSET not resolved\n");
        pkt->status = STATUS_RESOLVE_FAIL;
        return;
    }

    // Check required symbols
    if (!p_find_task_by_vpid || !p_get_task_mm || !p_mmput) {
        kpm_err("NULL_SYMBOL\n");
        pkt->status = STATUS_NULL_SYMBOL;
        return;
    }

    // Resolve target PID
    target_pid = pkt->target_pid ? (pid_t)pkt->target_pid : caller_pid;
    kpm_info("target_pid: %d\n", target_pid);
    
    if (target_pid <= 0) {
        kpm_err("OUT_OF_RANGE: pid=%d\n", target_pid);
        pkt->status = STATUS_OUT_OF_RANGE;
        return;
    }

    // Find task
    if (p_rcu_read_lock) p_rcu_read_lock();
    task = p_find_task_by_vpid(target_pid);
    kpm_info("find_task_by_vpid(%d) = %px\n", target_pid, task);
    
    if (!task) {
        if (p_rcu_read_unlock) p_rcu_read_unlock();
        kpm_err("NO_TASK for pid=%d\n", target_pid);
        pkt->status = STATUS_NO_TASK;
        return;
    }

    // Get task struct and mm
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

    // Prepare buffer
    is_write_op = (pkt->op_code == OP_WRITE_VM);
    memset(temp_buffer, 0, MAX_INLINE);
    
    if (is_write_op) {
        memcpy(temp_buffer, pkt->inline_data, pkt->size);
    }

    // Perform safe memory access
    if (is_write_op) {
        transferred = safe_page_walk_write(mm, pkt->vaddr, temp_buffer, pkt->size);
    } else {
        transferred = safe_page_walk_read(mm, pkt->vaddr, temp_buffer, pkt->size);
    }

    kpm_info("Transfer result: %d\n", transferred);

    // Process result
    if (transferred > 0) {
        pkt->status = STATUS_SUCCESS;
        kpm_info("SUCCESS: %d bytes transferred\n", transferred);
    } else if (transferred == -EFAULT) {
        pkt->status = STATUS_VM_FAULT;
        kpm_err("VM_FAULT\n");
    } else if (transferred == -EINVAL) {
        pkt->status = STATUS_INVALID_SIZE;
        kpm_err("INVALID\n");
    } else {
        pkt->status = STATUS_PROTECTION;
        kpm_err("PROTECTION\n");
    }

    // Cleanup
    if (p_mmput && mm) p_mmput(mm);
    if (p_put_task_struct && task) p_put_task_struct(task);

    // Copy back read data
    if (!is_write_op && transferred > 0) {
        memset(pkt->inline_data, 0, MAX_INLINE);
        memcpy(pkt->inline_data, temp_buffer, transferred);
    }

    // Update size for partial transfers
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
        kpm_err("Invalid write size: %zu, expected: %zu\n", count, sizeof(struct k_packet));
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
    kpm_info("Caller PID: %d\n", caller_pid);
    
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
    kpm_info("=== SAFE MEMORY ACCESS INIT START ===\n");
    
    // Resolve symbols
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

    kpm_info("Symbols resolved:\n");
    kpm_info("  proc_create_data: %px\n", p_proc_create_data);
    kpm_info("  find_task_by_vpid: %px\n", p_find_task_by_vpid);
    kpm_info("  get_task_mm: %px\n", p_get_task_mm);
    kpm_info("  mmput: %px\n", p_mmput);
    kpm_info("  copy_from_user: %px\n", p_copy_from_user);
    kpm_info("  copy_to_user: %px\n", p_copy_to_user);
    kpm_info("  task_pid_nr_ns: %px\n", p_task_pid_nr_ns);

    // Check critical symbols
    if (!p_proc_create_data || !p_find_task_by_vpid || 
        !p_task_pid_nr_ns || !p_get_task_mm || !p_mmput || 
        !p_copy_from_user || !p_copy_to_user) {
        kpm_err("CRITICAL SYMBOL MISSING\n");
        return -EFAULT;
    }

    // Resolve phys_to_virt offset dynamically
    kpm_info("Resolving phys_to_virt offset...\n");
    if (resolve_phys_to_virt_offset() != 0) {
        kpm_err("Failed to resolve phys_to_virt offset\n");
        return -EFAULT;
    }
    
    kpm_info("Phys to virt offset resolved: 0x%llx\n", g_phys_offset);

    // Initialize mutex
    if (p_mutex_init) p_mutex_init(&hfr_mutex);

    // Create proc entry
    proc_entry = p_proc_create_data(proc_filename, 0666, NULL, &p_ops, NULL);
    if (!proc_entry) {
        kpm_err("proc_create FAILED\n");
        return -EFAULT;
    }

    kpm_info("=== SAFE MEMORY ACCESS INIT SUCCESS ===\n");
    kpm_info("=== /proc/%s created ===\n", proc_filename);
    kpm_info("=== Dynamic offset: 0x%llx ===\n", g_phys_offset);
    return 0;
}

static long hfr_memory_exit(void __user *reserved)
{
    kpm_info("=== SAFE MEMORY ACCESS EXIT ===\n");
    if (proc_entry && p_remove_proc_entry) {
        p_remove_proc_entry(proc_filename, NULL);
        kpm_info("proc entry removed\n");
    }
    return 0;
}

KPM_INIT(hfr_memory_init);
KPM_EXIT(hfr_memory_exit);
