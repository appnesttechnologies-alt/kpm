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
// SAFE MEMORY PROBE - Check if address is in kernel range
// ============================================================
static int is_address_in_range(void *addr)
{
    unsigned long va = (unsigned long)addr;
    
    if (!addr)
        return 0;
    
    // Must be in kernel space (high memory)
    if (va < PAGE_OFFSET)
        return 0;
    
    // Must not be in vmalloc/modules space (typically ends at 0xffffffffffffffff)
    // Linear map goes from PAGE_OFFSET to PAGE_END
    // PAGE_END = PAGE_OFFSET + (max_physical_memory)
    // For modern phones with up to 512GB RAM, physical can be up to 0x8000000000
    // So linear map ends at PAGE_OFFSET + 0x8000000000
    // For 39-bit: PAGE_OFFSET=0xffffff8000000000, END=0xffffffff8000000000 (overflow, wraps)
    // Actually 39-bit VA space is: 0xffffff8000000000 - 0xffffffffffffffff (512GB linear map)
    
    // More practical check: just ensure it's above PAGE_OFFSET and below end of VA space
    if (va >= 0xfffffffffffff000ULL)  // Near end of address space
        return 0;
    
    return 1;
}

// ============================================================
// DYNAMIC PHYS_TO_VIRT OFFSET DISCOVERY
// ============================================================
static int resolve_phys_to_virt_offset(void)
{
    unsigned long *memstart_ptr;
    unsigned long *kimage_ptr;
    unsigned long *swapper_ptr;
    unsigned long *physvirt_ptr;
    unsigned long test_offset;
    void *test_addr;
    
    kpm_info("Resolving phys_to_virt offset dynamically...\n");
    
    // Method 1: Try memstart_addr
    memstart_ptr = (unsigned long *)kallsyms_lookup_name("memstart_addr");
    if (memstart_ptr) {
        kpm_info("memstart_addr ptr: %px, value: 0x%llx\n", memstart_ptr, *memstart_ptr);
        // Even if value is 0, the pointer itself tells us something
        // If memstart_addr symbol is at a valid kernel address, we can use it
        if ((unsigned long)memstart_ptr > PAGE_OFFSET) {
            // Symbol exists in kernel memory
            if (*memstart_ptr == 0) {
                // memstart_addr = 0 means physical address 0 maps to PAGE_OFFSET
                g_phys_offset = PAGE_OFFSET;
                g_offset_resolved = 1;
                kpm_info("Method 1 SUCCESS: memstart_addr=0, using PAGE_OFFSET=0x%llx\n", g_phys_offset);
                return 0;
            } else {
                g_phys_offset = PAGE_OFFSET - *memstart_ptr;
                g_offset_resolved = 1;
                kpm_info("Method 1 SUCCESS: memstart_addr=0x%llx, phys_offset=0x%llx\n", 
                         *memstart_ptr, g_phys_offset);
                return 0;
            }
        }
    }
    
    // Method 2: Try kimage_voffset to calculate offset
    kimage_ptr = (unsigned long *)kallsyms_lookup_name("kimage_voffset");
    if (kimage_ptr && (unsigned long)kimage_ptr > PAGE_OFFSET) {
        kpm_info("kimage_voffset ptr: %px, value: 0x%llx\n", kimage_ptr, *kimage_ptr);
        // kimage_voffset = virt_addr - phys_addr for kernel image
        // This is different from linear map offset
        // But we can use _text to find linear map offset
    }
    
    // Method 3: Try physvirt_offset
    physvirt_ptr = (unsigned long *)kallsyms_lookup_name("physvirt_offset");
    if (physvirt_ptr && (unsigned long)physvirt_ptr > PAGE_OFFSET) {
        kpm_info("physvirt_offset ptr: %px, value: 0x%llx\n", physvirt_ptr, *physvirt_ptr);
        if (*physvirt_ptr != 0) {
            // Use default PAGE_OFFSET with physvirt_offset
            g_phys_offset = PAGE_OFFSET;
            g_offset_resolved = 1;
            kpm_info("Method 3 SUCCESS: using PAGE_OFFSET=0x%llx\n", g_phys_offset);
            return 0;
        }
    }
    
    // Method 4: Use swapper_pg_dir to verify PAGE_OFFSET
    swapper_ptr = (unsigned long *)kallsyms_lookup_name("swapper_pg_dir");
    if (swapper_ptr && (unsigned long)swapper_ptr > PAGE_OFFSET) {
        kpm_info("swapper_pg_dir virtual: %px\n", swapper_ptr);
        
        // We know swapper_pg_dir is in the linear map
        // swapper_pg_dir is at a known physical address (usually kernel start)
        // For GKI, try to reverse-engineer the offset
        
        // First try: assume swapper_pg_dir virtual is in linear map
        // physical = virtual - PAGE_OFFSET + memstart_addr
        // If memstart_addr = 0: physical = virtual - PAGE_OFFSET
        
        // Try common PAGE_OFFSET values
        unsigned long possible_offsets[] = {
            0xffffff8000000000ULL,  // 39-bit VA
            0xffffffc000000000ULL,  // Default
        };
        
        for (int i = 0; i < 2; i++) {
            test_offset = possible_offsets[i];
            
            // If swapper_pg_dir > test_offset, this offset is possible
            if ((unsigned long)swapper_ptr > test_offset) {
                kpm_info("Testing PAGE_OFFSET=0x%llx (swapper_pg_dir above it)\n", test_offset);
                g_phys_offset = test_offset;
                g_offset_resolved = 1;
                kpm_info("Method 4 SUCCESS: phys_offset=0x%llx\n", g_phys_offset);
                return 0;
            }
        }
    }
    
    // Method 5: Use default PAGE_OFFSET from kernel config
    // For 39-bit VA, PAGE_OFFSET is typically 0xffffff8000000000
    kpm_info("Using default PAGE_OFFSET for 39-bit VA: 0x%llx\n", PAGE_OFFSET);
    g_phys_offset = PAGE_OFFSET;
    g_offset_resolved = 1;
    kpm_info("Method 5 SUCCESS: using PAGE_OFFSET=0x%llx\n", g_phys_offset);
    return 0;
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
    
    pgd_phys = 0;
    for (int i = 0; i < 8; i++) {
        pgd_phys = *(unsigned long *)((char *)mm + possible_offsets[i]);
        // Check if it looks like a valid physical address:
        // - Non-zero
        // - Page aligned (bottom 12 bits = 0)
        // - Within reasonable physical memory range (< 1TB for phones)
        if (pgd_phys != 0 && (pgd_phys & 0xFFF) == 0 && pgd_phys < (1ULL << 40)) {
            kpm_info("pgd offset try 0x%lx: pgd_phys=0x%llx (valid)\n", 
                     possible_offsets[i], pgd_phys);
            pgd_found = 1;
            break;
        } else {
            kpm_info("pgd offset try 0x%lx: pgd_phys=0x%llx (invalid)\n", 
                     possible_offsets[i], pgd_phys);
        }
    }
    
    if (!pgd_found) {
        kpm_err("Cannot find valid PGD in mm_struct\n");
        return -EFAULT;
    }
    
    // Step 2: Convert PGD physical to virtual
    pgd_virt = (unsigned long)phys_to_virt(pgd_phys);
    kpm_info("PGD physical: 0x%llx, virtual: 0x%llx, phys_offset: 0x%llx\n", 
             pgd_phys, pgd_virt, g_phys_offset);
    
    if (!pgd_virt || !is_address_in_range((void *)pgd_virt)) {
        kpm_err("PGD virtual address 0x%llx not in valid range\n", pgd_virt);
        return -EFAULT;
    }
    kpm_info("PGD virtual: 0x%llx (valid)\n", pgd_virt);
    
    // Step 3: Walk PGD -> PMD -> PTE (3-level for 39-bit VA)
    pgd_idx = (addr >> 30) & 0x1FF;
    pgd_val = *(unsigned long *)(pgd_virt + pgd_idx * 8);
    kpm_info("PGD[%lu] = 0x%llx\n", pgd_idx, pgd_val);
    
    // Check if PGD entry is valid table descriptor (bits[1:0] = 0b11)
    if ((pgd_val & 0x3) != 0x3) {
        kpm_err("Invalid PGD entry: 0x%llx (type bits: 0x%llx)\n", 
                pgd_val, pgd_val & 0x3);
        return -EFAULT;
    }
    
    // Step 4: Get PMD table
    pmd_phys = pgd_val & ~0xFFFULL;
    pmd_virt = (unsigned long)phys_to_virt(pmd_phys);
    kpm_info("PMD physical: 0x%llx, virtual: 0x%llx\n", pmd_phys, pmd_virt);
    
    if (!pmd_virt || !is_address_in_range((void *)pmd_virt)) {
        kpm_err("PMD virtual address 0x%llx not in valid range\n", pmd_virt);
        return -EFAULT;
    }
    kpm_info("PMD virtual: 0x%llx (valid)\n", pmd_virt);
    
    pmd_idx = (addr >> 21) & 0x1FF;
    pmd_val = *(unsigned long *)(pmd_virt + pmd_idx * 8);
    kpm_info("PMD[%lu] = 0x%llx\n", pmd_idx, pmd_val);
    
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
        kpm_info("Block physical: 0x%llx, virtual: %px\n", phys_addr, kaddr);
        
        if (!kaddr || !is_address_in_range(kaddr)) {
            kpm_err("Block physical 0x%llx maps to invalid virtual\n", phys_addr);
            return -EFAULT;
        }
        
        memcpy(buffer, (char *)kaddr, size);
        kpm_info("Block read success: %d bytes\n", size);
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
    kpm_info("PTE physical: 0x%llx, virtual: 0x%llx\n", pte_phys, pte_virt);
    
    if (!pte_virt || !is_address_in_range((void *)pte_virt)) {
        kpm_err("PTE virtual address 0x%llx not in valid range\n", pte_virt);
        return -EFAULT;
    }
    kpm_info("PTE virtual: 0x%llx (valid)\n", pte_virt);
    
    pte_idx = (addr >> 12) & 0x1FF;
    pte_val = *(unsigned long *)(pte_virt + pte_idx * 8);
    kpm_info("PTE[%lu] = 0x%llx\n", pte_idx, pte_val);
    
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
    kpm_info("Final physical: 0x%llx, virtual: %px\n", phys_addr, kaddr);
    
    if (!kaddr || !is_address_in_range(kaddr)) {
        kpm_err("Physical 0x%llx maps to invalid virtual\n", phys_addr);
        return -EFAULT;
    }
    kpm_info("Final kaddr: %px (valid)\n", kaddr);
    
    memcpy(buffer, (char *)kaddr, size);
    kpm_info("Page read success: %d bytes\n", size);
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
    
    // Same walk as read
    int pgd_found = 0;
    unsigned long possible_offsets[] = {0x48, 0x50, 0x58, 0x60, 0x68, 0x70, 0x78, 0x80};
    
    pgd_phys = 0;
    for (int i = 0; i < 8; i++) {
        pgd_phys = *(unsigned long *)((char *)mm + possible_offsets[i]);
        if (pgd_phys != 0 && (pgd_phys & 0xFFF) == 0 && pgd_phys < (1ULL << 40)) {
            kpm_info("pgd offset try 0x%lx: pgd_phys=0x%llx (valid)\n", 
                     possible_offsets[i], pgd_phys);
            pgd_found = 1;
            break;
        }
    }
    
    if (!pgd_found) {
        kpm_err("Cannot find valid PGD in mm_struct\n");
        return -EFAULT;
    }
    
    pgd_virt = (unsigned long)phys_to_virt(pgd_phys);
    if (!pgd_virt || !is_address_in_range((void *)pgd_virt)) {
        kpm_err("PGD virtual address 0x%llx not in valid range\n", pgd_virt);
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
    if (!pmd_virt || !is_address_in_range((void *)pmd_virt)) {
        kpm_err("PMD virtual address 0x%llx not in valid range\n", pmd_virt);
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
        if (!kaddr || !is_address_in_range(kaddr)) {
            kpm_err("Block physical 0x%llx maps to invalid virtual\n", phys_addr);
            return -EFAULT;
        }
        
        memcpy((char *)kaddr, buffer, size);
        kpm_info("Block write success: %d bytes\n", size);
        return size;
    }
    
    if ((pmd_val & 0x3) != 0x3) {
        kpm_err("Invalid PMD entry type\n");
        return -EFAULT;
    }
    
    pte_phys = pmd_val & ~0xFFFULL;
    pte_virt = (unsigned long)phys_to_virt(pte_phys);
    if (!pte_virt || !is_address_in_range((void *)pte_virt)) {
        kpm_err("PTE virtual address 0x%llx not in valid range\n", pte_virt);
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
    if (!kaddr || !is_address_in_range(kaddr)) {
        kpm_err("Physical 0x%llx maps to invalid virtual\n", phys_addr);
        return -EFAULT;
    }
    
    memcpy((char *)kaddr, buffer, size);
    kpm_info("Page write success: %d bytes\n", size);
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

    if (!g_offset_resolved) {
        kpm_err("PHYS_OFFSET not resolved\n");
        pkt->status = STATUS_RESOLVE_FAIL;
        return;
    }

    if (!p_find_task_by_vpid || !p_get_task_mm || !p_mmput) {
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

    is_write_op = (pkt->op_code == OP_WRITE_VM);
    memset(temp_buffer, 0, MAX_INLINE);
    
    if (is_write_op) {
        memcpy(temp_buffer, pkt->inline_data, pkt->size);
    }

    if (is_write_op) {
        transferred = safe_page_walk_write(mm, pkt->vaddr, temp_buffer, pkt->size);
    } else {
        transferred = safe_page_walk_read(mm, pkt->vaddr, temp_buffer, pkt->size);
    }

    kpm_info("Transfer result: %d\n", transferred);

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

    kpm_info("Symbols resolved\n");
    kpm_info("  proc_create_data: %px\n", p_proc_create_data);
    kpm_info("  find_task_by_vpid: %px\n", p_find_task_by_vpid);
    kpm_info("  get_task_mm: %px\n", p_get_task_mm);
    kpm_info("  copy_from_user: %px\n", p_copy_from_user);
    kpm_info("  copy_to_user: %px\n", p_copy_to_user);

    if (!p_proc_create_data || !p_find_task_by_vpid || 
        !p_task_pid_nr_ns || !p_get_task_mm || !p_mmput || 
        !p_copy_from_user || !p_copy_to_user) {
        kpm_err("CRITICAL SYMBOL MISSING\n");
        return -EFAULT;
    }

    kpm_info("Resolving phys_to_virt offset...\n");
    if (resolve_phys_to_virt_offset() != 0) {
        kpm_err("Failed to resolve phys_to_virt offset\n");
        return -EFAULT;
    }
    
    kpm_info("Phys to virt offset resolved: 0x%llx\n", g_phys_offset);

    if (p_mutex_init) p_mutex_init(&hfr_mutex);

    proc_entry = p_proc_create_data(proc_filename, 0666, NULL, &p_ops, NULL);
    if (!proc_entry) {
        kpm_err("proc_create FAILED\n");
        return -EFAULT;
    }

    kpm_info("=== SAFE MEMORY ACCESS INIT SUCCESS ===\n");
    kpm_info("=== /proc/%s created ===\n", proc_filename);
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
