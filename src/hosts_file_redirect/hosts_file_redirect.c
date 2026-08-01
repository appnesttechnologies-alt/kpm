#include <compiler.h>
#include <kpmodule.h>
#include <linux/printk.h>
#include <common.h>
#include <syscall.h>


#define ENABLE_DEBUG_LOG 0  // Production me 0 rakho

#if ENABLE_DEBUG_LOG
    #define TAG "[FCK]"
    #define logv(fmt, ...) pr_info(TAG fmt, ##__VA_ARGS__)
#else
    #define logv(fmt, ...) do {} while(0) 
#endif


KPM_NAME("FCK");
KPM_VERSION("1.0.0");
KPM_LICENSE("GPL v2");
KPM_AUTHOR("FKC");
KPM_DESCRIPTION("FCK");


// ===== OPCODES =====
#define OP_READ_MEM                 8001
#define OP_WRITE_MEM                8002
#define OP_BULK_READ_MEM            8020
#define OP_BULK_WRITE_MEM           8021
#define OP_GET_CPU_NUM_BRPS         8009
#define OP_GET_CPU_NUM_WRPS         8010
#define OP_SET_HW_BREAKPOINT        8011
#define OP_REMOVE_HW_BREAKPOINT     8013
#define OP_REMOVE_ALL_HW_BREAKPOINT 8014

// ===== STRUCTURES =====
typedef struct {
    uint32_t pid;
    uint32_t _pad0;
    uint64_t addr;
    uint64_t buffer;
    uint64_t size;
} copy_memory_t;

typedef struct {
    uint64_t addr;
    uint64_t buffer;
    uint64_t size;
} bulk_mem_item_t;

typedef struct {
    uint32_t pid;
    uint32_t count;
    uint64_t items;  // Pointer to array of bulk_mem_item_t
} bulk_mem_cmd_t;

typedef struct {
    uint32_t pid;
    uint32_t _pad0;
    uint64_t addr;
    int32_t  type;
    int32_t  _pad1;
    uint64_t len;
} hw_breakpoint_cmd_t;

struct bp_node {
    struct bp_node *next;
    struct bp_node *prev;
    uint64_t perf_event;
    uint32_t pid;
    uint32_t pad;
    uint64_t addr;
};

// ===== GLOBALS =====
static uint64_t my_page_shift = 12;
static uint64_t my_va_bits = 48;
static uint64_t my_pa_bits = 48;

static struct bp_node bp_list = {
    .next = &bp_list,
    .prev = &bp_list,
};
static uint32_t bp_lock = 0;

static uint64_t kv_memstart_addr = 0;
static uint64_t kv_kimage_voffset = 0;
static uint64_t pgd_offset = 0;

// ===== KERNEL FUNCTION POINTERS =====
static uint64_t (*kf___arch_copy_from_user)(void *to, const void __user *from, uint64_t n) = 0;
static uint64_t (*kf___arch_copy_to_user)(void __user *to, const void *from, uint64_t n) = 0;
static void *(*kf_get_task_pid)(void *task, int type) = 0;
static void (*kf_put_pid)(void *pid) = 0;
static void *(*kf_find_task_by_vpid)(uint32_t pid) = 0;
static volatile uint64_t kf_attach_pid = 0;
static void *(*kf_get_task_mm)(void *task) = 0;
static void (*kf_mmput)(void *mm) = 0;
static int (*kf_pfn_valid)(uint64_t pfn) = 0;
static int (*kf_valid_phys_addr_range)(uint64_t addr, uint64_t size) = 0;
static void *(*kf_register_user_hw_breakpoint)(void *attr, void *handler, void *overflow, void *task) = 0;
static volatile uint64_t kf_modify_user_hw_breakpoint = 0;
static void (*kf_unregister_hw_breakpoint)(void *event) = 0;
static void (*kf_perf_event_enable)(void *event) = 0;
static void *(*kf_memset)(void *s, int c, uint64_t n) = 0;
static void *(*kf___kmalloc)(uint64_t size, uint32_t flags) = 0;
static void *(*kf_kmalloc)(uint64_t size, uint32_t flags) = 0;
static void (*kf_kfree)(void *ptr) = 0;
static void (*kf__raw_spin_lock)(void *lock) = 0;
static void (*kf__raw_spin_unlock)(void *lock) = 0;

static const uint64_t pa_bits_table[] = { 32, 36, 40, 42, 44, 48, 52 };

#define LIST_POISON1  0xDEAD000000000100ULL
#define LIST_POISON2  0xDEAD000000000122ULL

// ===== HELPER FUNCTIONS =====
static inline void bp_list_add(struct bp_node *node, struct bp_node *head)
{
    struct bp_node *old_next = head->next;
    head->next = node;
    node->next = (struct bp_node *)head;
    node->prev = old_next;
    old_next->next = node;
}

static inline void bp_list_del(struct bp_node *entry)
{
    struct bp_node *n = entry->next;
    struct bp_node *p = entry->prev;
    n->prev = p;
    p->next = n;
    entry->next = (struct bp_node *)LIST_POISON1;
    entry->prev = (struct bp_node *)LIST_POISON2;
}

static void hw_breakpoint_handler(void *event, void *data)
{
    logv("hw_breakpoint: Breakpoint hit\n");
}

// ===== PAGE TABLE WALK =====
static int walk_page_table(void *mm, uint64_t vaddr, uint64_t *out_phys)
{
    uint64_t ps = my_page_shift;
    uint64_t vb = my_va_bits;
    uint64_t es = ps - 3;
    int64_t levels = (int64_t)((vb - 4) / es);
    
    if (levels < 1) return 0;
    
    int64_t level = 4 - levels;
    uint64_t tbl = *(uint64_t *)((uint64_t)mm + pgd_offset);
    uint64_t pmask = ~(-1ULL << (48 - (uint8_t)ps)) << ps;
    uint64_t imask = (1U << es) - 1;
    int found = 0;
    
    while (!found && level < 4) {
        uint64_t shift = (4 - (uint8_t)level) * es + 3;
        uint64_t idx = (vaddr >> shift) & imask;
        uint64_t entry = *(uint64_t *)(tbl + idx * 8);
        uint64_t dt = entry & 3;
        
        if (dt == 3) {
            tbl = (pmask & entry) + (-1ULL << vb) - *(uint64_t *)kv_memstart_addr;
            level++;
            if (level >= 3) { found = 1; break; }
        } else if (dt == 1) {
            found = 1; break;
        } else {
            return 0;
        }
    }
    
    if (found) {
        uint64_t shift = (4 - (uint8_t)level) * es + 3;
        uint64_t idx = (vaddr >> shift) & imask;
        uint64_t entry = *(uint64_t *)(tbl + idx * 8);
        if ((~(uint16_t)entry & 0x401) == 0) {
            uint64_t pa_frame = 0;
            if (my_pa_bits == 52)
                pa_frame = (entry << 36) & 0xF000000000000ULL;
            *out_phys = (pa_frame + (entry & pmask)) & (-1ULL << ps);
            *out_phys |= vaddr & ~(-1ULL << ps);
            return 1;
        }
    }
    return 0;
}

// ===== SINGLE READ/WRITE =====
static void do_single_rw(uint32_t pid, uint64_t vaddr, uint64_t buf, uint64_t size, int is_write)
{
    uint64_t remaining = size;
    uint64_t curr_vaddr = vaddr;
    uint64_t curr_buf = buf;
    
    void *task = kf_find_task_by_vpid(pid);
    if (!task) return;
    
    void *mm = kf_get_task_mm(task);
    if (!mm) return;
    
    while (remaining) {
        uint64_t pgsz = 1ULL << my_page_shift;
        uint64_t pgoff = curr_vaddr & (pgsz - 1);
        uint64_t chunk = pgsz - pgoff;
        if (chunk > remaining) chunk = remaining;
        
        uint64_t phys_addr = 0;
        if (walk_page_table(mm, curr_vaddr, &phys_addr) && phys_addr) {
            if (kf_pfn_valid(phys_addr >> my_page_shift) &&
                kf_valid_phys_addr_range(phys_addr, chunk)) {
                uint64_t kva = (phys_addr & (-1ULL << my_page_shift))
                             - *(uint64_t *)kv_memstart_addr
                             + (-1ULL << my_va_bits)
                             + (phys_addr & ~(-1ULL << my_page_shift));
                
                if (is_write) {
                    uint8_t *tmp = (uint8_t *)kf_kmalloc(chunk, 0xD0);
                    if (tmp) {
                        if (!kf___arch_copy_from_user(tmp, (void __user *)curr_buf, chunk)) {
                            for (uint64_t i = 0; i < chunk; i++)
                                *(volatile uint8_t *)(kva + i) = tmp[i];
                        }
                        kf_kfree(tmp);
                    }
                } else {
                    kf___arch_copy_to_user((void __user *)curr_buf, (void *)kva, chunk);
                }
            }
        }
        
        remaining -= chunk;
        curr_vaddr += chunk;
        curr_buf += chunk;
    }
    
    kf_mmput(mm);
}

// ===== BULK READ =====
static void do_bulk_read(uint32_t pid, uint32_t count, bulk_mem_item_t __user *items)
{
    if (!count || count > 512) return;
    
    uint64_t alloc_size = count * sizeof(bulk_mem_item_t);
    bulk_mem_item_t *kitems = (bulk_mem_item_t *)kf_kmalloc(alloc_size, 0xD0);
    if (!kitems) return;
    
    if (kf___arch_copy_from_user(kitems, items, alloc_size)) {
        kf_kfree(kitems);
        return;
    }
    
    void *task = kf_find_task_by_vpid(pid);
    if (!task) {
        kf_kfree(kitems);
        return;
    }
    
    void *mm = kf_get_task_mm(task);
    if (!mm) {
        kf_kfree(kitems);
        return;
    }
    
    for (uint32_t i = 0; i < count; i++) {
        uint64_t vaddr = kitems[i].addr;
        uint64_t buf = kitems[i].buffer;
        uint64_t size = kitems[i].size;
        
        if (!size || size > 0x100000) continue;
        if (vaddr < 0x1000) continue;
        
        uint64_t remaining = size;
        uint64_t curr_vaddr = vaddr;
        uint64_t curr_buf = buf;
        
        while (remaining) {
            uint64_t pgsz = 1ULL << my_page_shift;
            uint64_t pgoff = curr_vaddr & (pgsz - 1);
            uint64_t chunk = pgsz - pgoff;
            if (chunk > remaining) chunk = remaining;
            
            uint64_t phys_addr = 0;
            if (walk_page_table(mm, curr_vaddr, &phys_addr) && phys_addr) {
                if (kf_pfn_valid(phys_addr >> my_page_shift) &&
                    kf_valid_phys_addr_range(phys_addr, chunk)) {
                    uint64_t kva = (phys_addr & (-1ULL << my_page_shift))
                                 - *(uint64_t *)kv_memstart_addr
                                 + (-1ULL << my_va_bits)
                                 + (phys_addr & ~(-1ULL << my_page_shift));
                    
                    kf___arch_copy_to_user((void __user *)curr_buf, (void *)kva, chunk);
                }
            }
            
            remaining -= chunk;
            curr_vaddr += chunk;
            curr_buf += chunk;
        }
    }
    
    kf_mmput(mm);
    kf_kfree(kitems);
}

// ===== BULK WRITE =====
static void do_bulk_write(uint32_t pid, uint32_t count, bulk_mem_item_t __user *items)
{
    if (!count || count > 512) return;
    
    uint64_t alloc_size = count * sizeof(bulk_mem_item_t);
    bulk_mem_item_t *kitems = (bulk_mem_item_t *)kf_kmalloc(alloc_size, 0xD0);
    if (!kitems) return;
    
    if (kf___arch_copy_from_user(kitems, items, alloc_size)) {
        kf_kfree(kitems);
        return;
    }
    
    void *task = kf_find_task_by_vpid(pid);
    if (!task) {
        kf_kfree(kitems);
        return;
    }
    
    void *mm = kf_get_task_mm(task);
    if (!mm) {
        kf_kfree(kitems);
        return;
    }
    
    for (uint32_t i = 0; i < count; i++) {
        uint64_t vaddr = kitems[i].addr;
        uint64_t buf = kitems[i].buffer;
        uint64_t size = kitems[i].size;
        
        if (!size || size > 0x100000) continue;
        if (vaddr < 0x1000) continue;
        
        uint8_t *tmp = (uint8_t *)kf_kmalloc(size, 0xD0);
        if (!tmp) continue;
        
        if (kf___arch_copy_from_user(tmp, (void __user *)buf, size)) {
            kf_kfree(tmp);
            continue;
        }
        
        uint64_t remaining = size;
        uint64_t curr_vaddr = vaddr;
        uint64_t curr_off = 0;
        
        while (remaining) {
            uint64_t pgsz = 1ULL << my_page_shift;
            uint64_t pgoff = curr_vaddr & (pgsz - 1);
            uint64_t chunk = pgsz - pgoff;
            if (chunk > remaining) chunk = remaining;
            
            uint64_t phys_addr = 0;
            if (walk_page_table(mm, curr_vaddr, &phys_addr) && phys_addr) {
                if (kf_pfn_valid(phys_addr >> my_page_shift) &&
                    kf_valid_phys_addr_range(phys_addr, chunk)) {
                    uint64_t kva = (phys_addr & (-1ULL << my_page_shift))
                                 - *(uint64_t *)kv_memstart_addr
                                 + (-1ULL << my_va_bits)
                                 + (phys_addr & ~(-1ULL << my_page_shift));
                    
                    for (uint64_t j = 0; j < chunk; j++)
                        *(volatile uint8_t *)(kva + j) = tmp[curr_off + j];
                }
            }
            
            remaining -= chunk;
            curr_vaddr += chunk;
            curr_off += chunk;
        }
        
        kf_kfree(tmp);
    }
    
    kf_mmput(mm);
    kf_kfree(kitems);
}

// ===== IOCTL HANDLER =====
static void before_ioctl(hook_fargs4_t *args, void *udata)
{
    uint64_t *regs = syscall_args(args);
    int64_t cmd = (int64_t)regs[1];
    uint64_t user_data = regs[2];

    // BULK READ
    if (cmd == OP_BULK_READ_MEM) {
        bulk_mem_cmd_t bcmd;
        if (kf___arch_copy_from_user(&bcmd, (void __user *)user_data, sizeof(bcmd)))
            return;
        do_bulk_read(bcmd.pid, bcmd.count, (bulk_mem_item_t __user *)bcmd.items);
        return;
    }

    // BULK WRITE
    if (cmd == OP_BULK_WRITE_MEM) {
        bulk_mem_cmd_t bcmd;
        if (kf___arch_copy_from_user(&bcmd, (void __user *)user_data, sizeof(bcmd)))
            return;
        do_bulk_write(bcmd.pid, bcmd.count, (bulk_mem_item_t __user *)bcmd.items);
        return;
    }

    // SINGLE READ/WRITE
    if (cmd == OP_READ_MEM || cmd == OP_WRITE_MEM) {
        copy_memory_t rcmd;
        if (kf___arch_copy_from_user(&rcmd, (void __user *)user_data, sizeof(rcmd)))
            return;
        do_single_rw(rcmd.pid, rcmd.addr, rcmd.buffer, rcmd.size, (cmd == OP_WRITE_MEM));
        return;
    }

    // HW BREAKPOINTS
    if (cmd == OP_SET_HW_BREAKPOINT) {
        hw_breakpoint_cmd_t bcmd;
        if (kf___arch_copy_from_user(&bcmd, (void __user *)user_data, sizeof(bcmd)))
            return;

        void *task = kf_find_task_by_vpid(bcmd.pid);
        if (!task) return;

        char attr[136];
        if (kf_memset) kf_memset(attr, 0, sizeof(attr));

        *(uint32_t *)(attr + 0x00) = 5;
        if (kver >> 9 >= 0x285) {
            *(uint32_t *)(attr + 0x04) = 120;
            if (kver > 0x50EFF) {
                *(uint32_t *)(attr + 0x04) = (kver >> 8 > 0x600) ? 136 : 128;
            }
        }
        *(uint64_t *)(attr + 0x10) = 1;
        *(uint64_t *)(attr + 0x28) |= 0x24;
        *(uint32_t *)(attr + 0x34) = bcmd.type;
        *(uint64_t *)(attr + 0x38) = bcmd.addr;
        *(uint64_t *)(attr + 0x40) = bcmd.len;

        void *ev = kf_register_user_hw_breakpoint(attr, hw_breakpoint_handler, 0, task);
        if ((uint64_t)ev > 0xFFFFFFFFFFFFF000ULL) return;

        if (kf_perf_event_enable) kf_perf_event_enable(ev);

        void *(*alloc_fn)(uint64_t, uint32_t);
        alloc_fn = kf_kmalloc ? (void *)kf_kmalloc : (void *)kf___kmalloc;
        struct bp_node *node = (struct bp_node *)alloc_fn(sizeof(struct bp_node), 0xD0);
        if (!node) {
            if (kf_unregister_hw_breakpoint) kf_unregister_hw_breakpoint(ev);
            return;
        }

        node->pid = bcmd.pid;
        node->perf_event = (uint64_t)ev;
        node->addr = bcmd.addr;

        kf__raw_spin_lock(&bp_lock);
        bp_list_add(node, &bp_list);
        kf__raw_spin_unlock(&bp_lock);
        return;
    }

    if (cmd == OP_REMOVE_HW_BREAKPOINT) {
        hw_breakpoint_cmd_t bcmd;
        if (kf___arch_copy_from_user(&bcmd, (void __user *)user_data, sizeof(bcmd)))
            return;

        kf__raw_spin_lock(&bp_lock);
        struct bp_node *pos = bp_list.next;
        while ((void *)pos != (void *)&bp_list) {
            struct bp_node *n = pos->next;
            if (pos->pid == bcmd.pid && pos->addr == bcmd.addr) {
                bp_list_del(pos);
                if (kf_unregister_hw_breakpoint)
                    kf_unregister_hw_breakpoint((void *)pos->perf_event);
                kf_kfree(pos);
                break;
            }
            pos = n;
        }
        kf__raw_spin_unlock(&bp_lock);
        return;
    }

    if (cmd == OP_REMOVE_ALL_HW_BREAKPOINT) {
        kf__raw_spin_lock(&bp_lock);
        struct bp_node *pos = bp_list.next;
        while ((void *)pos != (void *)&bp_list) {
            struct bp_node *n = pos->next;
            bp_list_del(pos);
            if (kf_unregister_hw_breakpoint)
                kf_unregister_hw_breakpoint((void *)pos->perf_event);
            kf_kfree(pos);
            pos = n;
        }
        kf__raw_spin_unlock(&bp_lock);
        return;
    }
}

// ===== INIT =====
static long hello_demo_init(const char *args, const char *event, void *__user reserved)
{
    kv_memstart_addr = (uint64_t)kallsyms_lookup_name("memstart_addr");
    kv_kimage_voffset = (uint64_t)kallsyms_lookup_name("kimage_voffset");
    kf___arch_copy_from_user = (typeof(kf___arch_copy_from_user))kallsyms_lookup_name("__arch_copy_from_user");
    kf___arch_copy_to_user = (typeof(kf___arch_copy_to_user))kallsyms_lookup_name("__arch_copy_to_user");
    kf_get_task_pid = (typeof(kf_get_task_pid))kallsyms_lookup_name("get_task_pid");
    kf_put_pid = (typeof(kf_put_pid))kallsyms_lookup_name("put_pid");
    kf_find_task_by_vpid = (typeof(kf_find_task_by_vpid))kallsyms_lookup_name("find_task_by_vpid");
    kf_attach_pid = (uint64_t)kallsyms_lookup_name("attach_pid");
    kf_get_task_mm = (typeof(kf_get_task_mm))kallsyms_lookup_name("get_task_mm");
    kf_mmput = (typeof(kf_mmput))kallsyms_lookup_name("mmput");
    kf_pfn_valid = (typeof(kf_pfn_valid))kallsyms_lookup_name("pfn_valid");
    kf_valid_phys_addr_range = (typeof(kf_valid_phys_addr_range))kallsyms_lookup_name("valid_phys_addr_range");
    kf_register_user_hw_breakpoint = (typeof(kf_register_user_hw_breakpoint))kallsyms_lookup_name("register_user_hw_breakpoint");
    kf_modify_user_hw_breakpoint = (uint64_t)kallsyms_lookup_name("modify_user_hw_breakpoint");
    kf_unregister_hw_breakpoint = (typeof(kf_unregister_hw_breakpoint))kallsyms_lookup_name("unregister_hw_breakpoint");
    kf_perf_event_enable = (typeof(kf_perf_event_enable))kallsyms_lookup_name("perf_event_enable");
    kf_memset = (typeof(kf_memset))kallsyms_lookup_name("memset");
    kf___kmalloc = (typeof(kf___kmalloc))kallsyms_lookup_name("__kmalloc");
    kf_kmalloc = (typeof(kf_kmalloc))kallsyms_lookup_name("kmalloc");
    kf_kfree = (typeof(kf_kfree))kallsyms_lookup_name("kfree");
    kf__raw_spin_lock = (typeof(kf__raw_spin_lock))kallsyms_lookup_name("_raw_spin_lock");
    kf__raw_spin_unlock = (typeof(kf__raw_spin_unlock))kallsyms_lookup_name("_raw_spin_unlock");

    uint64_t tcr_el1;
    __asm__ volatile("mrs %0, tcr_el1" : "=r"(tcr_el1));
    uint64_t tg1 = (tcr_el1 >> 30) & 0x3;
    my_va_bits = 64 - ((tcr_el1 >> 16) & 0x1F);
    if (tg1 == 1) my_page_shift = 14;
    else if (tg1 == 3) my_page_shift = 16;
    else my_page_shift = 12;

    uint64_t mmfr0;
    __asm__ volatile("mrs %0, id_aa64mmfr0_el1" : "=r"(mmfr0));
    uint64_t parange = mmfr0 & 0xF;
    my_pa_bits = (parange > 6) ? 48 : pa_bits_table[parange];

    uint64_t ttbr1;
    __asm__ volatile("mrs %0, ttbr1_el1" : "=r"(ttbr1));

    uint64_t init_mm_addr = (uint64_t)kallsyms_lookup_name("init_mm");
    if (init_mm_addr && init_mm_addr <= 0xFFFFFFFFFFFFFF4FULL) {
        uint64_t expected_pgd = *(uint64_t *)kv_kimage_voffset
                              + (ttbr1 & (-1ULL << my_page_shift) & 0xFFFFFFFFFFFEULL);
        for (uint64_t off = 0; off < 176; off += 4) {
            if (*(uint64_t *)(init_mm_addr + off) == expected_pgd) {
                pgd_offset = off;
                break;
            }
        }
    }

    return (long)fp_hook_syscalln(29, 3, before_ioctl, NULL, NULL);
}

static long hello_demo_control0(const char *ctl_args, char *__user out_msg, int outlen)
{
    logv("FCK KPM Loaded with Bulk R/W Support\n");
    return 0;
}

static long hello_demo_exit(void *__user reserved)
{
    fp_unhook_syscall(29, 0, before_ioctl);

    kf__raw_spin_lock(&bp_lock);
    struct bp_node *pos = bp_list.next;
    while ((void *)pos != (void *)&bp_list) {
        struct bp_node *next_node = pos->next;
        bp_list_del(pos);
        if (kf_unregister_hw_breakpoint)
            kf_unregister_hw_breakpoint((void *)pos->perf_event);
        kf_kfree(pos);
        pos = next_node;
    }
    kf__raw_spin_unlock(&bp_lock);

    logv("FCK KPM Unloaded\n");
    return 0;
}

KPM_INIT(hello_demo_init);
KPM_CTL0(hello_demo_control0);
KPM_EXIT(hello_demo_exit);
