#include <compiler.h>
#include <kpmodule.h>
#include <linux/printk.h>
#include <common.h>
#include <syscall.h>

#define ENABLE_DEBUG_LOG 1

#if ENABLE_DEBUG_LOG
    #define TAG "FKR"
    #define logv(fmt, ...) pr_info(TAG fmt, ##__VA_ARGS__)
#else
    #define logv(fmt, ...) do {} while(0)
#endif

KPM_NAME("FKR");
KPM_VERSION("1.0.0");
KPM_LICENSE("GPL v2");
KPM_AUTHOR("FKR");
KPM_DESCRIPTION("FKR");

#define OP_READ_MEM                 8001
#define OP_WRITE_MEM                8002
#define OP_GET_CPU_NUM_BRPS         8009
#define OP_GET_CPU_NUM_WRPS         8010
#define OP_SET_HW_BREAKPOINT        8011
#define OP_REMOVE_HW_BREAKPOINT     8013
#define OP_REMOVE_ALL_HW_BREAKPOINT 8014

typedef struct {
    uint32_t pid;
    uint32_t _pad0;
    uint64_t addr;
    uint64_t buffer;
    uint64_t size;
} copy_memory_t;

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

static inline void bp_list_add(struct bp_node *node, struct bp_node *head)
{
    struct bp_node *old_next = head->next;
    node->next = old_next;
    node->prev = head;
    old_next->prev = node;
    head->next = node;
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

// Helper: get task_mm safely
static void *get_task_mm_safe(uint32_t pid)
{
    void *task = kf_find_task_by_vpid ? kf_find_task_by_vpid(pid) : NULL;
    if (!task)
        return NULL;
    void *mm = kf_get_task_mm ? kf_get_task_mm(task) : NULL;
    // task ref ko explicitly drop nahi kar rahe; exact behavior kernel/version pe depend
    return mm;
}

// Helper: VA -> PA for a given vaddr, using current mm/pgd
static uint64_t va_to_pa(uint64_t vaddr, void *mm)
{
    if (!mm)
        return 0;

    uint64_t ps = my_page_shift;
    uint64_t vb = my_va_bits;
    uint64_t es = ps - 3;
    int64_t levels = (int64_t)((vb - 4) / es);
    if (levels < 1)
        return 0;

    int64_t level = 4 - levels;
    uint64_t tbl = *(uint64_t *)((uint64_t)mm + pgd_offset);
    if (!tbl)
        return 0;

    uint64_t pmask = ~(-1ULL << (48 - (uint8_t)ps)) << ps;
    uint64_t imask = (1U << es) - 1;

    while (1) {
        uint64_t shift = (4 - (uint8_t)level) * es + 3;
        uint64_t idx = (vaddr >> shift) & imask;
        uint64_t entry = *(uint64_t *)(tbl + idx * 8);
        uint64_t dt = entry & 3;

        if (dt == 3) {
            tbl = (pmask & entry) + (-1ULL << vb) - *(uint64_t *)kv_memstart_addr;
            level++;
            if (level >= 3)
                return 0;
        } else if (dt == 1) {
            if (level == 0) {
                pmask = ~(-1ULL << (48 - ((uint8_t)ps + 3 * es))) << ((uint8_t)ps + 3 * es);
                tbl = (pmask & entry) + (-1ULL << vb) - *(uint64_t *)kv_memstart_addr;
                level++;
                if (level >= 3)
                    return 0;
                continue;
            }
            // valid PTE
            if ((~(uint16_t)entry & 0x401) != 0)
                return 0;

            uint64_t pa_frame = 0;
            if (my_pa_bits == 52)
                pa_frame = (entry << 36) & 0xF000000000000ULL;

            uint64_t phys = (pa_frame + (entry & pmask)) & (-1ULL << ps);
            phys |= vaddr & ~(-1ULL << ps);
            return phys;
        } else {
            return 0;
        }
    }
}

// Helper: translate VA chunk and copy TO userspace (read)
static int copy_phys_to_user(uint64_t phys, uint64_t size, void __user *outbuf)
{
    if (!kf_pfn_valid || !kf_valid_phys_addr_range)
        return -1;
    if (!kf_pfn_valid(phys >> my_page_shift))
        return -1;
    if (!kf_valid_phys_addr_range(phys, size))
        return -1;

    uint64_t kva = (phys & (-1ULL << my_page_shift))
                 - *(uint64_t *)kv_memstart_addr
                 + (-1ULL << my_va_bits)
                 + (phys & ~(-1ULL << my_page_shift));

    if (kf___arch_copy_to_user((void __user *)outbuf, (void *)kva, size))
        return -1;
    return 0;
}

// Helper: copy FROM userspace to temp buf
static int copy_from_user_to_buf(void __user *inbuf, void *buf, uint64_t size)
{
    if (!kf___arch_copy_from_user)
        return -1;
    if (kf___arch_copy_from_user(buf, (const void __user *)inbuf, size))
        return -1;
    return 0;
}

// Helper: write temp buf to phys
static int copy_buf_to_phys(void *buf, uint64_t size, uint64_t phys)
{
    if (!kf_pfn_valid || !kf_valid_phys_addr_range)
        return -1;
    if (!kf_pfn_valid(phys >> my_page_shift))
        return -1;
    if (!kf_valid_phys_addr_range(phys, size))
        return -1;

    uint64_t kva = (phys & (-1ULL << my_page_shift))
                 - *(uint64_t *)kv_memstart_addr
                 + (-1ULL << my_va_bits)
                 + (phys & ~(-1ULL << my_page_shift));

    for (uint64_t i = 0; i < size; i++)
        *(volatile uint8_t *)(kva + i) = ((uint8_t *)buf)[i];

    return 0;
}

static void hw_breakpoint_handler(void *event, void *data)
{
    logv("hw_breakpoint: Breakpoint hit");
}

static void before_ioctl(hook_fargs4_t *args, void *udata);

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
    if (tg1 == 1)
        my_page_shift = 14;
    else if (tg1 == 3)
        my_page_shift = 16;
    else
        my_page_shift = 12;

    uint64_t mmfr0;
    __asm__ volatile("mrs %0, id_aa64mmfr0_el1" : "=r"(mmfr0));
    uint64_t parange = mmfr0 & 0xF;
    if (parange > 6)
        my_pa_bits = 48;
    else
        my_pa_bits = pa_bits_table[parange];

    uint64_t ttbr1;
    __asm__ volatile("mrs %0, ttbr1_el1" : "=r"(ttbr1));

    uint64_t init_mm_addr = (uint64_t)kallsyms_lookup_name("init_mm");
    if (init_mm_addr && init_mm_addr <= 0xFFFFFFFFFFFFFF4FULL) {
        uint64_t expected_pgd = *(uint64_t *)kv_kimage_voffset
                              + (ttbr1 & (-1ULL << my_page_shift) & 0xFFFFFFFFFFFEULL);
        uint64_t off;
        for (off = 0; off < 176; off += 4) {
            if (*(uint64_t *)(init_mm_addr + off) == expected_pgd) {
                pgd_offset = off;
                break;
            }
        }
    }

    uint64_t init_task_addr = (uint64_t)kallsyms_lookup_name("init_task");
    if (init_task_addr) {
        if (kf_get_task_pid) {
            void *pid = kf_get_task_pid((void *)init_task_addr, 0);
            if (kf_put_pid)
                kf_put_pid(pid);
        } else {
            logv("kfunc: %s not found", "get_task_pid");
        }
    }

    return (long)fp_hook_syscalln(29, 3, before_ioctl, NULL, NULL);
}

static long hello_demo_control0(const char *ctl_args, char *__user out_msg, int outlen)
{
    logv("welcome to use my kpm");
    return 0;
}

static long hello_demo_exit(void *__user reserved)
{
    fp_unhook_syscall(29, 0, before_ioctl);

    if (kf__raw_spin_lock)
        kf__raw_spin_lock(&bp_lock);
    struct bp_node *pos = bp_list.next;
    while ((void *)pos != (void *)&bp_list) {
        struct bp_node *next_node = pos->next;
        bp_list_del(pos);
        if (kf_unregister_hw_breakpoint)
            kf_unregister_hw_breakpoint((void *)pos->perf_event);
        if (kf_kfree)
            kf_kfree(pos);
        pos = next_node;
    }
    if (kf__raw_spin_unlock)
        kf__raw_spin_unlock(&bp_lock);

    logv("hello_demo_exit");
    return 0;
}

static void before_ioctl(hook_fargs4_t *args, void *udata)
{
    uint64_t *regs = syscall_args(args);
    int64_t cmd = (int64_t)regs[1];
    uint64_t user_data = regs[2];

    if ((uint64_t)(cmd - OP_READ_MEM) > (uint64_t)(OP_REMOVE_ALL_HW_BREAKPOINT - OP_READ_MEM))
        return;

    if (cmd == OP_READ_MEM) {
        copy_memory_t rcmd;
        if (!kf___arch_copy_from_user)
            return;
        if (kf___arch_copy_from_user(&rcmd, (void __user *)user_data, sizeof(rcmd)))
            return;

        uint64_t remaining = rcmd.size;
        if (!remaining)
            return;

        uint64_t vaddr = rcmd.addr;
        uint64_t outbuf = rcmd.buffer;

        while (remaining) {
            uint64_t pgsz = 1ULL << my_page_shift;
            uint64_t pgoff = vaddr & (pgsz - 1);
            uint64_t chunk = pgsz - pgoff;
            if (chunk > remaining)
                chunk = remaining;

            void *mm = get_task_mm_safe(rcmd.pid);
            if (!mm)
                goto next_read;

            uint64_t phys = va_to_pa(vaddr, mm);
            if (kf_mmput)
                kf_mmput(mm);

            if (phys) {
                if (copy_phys_to_user(phys, chunk, (void __user *)outbuf) < 0) {
                    // partial fail; continue ya break as per your policy
                }
            }

        next_read:
            remaining -= chunk;
            vaddr += chunk;
            outbuf += chunk;
        }
        return;
    }

    if (cmd == OP_WRITE_MEM) {
        copy_memory_t wcmd;
        if (!kf___arch_copy_from_user)
            return;
        if (kf___arch_copy_from_user(&wcmd, (void __user *)user_data, sizeof(wcmd)))
            return;

        uint64_t remaining = wcmd.size;
        if (!remaining)
            return;

        uint64_t vaddr = wcmd.addr;
        uint64_t inbuf = wcmd.buffer;

        // small kmalloc buffer for safe user->kernel copy
        uint64_t buf_sz = 512;
        void *tmp = kf_kmalloc ? kf_kmalloc(buf_sz, 0xD0) : kf___kmalloc(buf_sz, 0xD0);
        if (!tmp)
            return;

        while (remaining) {
            uint64_t pgsz = 1ULL << my_page_shift;
            uint64_t pgoff = vaddr & (pgsz - 1);
            uint64_t chunk = pgsz - pgoff;
            if (chunk > remaining)
                chunk = remaining;

            void *mm = get_task_mm_safe(wcmd.pid);
            if (!mm)
                goto next_write;

            uint64_t phys = va_to_pa(vaddr, mm);
            if (kf_mmput)
                kf_mmput(mm);

            if (phys) {
                uint64_t left = chunk;
                uint64_t cur_in = inbuf;
                uint64_t cur_phys = phys;

                while (left) {
                    uint64_t n = left > buf_sz ? buf_sz : left;
                    if (copy_from_user_to_buf((void __user *)cur_in, tmp, n) < 0)
                        break;
                    if (copy_buf_to_phys(tmp, n, cur_phys) < 0)
                        break;
                    cur_in += n;
                    cur_phys += n;
                    left -= n;
                }
            }

        next_write:
            remaining -= chunk;
            vaddr += chunk;
            inbuf += chunk;
        }

        if (kf_kfree)
            kf_kfree(tmp);
        return;
    }

    if (cmd == OP_GET_CPU_NUM_BRPS || cmd == OP_GET_CPU_NUM_WRPS) {
        uint64_t dfr0 = 0;
        __asm__ volatile("mrs %0, id_aa64dfr0_el1" : "=r"(dfr0));
        uint64_t brps = ((dfr0 >> 24) & 0xF) + 1; // BRPs = DBGBRP + 1
        // userspace ko return karna hai to syscall return value set karo
        // example: regs[0] = brps; (agar tumhara hook framework allow karta ho)
        regs[0] = brps;
        return;
    }

    if (cmd == OP_SET_HW_BREAKPOINT) {
        hw_breakpoint_cmd_t bcmd;
        if (!kf___arch_copy_from_user)
            return;
        if (kf___arch_copy_from_user(&bcmd, (void __user *)user_data, sizeof(bcmd)))
            return;

        void *task = kf_find_task_by_vpid ? kf_find_task_by_vpid(bcmd.pid) : NULL;
        if (!task)
            return;

        char attr[136];
        if (kf_memset)
            kf_memset(attr, 0, sizeof(attr));

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

        void *ev = kf_register_user_hw_breakpoint
                   ? kf_register_user_hw_breakpoint(attr, hw_breakpoint_handler, 0, task)
                   : NULL;
        if ((uint64_t)ev > 0xFFFFFFFFFFFFF000ULL || !ev)
            return;

        if (kf_perf_event_enable)
            kf_perf_event_enable(ev);

        void *(*alloc_fn)(uint64_t, uint32_t) =
            kf_kmalloc ? (void *)kf_kmalloc : (void *)kf___kmalloc;
        struct bp_node *node = (struct bp_node *)alloc_fn(sizeof(struct bp_node), 0xD0);
        if (!node) {
            if (kf_unregister_hw_breakpoint)
                kf_unregister_hw_breakpoint(ev);
            return;
        }

        node->pid = bcmd.pid;
        node->perf_event = (uint64_t)ev;
        node->addr = bcmd.addr;

        if (kf__raw_spin_lock)
            kf__raw_spin_lock(&bp_lock);
        bp_list_add(node, &bp_list);
        if (kf__raw_spin_unlock)
            kf__raw_spin_unlock(&bp_lock);
        return;
    }

    if (cmd == OP_REMOVE_HW_BREAKPOINT) {
        hw_breakpoint_cmd_t bcmd;
        if (!kf___arch_copy_from_user)
            return;
        if (kf___arch_copy_from_user(&bcmd, (void __user *)user_data, sizeof(bcmd)))
            return;

        if (kf__raw_spin_lock)
            kf__raw_spin_lock(&bp_lock);
        struct bp_node *pos = bp_list.next;
        while ((void *)pos != (void *)&bp_list) {
            struct bp_node *n = pos->next;
            if (pos->pid == bcmd.pid && pos->addr == bcmd.addr) {
                bp_list_del(pos);
                if (kf_unregister_hw_breakpoint)
                    kf_unregister_hw_breakpoint((void *)pos->perf_event);
                if (kf_kfree)
                    kf_kfree(pos);
                break;
            }
            pos = n;
        }
        if (kf__raw_spin_unlock)
            kf__raw_spin_unlock(&bp_lock);
        return;
    }

    if (cmd == OP_REMOVE_ALL_HW_BREAKPOINT) {
        if (kf__raw_spin_lock)
            kf__raw_spin_lock(&bp_lock);
        struct bp_node *pos = bp_list.next;
        while ((void *)pos != (void *)&bp_list) {
            struct bp_node *n = pos->next;
            bp_list_del(pos);
            if (kf_unregister_hw_breakpoint)
                kf_unregister_hw_breakpoint((void *)pos->perf_event);
            if (kf_kfree)
                kf_kfree(pos);
            pos = n;
        }
        if (kf__raw_spin_unlock)
            kf__raw_spin_unlock(&bp_lock);
        return;
    }
}

KPM_INIT(hello_demo_init);
KPM_CTL0(hello_demo_control0);
KPM_EXIT(hello_demo_exit);
