#include <compiler.h>
#include <kpmodule.h>
#include <linux/printk.h>
#include <common.h>
#include <syscall.h>

#define ENABLE_DEBUG_LOG 1

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

#define OP_READ_MEM                 8001
#define OP_WRITE_MEM                8002
#define OP_GET_CPU_NUM_BRPS         8009
#define OP_GET_CPU_NUM_WRPS         8010
#define OP_SET_HW_BREAKPOINT        8011
#define OP_REMOVE_HW_BREAKPOINT     8013
#define OP_REMOVE_ALL_HW_BREAKPOINT 8014
#define OP_GET_MODULE_BASE          8015   // ADDED

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

typedef struct {                             // ADDED
    uint32_t pid;
    uint32_t _pad0;
    uint64_t name;      // user ptr to lib name
    uint64_t name_len;  // includes ''
    uint64_t base;      // user ptr to uint64_t out
} module_base_cmd_t;

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
/* DO NOT redeclare kf_kfree or kf_d_path if provided by kfunc_def(...) in your tree */
static void (*kf__raw_spin_lock)(void *lock) = 0;
static void (*kf__raw_spin_unlock)(void *lock) = 0;

/* ADDED: only extra deps via kallsyms */
static void (*kf_mmap_read_lock)(void *mm) = 0;
static void (*kf_mmap_read_unlock)(void *mm) = 0;
static void *(*kf_find_vma)(void *mm, uint64_t addr) = 0;
static long (*kf_strnlen_user)(const char __user *str, long count) = 0;

static const uint64_t pa_bits_table[] = { 32, 36, 40, 42, 44, 48, 52 };

#define LIST_POISON1  0xDEAD000000000100ULL
#define LIST_POISON2  0xDEAD000000000122ULL

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

uint64_t *pgtable_entry(uint64_t table_base, uint64_t va)
{
    uint64_t ps = my_page_shift;
    uint64_t vb = my_va_bits;
    uint64_t es = ps - 3;
    int64_t levels = (int64_t)((vb - 4) / es);
    uint64_t *result;

    if (levels < 1)
        return 0;

    {
        int64_t level = 4 - levels;
        uint64_t pmask = ~(-1ULL << (48 - (uint8_t)ps)) << ps;
        uint64_t imask = (1U << es) - 1;

        while (1) {
            uint64_t shift = (4 - (uint8_t)level) * es + 3;
            uint64_t idx = (va >> shift) & imask;
            result = (uint64_t *)(table_base + idx * 8);
            {
                uint64_t entry = *result;
                uint64_t dt = entry & 3;

                if (dt == 3) {
                    table_base = (pmask & entry) + (-1ULL << vb) - *(uint64_t *)kv_memstart_addr;
                    level++;
                    if (level >= 3)
                        return result;
                } else if (dt == 1) {
                    if (level == 0) {
                        pmask = ~(-1ULL << (48 - ((uint8_t)ps + 3 * es))) << ((uint8_t)ps + 3 * es);
                        table_base = (pmask & entry) + (-1ULL << vb) - *(uint64_t *)kv_memstart_addr;
                        level++;
                        if (level >= 3)
                            return result;
                        continue;
                    }
                    return result;
                } else {
                    return 0;
                }
            }
        }
    }
}

/* ========================= ADDED: module base helpers ========================= */

static uint64_t my_strlen(const char *s)
{
    uint64_t n = 0;
    while (s && s[n])
        n++;
    return n;
}

static int my_strcmp(const char *a, const char *b)
{
    while (*a && *b) {
        if (*a != *b)
            return (unsigned char)*a - (unsigned char)*b;
        a++;
        b++;
    }
    return (unsigned char)*a - (unsigned char)*b;
}

static int my_strncmp(const char *a, const char *b, uint64_t n)
{
    while (n && *a && *b) {
        if (*a != *b)
            return (unsigned char)*a - (unsigned char)*b;
        a++;
        b++;
        n--;
    }
    if (!n)
        return 0;
    return (unsigned char)*a - (unsigned char)*b;
}

static int my_strstr(const char *hay, const char *needle)
{
    uint64_t nlen;

    if (!hay || !needle)
        return 0;

    nlen = my_strlen(needle);
    if (!nlen)
        return 1;

    while (*hay) {
        if (!my_strncmp(hay, needle, nlen))
            return 1;
        hay++;
    }
    return 0;
}

static const char *my_basename(const char *path)
{
    const char *base = path;

    while (*path) {
        if (*path == '/')
            base = path + 1;
        path++;
    }
    return base;
}

static uint64_t find_module_base_by_name(uint32_t pid, const char *libname)
{
    void *task;
    void *mm;
    struct vm_area_struct *vma;
    uint64_t addr = 0;
    uint64_t best = 0;
    char *tmpbuf;

    if (!libname || !*libname)
        return 0;

    if (!kf_find_task_by_vpid || !kf_get_task_mm || !kf_mmput ||
        !kf_mmap_read_lock || !kf_mmap_read_unlock || !kf_find_vma)
        return 0;

    task = kf_find_task_by_vpid(pid);
    if (!task)
        return 0;

    mm = kf_get_task_mm(task);
    if (!mm)
        return 0;

    tmpbuf = kf_kmalloc ? (char *)kf_kmalloc(512, 0xD0)
                        : (char *)kf___kmalloc(512, 0xD0);
    if (!tmpbuf) {
        kf_mmput(mm);
        return 0;
    }

    kf_mmap_read_lock(mm);

    while (1) {
        struct file *file;
        char *path;
        const char *base;

        vma = (struct vm_area_struct *)kf_find_vma(mm, addr);
        if (!vma)
            break;

        if ((uint64_t)vma->vm_end <= addr)
            break;

        file = vma->vm_file;
        if (file) {
            path = kf_d_path(&file->f_path, tmpbuf, 512);
            if (path && (uint64_t)path < 0xFFFFFFFFFFFFF000ULL) {
                base = my_basename(path);

                if (!my_strcmp(base, libname) || my_strstr(path, libname)) {
                    if (!best || (uint64_t)vma->vm_start < best)
                        best = (uint64_t)vma->vm_start;
                }
            }
        }

        addr = (uint64_t)vma->vm_end;
        if (!addr)
            break;
    }

    kf_mmap_read_unlock(mm);
    kf_kfree(tmpbuf);
    kf_mmput(mm);

    return best;
}

/* ======================= END ADDED: module base helpers ====================== */

static void hw_breakpoint_handler(void *event, void *data)
{
    logv("hw_breakpoint: Breakpoint hit");
}

static void before_ioctl(hook_fargs4_t *args, void *udata);

static long hello_demo_init(const char *args, const char *event, void *__user reserved)
{
    uint64_t tcr_el1;
    uint64_t mmfr0;
    uint64_t ttbr1;
    uint64_t init_mm_addr;
    uint64_t init_task_addr;

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
    /* kf_kfree and kf_d_path should already exist via kfunc_def in your tree */
    kf__raw_spin_lock = (typeof(kf__raw_spin_lock))kallsyms_lookup_name("_raw_spin_lock");
    kf__raw_spin_unlock = (typeof(kf__raw_spin_unlock))kallsyms_lookup_name("_raw_spin_unlock");

    /* ADDED */
    kf_mmap_read_lock = (typeof(kf_mmap_read_lock))kallsyms_lookup_name("mmap_read_lock");
    kf_mmap_read_unlock = (typeof(kf_mmap_read_unlock))kallsyms_lookup_name("mmap_read_unlock");
    kf_find_vma = (typeof(kf_find_vma))kallsyms_lookup_name("find_vma");
    kf_strnlen_user = (typeof(kf_strnlen_user))kallsyms_lookup_name("strnlen_user");

    __asm__ volatile("mrs %0, tcr_el1" : "=r"(tcr_el1));
    {
        uint64_t tg1 = (tcr_el1 >> 30) & 0x3;
        my_va_bits = 64 - ((tcr_el1 >> 16) & 0x1F);
        if (tg1 == 1)
            my_page_shift = 14;
        else if (tg1 == 3)
            my_page_shift = 16;
        else
            my_page_shift = 12;
    }

    __asm__ volatile("mrs %0, id_aa64mmfr0_el1" : "=r"(mmfr0));
    {
        uint64_t parange = mmfr0 & 0xF;
        if (parange > 6)
            my_pa_bits = 48;
        else
            my_pa_bits = pa_bits_table[parange];
    }

    __asm__ volatile("mrs %0, ttbr1_el1" : "=r"(ttbr1));

    init_mm_addr = (uint64_t)kallsyms_lookup_name("init_mm");
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

    init_task_addr = (uint64_t)kallsyms_lookup_name("init_task");
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
    struct bp_node *pos;

    fp_unhook_syscall(29, 0, before_ioctl);

    kf__raw_spin_lock(&bp_lock);
    pos = bp_list.next;
    while ((void *)pos != (void *)&bp_list) {
        struct bp_node *next_node = pos->next;
        bp_list_del(pos);
        if (kf_unregister_hw_breakpoint)
            kf_unregister_hw_breakpoint((void *)pos->perf_event);
        kf_kfree(pos);
        pos = next_node;
    }
    kf__raw_spin_unlock(&bp_lock);

    logv("hello_demo_exit");
    return 0;
}

static void before_ioctl(hook_fargs4_t *args, void *udata)
{
    uint64_t *regs = syscall_args(args);
    int64_t cmd = (int64_t)regs[1];
    uint64_t user_data = regs[2];

    if ((uint64_t)(cmd - OP_READ_MEM) > (uint64_t)(OP_GET_MODULE_BASE - OP_READ_MEM))
        return;

    if (cmd == OP_READ_MEM || cmd == OP_WRITE_MEM) {
        copy_memory_t rcmd;
        if (kf___arch_copy_from_user(&rcmd, (void __user *)user_data, sizeof(rcmd)))
            return;

        {
            uint64_t remaining = rcmd.size;
            uint64_t vaddr = rcmd.addr;
            uint64_t outbuf = rcmd.buffer;

            if (!remaining)
                return;

            while (remaining) {
                uint64_t pgsz = 1ULL << my_page_shift;
                uint64_t pgoff = vaddr & (pgsz - 1);
                uint64_t chunk = pgsz - pgoff;
                void *task;
                void *mm;
                uint64_t ps;
                uint64_t vb;
                uint64_t es;
                int64_t levels;
                uint64_t phys_addr = 0;

                if (chunk > remaining)
                    chunk = remaining;

                task = kf_find_task_by_vpid(rcmd.pid);
                if (!task)
                    goto next_chunk;

                mm = kf_get_task_mm(task);
                if (!mm)
                    goto next_chunk;

                ps = my_page_shift;
                vb = my_va_bits;
                es = ps - 3;
                levels = (int64_t)((vb - 4) / es);

                if (levels >= 1) {
                    int64_t level = 4 - levels;
                    uint64_t tbl = *(uint64_t *)((uint64_t)mm + pgd_offset);
                    uint64_t pmask = ~(-1ULL << (48 - (uint8_t)ps)) << ps;
                    uint64_t imask = (1U << es) - 1;
                    int found = 0;

                    while (!found) {
                        uint64_t shift = (4 - (uint8_t)level) * es + 3;
                        uint64_t idx = (vaddr >> shift) & imask;
                        uint64_t entry = *(uint64_t *)(tbl + idx * 8);
                        uint64_t dt = entry & 3;

                        if (dt == 3) {
                            tbl = (pmask & entry) + (-1ULL << vb) - *(uint64_t *)kv_memstart_addr;
                            level++;
                            if (level >= 3) {
                                found = 1;
                                break;
                            }
                        } else if (dt == 1) {
                            if (level == 0) {
                                pmask = ~(-1ULL << (48 - ((uint8_t)ps + 3 * es))) << ((uint8_t)ps + 3 * es);
                                tbl = (pmask & entry) + (-1ULL << vb) - *(uint64_t *)kv_memstart_addr;
                                level++;
                                if (level >= 3) {
                                    found = 1;
                                    break;
                                }
                                continue;
                            }
                            found = 1;
                            break;
                        } else {
                            break;
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
                            phys_addr = (pa_frame + (entry & pmask)) & (-1ULL << ps);
                            phys_addr |= vaddr & ~(-1ULL << ps);
                        }
                    }
                }

                if (kf_mmput)
                    kf_mmput(mm);

                if (phys_addr) {
                    if (kf_pfn_valid(phys_addr >> my_page_shift) &&
                        kf_valid_phys_addr_range(phys_addr, chunk)) {
                        uint64_t kva = (phys_addr & (-1ULL << my_page_shift))
                                     - *(uint64_t *)kv_memstart_addr
                                     + (-1ULL << my_va_bits)
                                     + (phys_addr & ~(-1ULL << my_page_shift));

                        if (cmd == OP_READ_MEM) {
                            kf___arch_copy_to_user((void __user *)outbuf, (void *)kva, chunk);
                        } else {
                            uint8_t *tmp;
                            uint64_t not_copied;
                            uint64_t i;

                            tmp = kf_kmalloc ? (uint8_t *)kf_kmalloc(chunk, 0xD0)
                                             : (uint8_t *)kf___kmalloc(chunk, 0xD0);
                            if (!tmp)
                                goto next_chunk;

                            not_copied = kf___arch_copy_from_user(tmp, (void __user *)outbuf, chunk);
                            if (not_copied) {
                                kf_kfree(tmp);
                                goto next_chunk;
                            }

                            for (i = 0; i < chunk; i++)
                                *(volatile uint8_t *)(kva + i) = tmp[i];

                            kf_kfree(tmp);
                        }
                    }
                }

next_chunk:
                remaining -= chunk;
                vaddr += chunk;
                outbuf += chunk;
            }
        }
        return;
    }

    if (cmd == OP_GET_MODULE_BASE) {
        module_base_cmd_t mcmd;
        char *kname;
        uint64_t base = 0;
        long nlen;

        if (kf___arch_copy_from_user(&mcmd, (void __user *)user_data, sizeof(mcmd)))
            return;

        if (!mcmd.name || !mcmd.base || !mcmd.name_len || mcmd.name_len > 256)
            return;

        kname = kf_kmalloc ? (char *)kf_kmalloc(mcmd.name_len, 0xD0)
                           : (char *)kf___kmalloc(mcmd.name_len, 0xD0);
        if (!kname)
            return;

        if (kf_strnlen_user) {
            nlen = kf_strnlen_user((const char __user *)(uintptr_t)mcmd.name, mcmd.name_len);
            if (nlen <= 0 || nlen > (long)mcmd.name_len) {
                kf_kfree(kname);
                return;
            }
        }

        if (kf___arch_copy_from_user(kname, (void __user *)(uintptr_t)mcmd.name, mcmd.name_len)) {
            kf_kfree(kname);
            return;
        }

        kname[mcmd.name_len - 1] = '';

        base = find_module_base_by_name(mcmd.pid, kname);
        kf___arch_copy_to_user((void __user *)(uintptr_t)mcmd.base, &base, sizeof(base));

        kf_kfree(kname);
        return;
    }

    if (cmd == OP_GET_CPU_NUM_BRPS || cmd == OP_GET_CPU_NUM_WRPS) {
        uint64_t __attribute__((unused)) dfr0;
        __asm__ volatile("mrs %0, id_aa64dfr0_el1" : "=r"(dfr0));
        return;
    }

    if (cmd == OP_SET_HW_BREAKPOINT) {
        hw_breakpoint_cmd_t bcmd;
        void *task;
        char attr[136];
        void *ev;
        void *(*alloc_fn)(uint64_t, uint32_t);
        struct bp_node *node;

        if (kf___arch_copy_from_user(&bcmd, (void __user *)user_data, sizeof(bcmd)))
            return;

        task = kf_find_task_by_vpid(bcmd.pid);
        if (!task)
            return;

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

        ev = kf_register_user_hw_breakpoint(attr, hw_breakpoint_handler, 0, task);
        if ((uint64_t)ev > 0xFFFFFFFFFFFFF000ULL)
            return;

        if (kf_perf_event_enable)
            kf_perf_event_enable(ev);

        alloc_fn = kf_kmalloc ? (void *)kf_kmalloc : (void *)kf___kmalloc;
        node = (struct bp_node *)alloc_fn(sizeof(struct bp_node), 0xD0);
        if (!node) {
            if (kf_unregister_hw_breakpoint)
                kf_unregister_hw_breakpoint(ev);
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
        struct bp_node *pos;

        if (kf___arch_copy_from_user(&bcmd, (void __user *)user_data, sizeof(bcmd)))
            return;

        kf__raw_spin_lock(&bp_lock);
        pos = bp_list.next;
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
        struct bp_node *pos;

        kf__raw_spin_lock(&bp_lock);
        pos = bp_list.next;
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

KPM_INIT(hello_demo_init);
KPM_CTL0(hello_demo_control0);
KPM_EXIT(hello_demo_exit);
