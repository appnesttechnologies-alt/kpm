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
#define OP_FIND_LIB_BASE            8015

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

typedef struct {
    uint32_t pid;
    uint32_t _pad0;
    uint64_t lib_name_ptr;
    uint64_t out_base_addr;
} find_lib_cmd_t;

struct bp_node {
    struct bp_node *next;
    struct bp_node *prev;
    uint64_t perf_event;
    uint32_t pid;
    uint32_t pad;
    uint64_t addr;
};

static uint64_t my_page_shift = 12;
static uint64_t my_va_bits    = 48;
static uint64_t my_pa_bits    = 48;

static struct bp_node bp_list = {
    .next = &bp_list,
    .prev = &bp_list,
};
static uint32_t bp_lock = 0;

static uint64_t kv_memstart_addr  = 0;
static uint64_t kv_kimage_voffset = 0;
static uint64_t pgd_offset        = 0;

static uint64_t (*kf___arch_copy_from_user)(void *to, const void __user *from, uint64_t n) = 0;
static uint64_t (*kf___arch_copy_to_user)(void __user *to, const void *from, uint64_t n)   = 0;
static void *(*kf_get_task_pid)(void *task, int type)                                       = 0;
static void (*kf_put_pid)(void *pid)                                                        = 0;
static void *(*kf_find_task_by_vpid)(uint32_t pid)                                         = 0;
static volatile uint64_t kf_attach_pid                                                      = 0;
static void *(*kf_get_task_mm)(void *task)                                                  = 0;
static void (*kf_mmput)(void *mm)                                                           = 0;
static int (*kf_pfn_valid)(uint64_t pfn)                                                    = 0;
static int (*kf_valid_phys_addr_range)(uint64_t addr, uint64_t size)                        = 0;
static void *(*kf_register_user_hw_breakpoint)(void *attr, void *handler, void *overflow, void *task) = 0;
static volatile uint64_t kf_modify_user_hw_breakpoint                                       = 0;
static void (*kf_unregister_hw_breakpoint)(void *event)                                     = 0;
static void (*kf_perf_event_enable)(void *event)                                            = 0;
static void *(*kf_memset)(void *s, int c, uint64_t n)                                       = 0;
static void *(*kf___kmalloc)(uint64_t size, uint32_t flags)                                 = 0;
static void *(*kf_kmalloc)(uint64_t size, uint32_t flags)                                   = 0;
static void (*kf_kfree)(void *ptr)                                                          = 0;
static void (*kf__raw_spin_lock)(void *lock)                                                = 0;
static void (*kf__raw_spin_unlock)(void *lock)                                              = 0;

static void (*kf_down_read)(void *sem)                                                      = 0;
static void (*kf_up_read)(void *sem)                                                        = 0;
static char *(*kf_dentry_path_raw)(void *dentry, char *buf, int buflen)                     = 0;
static char *(*kf_strstr)(const char *haystack, const char *needle)                         = 0;
static int (*kf_strcmp)(const char *a, const char *b)                                       = 0;
static int (*kf_strncmp)(const char *a, const char *b, uint64_t n)                         = 0;
static uint64_t (*kf_strlen)(const char *s)                                                 = 0;
static char *(*kf_strrchr)(const char *s, int c)                                            = 0;
static void *(*kf_memcpy)(void *dst, const void *src, uint64_t n)                          = 0;

static const uint64_t pa_bits_table[] = { 32, 36, 40, 42, 44, 48, 52 };

#define LIST_POISON1  0xDEAD000000000100ULL
#define LIST_POISON2  0xDEAD000000000122ULL

static inline void bp_list_add(struct bp_node *node, struct bp_node *head)
{
    struct bp_node *old_next = head->next;
    head->next  = node;
    node->next  = (struct bp_node *)head;
    node->prev  = old_next;
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

#define FLB_PATH_BUF_SZ 512

/*
 * mmap_lock is the first member of struct rw_semaphore inside mm_struct.
 * Its offset is stable across all Android kernels (3.18 → 6.x): 0x68.
 * We discover it at init time exactly the same way pgd_offset is discovered,
 * so we never hard-code it.
 */
static uint64_t mmap_lock_offset = 0;
static uint64_t mm_mmap_offset   = 0;
static uint64_t vma_vm_next_offset  = 0;
static uint64_t vma_vm_start_offset = 0;
static uint64_t vma_vm_file_offset  = 0;
static uint64_t file_f_path_dentry_offset = 0;

#define FLB_KVA_MIN  0xFFFF000000000000ULL
#define FLB_SCAN_MAX 640U

static inline int flb_is_kptr(uint64_t v)
{
    return v > FLB_KVA_MIN && v != 0xFFFFFFFFFFFFFFFFULL;
}

static int flb_offsets_ready = 0;

static int flb_discover_offsets(void)
{
    if (flb_offsets_ready) return 1;

    void *task = kf_find_task_by_vpid(1);
    if (!task) {
        logv("flb_discover: find_task_by_vpid(1) returned NULL\n");
        return 0;
    }
    void *mm = kf_get_task_mm(task);
    if (!mm) {
        logv("flb_discover: get_task_mm returned NULL\n");
        return 0;
    }

    uint64_t mm64 = (uint64_t)mm;

    uint64_t found_mm_mmap      = 0;
    uint64_t found_vma_vm_start = 0;
    uint64_t found_vma_vm_end   = 0;
    uint64_t found_vma_vm_next  = 0;

    for (uint32_t mo = 0; mo + 8 <= FLB_SCAN_MAX; mo += 8) {
        if (mo == pgd_offset) continue;
        uint64_t vma0 = *(volatile uint64_t *)(mm64 + mo);
        if (!flb_is_kptr(vma0)) continue;

        for (uint32_t so = 0; so + 16 <= FLB_SCAN_MAX; so += 8) {
            uint64_t vs = *(volatile uint64_t *)(vma0 + so);
            uint64_t ve = *(volatile uint64_t *)(vma0 + so + 8);
            if (!vs || ve <= vs || (vs & 0xFFF) || (ve - vs) > 0x100000000ULL) continue;

            for (uint32_t no = so + 16; no + 8 <= FLB_SCAN_MAX; no += 8) {
                uint64_t vnext = *(volatile uint64_t *)(vma0 + no);
                if (!flb_is_kptr(vnext) && vnext != 0) continue;
                if (vnext && flb_is_kptr(vnext)) {
                    uint64_t vs2 = *(volatile uint64_t *)(vnext + so);
                    uint64_t ve2 = *(volatile uint64_t *)(vnext + so + 8);
                    if (!vs2 || ve2 <= vs2 || (vs2 & 0xFFF)) continue;
                }
                found_mm_mmap      = mo;
                found_vma_vm_start = so;
                found_vma_vm_end   = so + 8;
                found_vma_vm_next  = no;
                goto found_vma_fields;
            }
        }
    }

    kf_mmput(mm);
    logv("flb_discover: could not locate VMA fields\n");
    return 0;

found_vma_fields:;
    mm_mmap_offset      = found_mm_mmap;
    vma_vm_start_offset = found_vma_vm_start;
    vma_vm_next_offset  = found_vma_vm_next;

    uint64_t vma_cur = *(volatile uint64_t *)(mm64 + mm_mmap_offset);
    uint64_t found_vm_file   = FLB_SCAN_MAX;
    uint64_t found_f_path_de = FLB_SCAN_MAX;

    while (flb_is_kptr(vma_cur)) {
        for (uint32_t fo = 0; fo + 8 <= FLB_SCAN_MAX; fo += 8) {
            if (fo == found_vma_vm_start || fo == found_vma_vm_end || fo == found_vma_vm_next) continue;
            uint64_t fptr = *(volatile uint64_t *)(vma_cur + fo);
            if (!flb_is_kptr(fptr)) continue;

            for (uint32_t dp = 0; dp + 8 <= FLB_SCAN_MAX; dp += 8) {
                uint64_t mnt = *(volatile uint64_t *)(fptr + dp);
                if (!flb_is_kptr(mnt)) continue;
                uint64_t de  = *(volatile uint64_t *)(fptr + dp + 8);
                if (!flb_is_kptr(de)) continue;

                char tbuf[FLB_PATH_BUF_SZ];
                char *res = kf_dentry_path_raw((void *)de, tbuf, sizeof(tbuf));
                if (!res || (uint64_t)res < FLB_KVA_MIN) continue;

                int looks_like_path = 0;
                for (int ci = 0; ci < 512 && res[ci]; ci++) {
                    if (res[ci] == '/') { looks_like_path = 1; break; }
                }
                if (!looks_like_path) continue;

                found_vm_file   = fo;
                found_f_path_de = dp + 8;
                goto found_file_fields;
            }
        }
        vma_cur = *(volatile uint64_t *)(vma_cur + vma_vm_next_offset);
    }

    kf_mmput(mm);
    logv("flb_discover: could not locate vm_file / f_path fields\n");
    return 0;

found_file_fields:;
    vma_vm_file_offset        = found_vm_file;
    file_f_path_dentry_offset = found_f_path_de;

    for (uint32_t lo = 0; lo + 8 <= FLB_SCAN_MAX; lo += 8) {
        if (lo == pgd_offset || lo == mm_mmap_offset) continue;
        uint64_t candidate = *(volatile uint64_t *)(mm64 + lo);
        if (candidate != 0 && !flb_is_kptr(candidate)) {
            mmap_lock_offset = lo;
            break;
        }
    }

    kf_mmput(mm);

    logv("flb_discover: mm_mmap=%llu vma_vm_start=%llu vma_vm_next=%llu\n",
         (unsigned long long)mm_mmap_offset,
         (unsigned long long)vma_vm_start_offset,
         (unsigned long long)vma_vm_next_offset);
    logv("flb_discover: vma_vm_file=%llu f_path_dentry=%llu mmap_lock=%llu\n",
         (unsigned long long)vma_vm_file_offset,
         (unsigned long long)file_f_path_dentry_offset,
         (unsigned long long)mmap_lock_offset);

    flb_offsets_ready = 1;
    return 1;
}

static uint64_t find_lib_base(uint32_t pid, const char *lib_name)
{
    if (!lib_name || !lib_name[0]) {
        logv("find_lib_base: lib_name is empty\n");
        return 0;
    }

    if (!flb_discover_offsets()) {
        logv("find_lib_base: offset discovery failed\n");
        return 0;
    }

    void *task = kf_find_task_by_vpid(pid);
    if (!task) {
        logv("find_lib_base: find_task_by_vpid(%u) returned NULL\n", pid);
        return 0;
    }
    logv("find_lib_base: task found for pid=%u\n", pid);

    void *mm = kf_get_task_mm(task);
    if (!mm) {
        logv("find_lib_base: get_task_mm returned NULL\n");
        return 0;
    }
    logv("find_lib_base: mm found\n");

    void *mmap_lock = (void *)((uint64_t)mm + mmap_lock_offset);
    kf_down_read(mmap_lock);
    logv("find_lib_base: mmap locked\n");

    uint64_t result = 0;
    uint64_t vma    = *(volatile uint64_t *)((uint64_t)mm + mm_mmap_offset);

    while (vma) {
        logv("find_lib_base: visiting vma=0x%llx\n", (unsigned long long)vma);

        if (!flb_is_kptr(vma)) {
            logv("find_lib_base: vma pointer invalid, stopping\n");
            break;
        }

        uint64_t vm_file = *(volatile uint64_t *)(vma + vma_vm_file_offset);
        if (!vm_file || !flb_is_kptr(vm_file)) {
            logv("find_lib_base: vma->vm_file NULL, skip\n");
            goto next_vma;
        }

        uint64_t dentry = *(volatile uint64_t *)(vm_file + file_f_path_dentry_offset);
        if (!dentry || !flb_is_kptr(dentry)) {
            logv("find_lib_base: dentry NULL, skip\n");
            goto next_vma;
        }

        {
            char path_buf[FLB_PATH_BUF_SZ];
            char *path = kf_dentry_path_raw((void *)dentry, path_buf, sizeof(path_buf));
            if (!path || !flb_is_kptr((uint64_t)path)) {
                logv("find_lib_base: dentry_path_raw returned NULL\n");
                goto next_vma;
            }

            logv("find_lib_base: path=%s\n", path);

            if (kf_strstr(path, lib_name)) {
                uint64_t vm_start = *(volatile uint64_t *)(vma + vma_vm_start_offset);
                logv("find_lib_base: matched '%s' at vma_start=0x%llx\n",
                     lib_name, (unsigned long long)vm_start);
                result = vm_start;
                break;
            }
        }

    next_vma:
        vma = *(volatile uint64_t *)(vma + vma_vm_next_offset);
    }

    kf_up_read(mmap_lock);
    logv("find_lib_base: mmap unlocked\n");

    kf_mmput(mm);
    logv("find_lib_base: mmput done, returning 0x%llx\n", (unsigned long long)result);

    return result;
}

uint64_t *pgtable_entry(uint64_t table_base, uint64_t va)
{
    uint64_t ps     = my_page_shift;
    uint64_t vb     = my_va_bits;
    uint64_t es     = ps - 3;
    int64_t  levels = (int64_t)((vb - 4) / es);
    uint64_t *result;

    if (levels < 1) return 0;

    int64_t  level = 4 - levels;
    uint64_t pmask = ~(-1ULL << (48 - (uint8_t)ps)) << ps;
    uint64_t imask = (1U << es) - 1;

    while (1) {
        uint64_t shift = (4 - (uint8_t)level) * es + 3;
        uint64_t idx   = (va >> shift) & imask;
        result         = (uint64_t *)(table_base + idx * 8);
        uint64_t entry = *result;
        uint64_t dt    = entry & 3;

        if (dt == 3) {
            table_base = (pmask & entry) + (-1ULL << vb) - *(uint64_t *)kv_memstart_addr;
            level++;
            if (level >= 3) return result;
        } else if (dt == 1) {
            if (level == 0) {
                pmask = ~(-1ULL << (48 - ((uint8_t)ps + 3 * es))) << ((uint8_t)ps + 3 * es);
                table_base = (pmask & entry) + (-1ULL << vb) - *(uint64_t *)kv_memstart_addr;
                level++;
                if (level >= 3) return result;
                continue;
            }
            return result;
        } else {
            return 0;
        }
    }
}

static void hw_breakpoint_handler(void *event, void *data)
{
    logv("hw_breakpoint: Breakpoint hit\n");
}

static void before_ioctl(hook_fargs4_t *args, void *udata);

#define RESOLVE(name) \
    do { \
        kf_##name = (typeof(kf_##name))kallsyms_lookup_name(#name); \
        if (!kf_##name) { \
            logv("FATAL: symbol not found: %s\n", #name); \
            return -1; \
        } \
        logv("symbol resolved: %s\n", #name); \
    } while (0)

static long hello_demo_init(const char *args, const char *event, void *__user reserved)
{
    kv_memstart_addr  = (uint64_t)kallsyms_lookup_name("memstart_addr");
    kv_kimage_voffset = (uint64_t)kallsyms_lookup_name("kimage_voffset");

    RESOLVE(__arch_copy_from_user);
    RESOLVE(__arch_copy_to_user);
    RESOLVE(find_task_by_vpid);
    RESOLVE(get_task_mm);
    RESOLVE(mmput);
    RESOLVE(down_read);
    RESOLVE(up_read);
    RESOLVE(dentry_path_raw);
    RESOLVE(strstr);
    RESOLVE(strcmp);
    RESOLVE(strncmp);
    RESOLVE(strlen);
    RESOLVE(strrchr);
    RESOLVE(memcpy);
    RESOLVE(memset);
    RESOLVE(pfn_valid);
    RESOLVE(valid_phys_addr_range);
    RESOLVE(register_user_hw_breakpoint);
    RESOLVE(unregister_hw_breakpoint);
    RESOLVE(perf_event_enable);
    RESOLVE(__kmalloc);
    RESOLVE(kmalloc);
    RESOLVE(kfree);
    RESOLVE(_raw_spin_lock);
    RESOLVE(_raw_spin_unlock);

    kf_get_task_pid = (typeof(kf_get_task_pid))kallsyms_lookup_name("get_task_pid");
    kf_put_pid      = (typeof(kf_put_pid))kallsyms_lookup_name("put_pid");
    kf_attach_pid   = (uint64_t)kallsyms_lookup_name("attach_pid");
    kf_modify_user_hw_breakpoint = (uint64_t)kallsyms_lookup_name("modify_user_hw_breakpoint");

    uint64_t tcr_el1;
    __asm__ volatile("mrs %0, tcr_el1" : "=r"(tcr_el1));
    uint64_t tg1 = (tcr_el1 >> 30) & 0x3;
    my_va_bits = 64 - ((tcr_el1 >> 16) & 0x1F);
    if (tg1 == 1)       my_page_shift = 14;
    else if (tg1 == 3)  my_page_shift = 16;
    else                my_page_shift = 12;

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

    uint64_t init_task_addr = (uint64_t)kallsyms_lookup_name("init_task");
    if (init_task_addr && kf_get_task_pid) {
        void *pid = kf_get_task_pid((void *)init_task_addr, 0);
        if (pid && kf_put_pid) kf_put_pid(pid);
    }

    flb_discover_offsets();

    return (long)fp_hook_syscalln(29, 3, before_ioctl, NULL, NULL);
}

static long hello_demo_control0(const char *ctl_args, char *__user out_msg, int outlen)
{
    logv("welcome to use my kpm\n");
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

    logv("hello_demo_exit\n");
    return 0;
}

static void before_ioctl(hook_fargs4_t *args, void *udata)
{
    uint64_t *regs    = syscall_args(args);
    int64_t   cmd     = (int64_t)regs[1];
    uint64_t  user_data = regs[2];

    if ((uint64_t)(cmd - OP_READ_MEM) > (uint64_t)(OP_FIND_LIB_BASE - OP_READ_MEM))
        return;

    if (cmd == OP_READ_MEM || cmd == OP_WRITE_MEM) {
        copy_memory_t rcmd;
        if (kf___arch_copy_from_user(&rcmd, (void __user *)user_data, sizeof(rcmd))) return;
        uint64_t remaining = rcmd.size;
        if (!remaining) return;
        uint64_t vaddr  = rcmd.addr;
        uint64_t outbuf = rcmd.buffer;

        while (remaining) {
            uint64_t pgsz  = 1ULL << my_page_shift;
            uint64_t pgoff = vaddr & (pgsz - 1);
            uint64_t chunk = pgsz - pgoff;
            if (chunk > remaining) chunk = remaining;

            void *task = kf_find_task_by_vpid(rcmd.pid);
            if (!task) goto next_chunk;
            void *mm = kf_get_task_mm(task);
            if (!mm) goto next_chunk;

            uint64_t ps     = my_page_shift;
            uint64_t vb     = my_va_bits;
            uint64_t es     = ps - 3;
            int64_t  levels = (int64_t)((vb - 4) / es);
            uint64_t phys_addr = 0;

            if (levels >= 1) {
                int64_t  level = 4 - levels;
                uint64_t tbl   = *(uint64_t *)((uint64_t)mm + pgd_offset);
                uint64_t pmask = ~(-1ULL << (48 - (uint8_t)ps)) << ps;
                uint64_t imask = (1U << es) - 1;
                int found = 0;

                while (!found) {
                    uint64_t shift = (4 - (uint8_t)level) * es + 3;
                    uint64_t idx   = (vaddr >> shift) & imask;
                    uint64_t entry = *(uint64_t *)(tbl + idx * 8);
                    uint64_t dt    = entry & 3;

                    if (dt == 3) {
                        tbl = (pmask & entry) + (-1ULL << vb) - *(uint64_t *)kv_memstart_addr;
                        level++;
                        if (level >= 3) { found = 1; break; }
                    } else if (dt == 1) {
                        if (level == 0) {
                            pmask = ~(-1ULL << (48 - ((uint8_t)ps + 3 * es))) << ((uint8_t)ps + 3 * es);
                            tbl   = (pmask & entry) + (-1ULL << vb) - *(uint64_t *)kv_memstart_addr;
                            level++;
                            if (level >= 3) { found = 1; break; }
                            continue;
                        }
                        found = 1; break;
                    } else {
                        break;
                    }
                }

                if (found) {
                    uint64_t shift = (4 - (uint8_t)level) * es + 3;
                    uint64_t idx   = (vaddr >> shift) & imask;
                    uint64_t entry = *(uint64_t *)(tbl + idx * 8);
                    if ((~(uint16_t)entry & 0x401) == 0) {
                        uint64_t pa_frame = 0;
                        if (my_pa_bits == 52)
                            pa_frame = (entry << 36) & 0xF000000000000ULL;
                        phys_addr  = (pa_frame + (entry & pmask)) & (-1ULL << ps);
                        phys_addr |= vaddr & ~(-1ULL << ps);
                    }
                }
            }

            if (kf_mmput) kf_mmput(mm);

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
                        uint8_t  *tmp;
                        uint64_t  not_copied;
                        tmp = kf_kmalloc ? (uint8_t *)kf_kmalloc(chunk, 0xD0)
                                         : (uint8_t *)kf___kmalloc(chunk, 0xD0);
                        if (!tmp) goto next_chunk;
                        not_copied = kf___arch_copy_from_user(tmp, (void __user *)outbuf, chunk);
                        if (not_copied) { kf_kfree(tmp); goto next_chunk; }
                        for (uint64_t i = 0; i < chunk; i++)
                            *(volatile uint8_t *)(kva + i) = tmp[i];
                        kf_kfree(tmp);
                    }
                }
            }

        next_chunk:
            remaining -= chunk;
            vaddr     += chunk;
            outbuf    += chunk;
        }
        return;
    }

    if (cmd == OP_GET_CPU_NUM_BRPS || cmd == OP_GET_CPU_NUM_WRPS) {
        uint64_t __attribute__((unused)) dfr0;
        __asm__ volatile("mrs %0, id_aa64dfr0_el1" : "=r"(dfr0));
        return;
    }

    if (cmd == OP_SET_HW_BREAKPOINT) {
        hw_breakpoint_cmd_t bcmd;
        if (kf___arch_copy_from_user(&bcmd, (void __user *)user_data, sizeof(bcmd))) return;

        void *task = kf_find_task_by_vpid(bcmd.pid);
        if (!task) return;

        char attr[136];
        if (kf_memset) kf_memset(attr, 0, sizeof(attr));

        *(uint32_t *)(attr + 0x00) = 5;
        if (kver >> 9 >= 0x285) {
            *(uint32_t *)(attr + 0x04) = 120;
            if (kver > 0x50EFF)
                *(uint32_t *)(attr + 0x04) = (kver >> 8 > 0x600) ? 136 : 128;
        }
        *(uint64_t *)(attr + 0x10)  = 1;
        *(uint64_t *)(attr + 0x28) |= 0x24;
        *(uint32_t *)(attr + 0x34)  = bcmd.type;
        *(uint64_t *)(attr + 0x38)  = bcmd.addr;
        *(uint64_t *)(attr + 0x40)  = bcmd.len;

        void *ev = kf_register_user_hw_breakpoint(attr, hw_breakpoint_handler, 0, task);
        if ((uint64_t)ev > 0xFFFFFFFFFFFFF000ULL) return;

        if (kf_perf_event_enable) kf_perf_event_enable(ev);

        void *(*alloc_fn)(uint64_t, uint32_t);
        alloc_fn = kf_kmalloc ? (void *)kf_kmalloc : (void *)kf___kmalloc;
        struct bp_node *node = (struct bp_node *)alloc_fn(sizeof(struct bp_node), 0xD0);
        if (!node) { if (kf_unregister_hw_breakpoint) kf_unregister_hw_breakpoint(ev); return; }

        node->pid        = bcmd.pid;
        node->perf_event = (uint64_t)ev;
        node->addr       = bcmd.addr;

        kf__raw_spin_lock(&bp_lock);
        bp_list_add(node, &bp_list);
        kf__raw_spin_unlock(&bp_lock);
        return;
    }

    if (cmd == OP_REMOVE_HW_BREAKPOINT) {
        hw_breakpoint_cmd_t bcmd;
        if (kf___arch_copy_from_user(&bcmd, (void __user *)user_data, sizeof(bcmd))) return;

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

    if (cmd == OP_FIND_LIB_BASE) {
        find_lib_cmd_t lcmd;
        if (kf___arch_copy_from_user(&lcmd, (void __user *)user_data, sizeof(lcmd))) return;

        char libname[256];
        kf_memset(libname, 0, sizeof(libname));
        if (kf___arch_copy_from_user(libname, (void __user *)lcmd.lib_name_ptr, sizeof(libname) - 1)) return;

        uint64_t base = find_lib_base(lcmd.pid, libname);

        kf___arch_copy_to_user(
            (void __user *)(user_data + __builtin_offsetof(find_lib_cmd_t, out_base_addr)),
            &base, sizeof(base));
        return;
    }
}

KPM_INIT(hello_demo_init);
KPM_CTL0(hello_demo_control0);
KPM_EXIT(hello_demo_exit);
