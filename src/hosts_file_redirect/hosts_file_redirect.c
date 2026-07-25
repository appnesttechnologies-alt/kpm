/* SPDX-License-Identifier: GPL-2.0-or-later */
/*
 * kpm_bridge.c — KernelPatch Memory Bridge (ANTICRASH VERSION)
 * Robust process memory read/write via /proc/hfr_mem
 *
 * Transport: write(k_packet) → driver processes → copy_to_user result back
 * Architecture: ARM64 Android (KernelPatch environment)
 */

#include <compiler.h>
#include <hook.h>
#include <kpmodule.h>
#include <kputils.h>
#include <linux/errno.h>
#include <linux/printk.h>
#include <linux/string.h>
#include <linux/sched.h>
#include <linux/pid.h>
#include <linux/version.h>
#include <linux/uaccess.h>
#include <linux/fs.h>
#include <linux/mm.h>

KPM_NAME("kpm_bridge");
KPM_VERSION("3.0.0");
KPM_LICENSE("GPL v2");
KPM_AUTHOR("Surajit");
KPM_DESCRIPTION("KPM ANTICRASH Memory Bridge — bulletproof read/write via GUP");

/* ─── Logging ──────────────────────────────────────────────────────────────── */
#define KPM_TAG "KPM_AC"
#define kpm_info(fmt, ...)  pr_info("[%s] " fmt, KPM_TAG, ##__VA_ARGS__)
#define kpm_err(fmt, ...)   pr_err("[%s] ERR " fmt, KPM_TAG, ##__VA_ARGS__)
#define kpm_warn(fmt, ...)  pr_warn("[%s] WARN " fmt, KPM_TAG, ##__VA_ARGS__)

/* Comment out pr_debug usage - not available in all kernel configs */
#ifdef CONFIG_DYNAMIC_DEBUG
#define kpm_dbg(fmt, ...)   pr_debug("[%s] DBG " fmt, KPM_TAG, ##__VA_ARGS__)
#else
#define kpm_dbg(fmt, ...)   /* disabled */
#endif

/* ─── Protocol ─────────────────────────────────────────────────────────────── */
#define MAX_INLINE      256
#define MAX_GUP_PAGES   16

#define OP_READ_VM      0x2000
#define OP_WRITE_VM     0x3000

#define STATUS_SUCCESS          0x0000
#define STATUS_INVALID_SIZE     0x1005
#define STATUS_OUT_OF_RANGE     0x1006
#define STATUS_BAD_OPCODE       0x1007
#define STATUS_NO_TASK          0x1008
#define STATUS_NO_MM            0x1009
#define STATUS_VM_FAULT         0x100A
#define STATUS_PARTIAL_IO       0x100B
#define STATUS_PROTECTION       0x100C
#define STATUS_INVALID_ADDR     0x100D
#define STATUS_NULL_SYMBOL      0x100E
#define STATUS_INTERNAL_ERR     0x100F
#define STATUS_MM_DEAD          0x1010
#define STATUS_TASK_DEAD        0x1011
#define STATUS_TIMEOUT          0x1012

/* ─── Constants ────────────────────────────────────────────────────────────── */
#ifndef PAGE_SIZE
#define PAGE_SIZE 4096UL
#endif
#ifndef PAGE_MASK
#define PAGE_MASK (~(PAGE_SIZE - 1))
#endif
#ifndef PAGE_SHIFT
#define PAGE_SHIFT 12
#endif

#define PAGE_OFFSET_OF(addr)  ((addr) & ~PAGE_MASK)
#define PAGE_BASE_OF(addr)    ((addr) &  PAGE_MASK)
#define min(a, b) ((a) < (b) ? (a) : (b))
#define GUP_RETRY_COUNT 3
#define MM_LOCK_TIMEOUT 100

/* ─── ARM64 user VA validation ─────────────────────────────────────────────── */
#define USER_VA_MIN  0x0000000000001000ULL
#define USER_VA_MAX  0x0000800000000000ULL

static inline int is_valid_user_addr(uint64_t addr, uint32_t size)
{
    if (addr < USER_VA_MIN)          return 0;
    if (addr >= USER_VA_MAX)         return 0;
    if (size == 0)                   return 0;
    if (size > MAX_INLINE)           return 0;
    if (addr + (uint64_t)size < addr) return 0;
    if (addr + (uint64_t)size > USER_VA_MAX) return 0;
    return 1;
}

/* ─── Packet ────────────────────────────────────────────────────────────────── */
struct k_packet {
    uint32_t op_code;
    uint32_t target_pid;
    uint64_t vaddr;
    uint32_t size;
    uint32_t status;
    uint8_t  inline_data[MAX_INLINE];
} __attribute__((aligned(8), packed));

/* ─── Dynamic Struct Definitions ───────────────────────────────────────────── */
struct mm_struct_dynamic {
    void *mmap;
    void *pgd;
    int mm_users;
    int mm_count;
    void *mmap_sem;
    unsigned long task_size;
    unsigned long start_code;
    unsigned long end_code;
    unsigned long start_data;
    unsigned long end_data;
    unsigned long start_brk;
    unsigned long brk;
    unsigned long start_stack;
    unsigned long arg_start;
    unsigned long arg_end;
    unsigned long env_start;
    unsigned long env_end;
};

/* ─── Symbol typedefs ───────────────────────────────────────────────────────── */
typedef void *(*fn_proc_create_data)(const char *, uint16_t, void *, const void *, void *);
typedef void  (*fn_remove_proc_entry)(const char *, void *);
typedef unsigned long (*fn_copy_from_user)(void *, const void __user *, unsigned long);
typedef unsigned long (*fn_copy_to_user)(void __user *, const void *, unsigned long);
typedef struct task_struct *(*fn_find_task_by_vpid)(pid_t);
typedef struct mm_struct *(*fn_get_task_mm)(struct task_struct *);
typedef void (*fn_mmput)(struct mm_struct *);
typedef struct task_struct *(*fn_get_task_struct)(struct task_struct *);
typedef void (*fn_put_task_struct)(struct task_struct *);
typedef pid_t (*fn_task_pid_nr_ns)(struct task_struct *, int, void *);
typedef void (*fn_rcu_read_lock)(void);
typedef void (*fn_rcu_read_unlock)(void);
typedef long (*fn_get_user_pages_remote)(
    struct mm_struct *, unsigned long, unsigned long, unsigned int,
    struct page **, struct vm_area_struct **, int *);
typedef void *(*fn_kmap_atomic)(struct page *);
typedef void  (*fn_kunmap_atomic)(void *);
typedef void *(*fn_page_address)(struct page *);
typedef int   (*fn_set_page_dirty)(struct page *);
typedef void  (*fn_flush_dcache_page)(struct page *);
typedef void  (*fn_put_page)(struct page *);
typedef int   (*fn_atomic_read)(int *);
typedef void  (*fn_msleep)(unsigned int);
typedef long  (*fn_down_read_killable)(void *);
typedef void  (*fn_up_read)(void *);

/* ─── Global state ──────────────────────────────────────────────────────────── */
static const char *PROC_NAME = "hfr_mem";
static void *proc_entry = NULL;
static int g_module_active = 0;
static unsigned long g_total_reads = 0;
static unsigned long g_total_writes = 0;
static unsigned long g_total_errors = 0;

/* ─── Symbol table ──────────────────────────────────────────────────────────── */
static fn_proc_create_data       sym_proc_create_data;
static fn_remove_proc_entry      sym_remove_proc_entry;
static fn_copy_from_user         sym_copy_from_user;
static fn_copy_to_user           sym_copy_to_user;
static fn_find_task_by_vpid      sym_find_task_by_vpid;
static fn_get_task_mm            sym_get_task_mm;
static fn_mmput                  sym_mmput;
static fn_get_task_struct        sym_get_task_struct;
static fn_put_task_struct        sym_put_task_struct;
static fn_task_pid_nr_ns         sym_task_pid_nr_ns;
static fn_rcu_read_lock          sym_rcu_read_lock;
static fn_rcu_read_unlock        sym_rcu_read_unlock;
static fn_get_user_pages_remote  sym_get_user_pages_remote;
static fn_kmap_atomic            sym_kmap_atomic;
static fn_kunmap_atomic          sym_kunmap_atomic;
static fn_page_address           sym_page_address;
static fn_set_page_dirty         sym_set_page_dirty;
static fn_flush_dcache_page      sym_flush_dcache_page;
static fn_put_page               sym_put_page;
static fn_atomic_read            sym_atomic_read;
static fn_msleep                  sym_msleep;
static fn_down_read_killable      sym_down_read_killable;
static fn_up_read                 sym_up_read;

/* ─── Utility: Resolve symbol with multiple variants ───────────────────────── */
static void *resolve_symbol_dynamic(const char **names, const char *desc)
{
    const char **n = names;
    while (*n) {
        void *addr = (void *)kallsyms_lookup_name(*n);
        if (addr) {
            kpm_info("✓ %s: '%s' -> %px\n", desc, *n, addr);
            return addr;
        }
        n++;
    }
    kpm_warn("✗ %s: NOT FOUND (tried variants)\n", desc);
    return NULL;
}

/* ─── Current task via sp_el0 (ARM64) ──────────────────────────────────────── */
static inline struct task_struct *get_current_task_safe(void)
{
    struct task_struct *tsk = NULL;
    asm volatile("mrs %0, sp_el0" : "=r"(tsk));
    if (!tsk || (unsigned long)tsk < 0xffff000000000000ULL) {
        kpm_err("sp_el0 returned invalid task: %px\n", tsk);
        return NULL;
    }
    return tsk;
}

/* ─── Safe page mapping ─────────────────────────────────────────────────────── */
typedef struct {
    void *kaddr;
    int used_kmap;
} page_map_safe_t;

static page_map_safe_t map_page_safe(struct page *page)
{
    page_map_safe_t m = { .kaddr = NULL, .used_kmap = 0 };

    if (!page) {
        kpm_err("map_page_safe: NULL page\n");
        return m;
    }

    /* Try page_address first */
    if (sym_page_address) {
        m.kaddr = sym_page_address(page);
        if (m.kaddr) {
            if ((unsigned long)m.kaddr < 0xffff000000000000ULL) {
                kpm_err("map_page_safe: page_address returned invalid address %px\n", m.kaddr);
                m.kaddr = NULL;
                return m;
            }
            return m;
        }
    }

    /* Fallback to kmap_atomic */
    if (sym_kmap_atomic) {
        m.kaddr = sym_kmap_atomic(page);
        m.used_kmap = 1;
        
        if (!m.kaddr) {
            kpm_err("map_page_safe: kmap_atomic returned NULL\n");
            m.used_kmap = 0;
            return m;
        }
        
        if ((unsigned long)m.kaddr < 0xffff000000000000ULL) {
            kpm_err("map_page_safe: kmap_atomic returned invalid address %px\n", m.kaddr);
            if (sym_kunmap_atomic)
                sym_kunmap_atomic(m.kaddr);
            m.kaddr = NULL;
            m.used_kmap = 0;
        }
    }

    return m;
}

static void unmap_page_safe(page_map_safe_t *m)
{
    if (!m) return;
    
    if (m->used_kmap && m->kaddr && sym_kunmap_atomic) {
        sym_kunmap_atomic(m->kaddr);
    }
    m->kaddr = NULL;
    m->used_kmap = 0;
}

/* ─── Validate mm_struct is alive ──────────────────────────────────────────── */
static int is_mm_alive(struct mm_struct *mm)
{
    if (!mm) {
        return 0;
    }

    if (!sym_atomic_read) {
        return 1; /* Assume alive if we can't check */
    }

    struct mm_struct_dynamic *mmd = (struct mm_struct_dynamic *)mm;
    int users = sym_atomic_read(&mmd->mm_users);
    
    if (users <= 0) {
        kpm_warn("is_mm_alive: mm_users=%d (DEAD)\n", users);
        return 0;
    }

    return 1;
}

/* ─── Safe mm locking ──────────────────────────────────────────────────────── */
static int lock_mm_safe(struct mm_struct *mm)
{
    if (!mm || !is_mm_alive(mm)) {
        return 0;
    }

    if (!sym_down_read_killable) {
        return 1; /* Assume success, GUP will handle it */
    }

    struct mm_struct_dynamic *mmd = (struct mm_struct_dynamic *)mm;
    long ret = sym_down_read_killable(mmd->mmap_sem);
    
    if (ret != 0) {
        kpm_err("lock_mm_safe: down_read_killable failed with %ld\n", ret);
        return 0;
    }

    if (!is_mm_alive(mm)) {
        if (sym_up_read)
            sym_up_read(mmd->mmap_sem);
        kpm_err("lock_mm_safe: mm died during lock\n");
        return 0;
    }

    return 1;
}

static void unlock_mm_safe(struct mm_struct *mm)
{
    if (!mm || !sym_up_read) return;
    
    struct mm_struct_dynamic *mmd = (struct mm_struct_dynamic *)mm;
    sym_up_read(mmd->mmap_sem);
}

/* ─── Core safe read/write ─────────────────────────────────────────────────── */
static int rw_core_safe(struct task_struct *task,
                        unsigned long addr,
                        void *buffer,
                        int size,
                        int is_write)
{
    struct mm_struct *mm = NULL;
    struct page *pages[MAX_GUP_PAGES];
    long gup_ret;
    int nr_pages_needed;
    int processed = 0;
    int i, retry;
    unsigned int gup_flags;
    int mm_locked = 0;

    /* Validation */
    if (!task || !buffer || size <= 0 || size > MAX_INLINE) {
        kpm_err("rw_core_safe: invalid args task=%px buf=%px size=%d\n",
                task, buffer, size);
        return -EINVAL;
    }

    if (!sym_get_user_pages_remote) {
        kpm_err("rw_core_safe: get_user_pages_remote not available\n");
        return -ENOSYS;
    }

    /* Validate task structure */
    if ((unsigned long)task < 0xffff000000000000ULL) {
        kpm_err("rw_core_safe: invalid task pointer %px\n", task);
        return -EINVAL;
    }

    /* Calculate pages needed */
    nr_pages_needed = (int)(((addr & ~PAGE_MASK) + (unsigned long)size
                              + PAGE_SIZE - 1) >> PAGE_SHIFT);

    if (nr_pages_needed > MAX_GUP_PAGES) {
        kpm_err("rw_core_safe: needs %d pages (max %d)\n",
                nr_pages_needed, MAX_GUP_PAGES);
        return -EINVAL;
    }

    if (nr_pages_needed <= 0) {
        kpm_err("rw_core_safe: invalid page count %d\n", nr_pages_needed);
        return -EINVAL;
    }

    /* Retry logic for GUP */
    for (retry = 0; retry < GUP_RETRY_COUNT; retry++) {
        mm = sym_get_task_mm(task);
        if (!mm) {
            kpm_err("rw_core_safe: get_task_mm failed (attempt %d/%d)\n",
                    retry + 1, GUP_RETRY_COUNT);
            if (sym_msleep && retry < GUP_RETRY_COUNT - 1)
                sym_msleep(10);
            continue;
        }

        /* Validate mm */
        if (!is_mm_alive(mm)) {
            kpm_err("rw_core_safe: mm is dead (attempt %d/%d)\n",
                    retry + 1, GUP_RETRY_COUNT);
            sym_mmput(mm);
            mm = NULL;
            if (sym_msleep)
                sym_msleep(10);
            continue;
        }

        /* Lock mm if possible */
        mm_locked = lock_mm_safe(mm);
        if (!mm_locked) {
            kpm_warn("rw_core_safe: failed to lock mm (attempt %d/%d)\n",
                     retry + 1, GUP_RETRY_COUNT);
        }

        memset(pages, 0, sizeof(pages));

        /* GUP flags */
        gup_flags = 0x01 | 0x04; /* FOLL_GET | FOLL_WRITE */
        if (is_write) {
            gup_flags |= 0x10; /* FOLL_FORCE for write */
        }

        int locked = 1;
        gup_ret = sym_get_user_pages_remote(mm,
                                            addr & PAGE_MASK,
                                            (unsigned long)nr_pages_needed,
                                            gup_flags,
                                            pages,
                                            NULL,
                                            &locked);

        /* Handle GUP result */
        if (gup_ret <= 0) {
            kpm_warn("rw_core_safe: GUP failed ret=%ld addr=0x%lx flags=0x%x (attempt %d/%d)\n",
                    gup_ret, addr, gup_flags, retry + 1, GUP_RETRY_COUNT);
            
            if (mm_locked)
                unlock_mm_safe(mm);
            sym_mmput(mm);
            mm = NULL;
            mm_locked = 0;

            if (sym_msleep && retry < GUP_RETRY_COUNT - 1)
                sym_msleep(20);
            continue;
        }

        /* GUP succeeded - break retry loop */
        break;
    }

    /* Check if all retries failed */
    if (!mm || gup_ret <= 0) {
        kpm_err("rw_core_safe: all GUP retries failed\n");
        if (mm) {
            if (mm_locked) unlock_mm_safe(mm);
            sym_mmput(mm);
        }
        return -EFAULT;
    }

    /* Copy data page by page */
    for (i = 0; i < (int)gup_ret && processed < size; i++) {
        int offset = (i == 0) ? (int)(addr & ~PAGE_MASK) : 0;
        int copy_size = (int)min((unsigned long)(size - processed),
                                 PAGE_SIZE - (unsigned long)offset);
        page_map_safe_t m;

        if (!pages[i]) {
            kpm_err("rw_core_safe: pages[%d] is NULL\n", i);
            continue;
        }

        /* Verify page validity */
        if ((unsigned long)pages[i] < 0xffff000000000000ULL) {
            kpm_err("rw_core_safe: pages[%d] invalid address %px\n",
                    i, pages[i]);
            if (sym_put_page)
                sym_put_page(pages[i]);
            pages[i] = NULL;
            continue;
        }

        m = map_page_safe(pages[i]);
        if (!m.kaddr) {
            kpm_err("rw_core_safe: page[%d] map failed\n", i);
            if (sym_put_page)
                sym_put_page(pages[i]);
            pages[i] = NULL;
            continue;
        }

        /* Verify kernel address range */
        if ((unsigned long)m.kaddr < 0xffff000000000000ULL) {
            kpm_err("rw_core_safe: page[%d] mapped to invalid kaddr %px\n",
                    i, m.kaddr);
            unmap_page_safe(&m);
            if (sym_put_page)
                sym_put_page(pages[i]);
            pages[i] = NULL;
            continue;
        }

        /* Perform copy */
        if (is_write) {
            memcpy((char *)m.kaddr + offset,
                   (char *)buffer + processed,
                   (size_t)copy_size);
            
            if (sym_set_page_dirty)
                sym_set_page_dirty(pages[i]);
            if (sym_flush_dcache_page)
                sym_flush_dcache_page(pages[i]);
        } else {
            memcpy((char *)buffer + processed,
                   (char *)m.kaddr + offset,
                   (size_t)copy_size);
        }

        unmap_page_safe(&m);
        processed += copy_size;

        if (sym_put_page)
            sym_put_page(pages[i]);
        pages[i] = NULL;
    }

    /* Cleanup remaining pages */
    for (i = 0; i < (int)gup_ret; i++) {
        if (pages[i] && sym_put_page) {
            sym_put_page(pages[i]);
            pages[i] = NULL;
        }
    }

    /* Release mm */
    if (mm_locked)
        unlock_mm_safe(mm);
    if (mm)
        sym_mmput(mm);

    /* Log result */
    if (processed == 0 && size > 0) {
        kpm_err("rw_core_safe: ZERO bytes transferred for addr=0x%lx\n", addr);
        return -EFAULT;
    }

    if (processed != size) {
        kpm_warn("rw_core_safe: partial transfer %d/%d bytes\n", processed, size);
    }

    return processed;
}

/* ─── Packet processor with crash protection ────────────────────────────────── */
static void process_packet_safe(struct k_packet *pkt, pid_t caller_pid)
{
    struct task_struct *task = NULL;
    pid_t target_pid;
    int is_write;
    int transferred;
    uint8_t scratch[MAX_INLINE];
    int task_ref_taken = 0;

    /* Validate packet */
    if (!pkt) {
        kpm_err("process_packet_safe: NULL packet\n");
        return;
    }

    /* Validate opcode */
    if (pkt->op_code != OP_READ_VM && pkt->op_code != OP_WRITE_VM) {
        kpm_err("process_packet_safe: bad opcode 0x%x\n", pkt->op_code);
        pkt->status = STATUS_BAD_OPCODE;
        g_total_errors++;
        return;
    }

    is_write = (pkt->op_code == OP_WRITE_VM);

    /* Validate address and size */
    if (!is_valid_user_addr(pkt->vaddr, pkt->size)) {
        kpm_err("process_packet_safe: invalid addr=0x%llx size=%u\n",
                pkt->vaddr, pkt->size);
        pkt->status = STATUS_INVALID_ADDR;
        g_total_errors++;
        return;
    }

    /* Critical symbol check */
    if (!sym_get_user_pages_remote || !sym_find_task_by_vpid ||
        !sym_get_task_mm || !sym_mmput || !sym_put_page) {
        kpm_err("process_packet_safe: critical symbols missing\n");
        pkt->status = STATUS_NULL_SYMBOL;
        g_total_errors++;
        return;
    }

    /* Determine target PID */
    target_pid = pkt->target_pid ? (pid_t)pkt->target_pid : caller_pid;
    if (target_pid <= 0) {
        kpm_err("process_packet_safe: invalid pid %d\n", target_pid);
        pkt->status = STATUS_OUT_OF_RANGE;
        g_total_errors++;
        return;
    }

    /* Find task with RCU protection */
    if (sym_rcu_read_lock)
        sym_rcu_read_lock();
    
    task = sym_find_task_by_vpid(target_pid);
    
    if (task) {
        /* Validate task pointer */
        if ((unsigned long)task < 0xffff000000000000ULL) {
            kpm_err("process_packet_safe: invalid task pointer %px\n", task);
            task = NULL;
        } else if (sym_get_task_struct) {
            sym_get_task_struct(task);
            task_ref_taken = 1;
        }
    }

    if (sym_rcu_read_unlock)
        sym_rcu_read_unlock();

    if (!task) {
        kpm_err("process_packet_safe: task not found for pid=%d\n", target_pid);
        pkt->status = STATUS_NO_TASK;
        g_total_errors++;
        return;
    }

    /* Prepare scratch buffer */
    memset(scratch, 0, MAX_INLINE);
    if (is_write)
        memcpy(scratch, pkt->inline_data, (size_t)pkt->size);

    /* Perform transfer */
    kpm_info("%s START pid=%d addr=0x%llx size=%u\n",
             is_write ? "WRITE" : "READ",
             target_pid, pkt->vaddr, pkt->size);

    transferred = rw_core_safe(task,
                               (unsigned long)pkt->vaddr,
                               scratch,
                               (int)pkt->size,
                               is_write);

    /* Release task reference */
    if (task_ref_taken && sym_put_task_struct) {
        sym_put_task_struct(task);
        task_ref_taken = 0;
    }

    /* Process result */
    if (transferred < 0) {
        kpm_err("process_packet_safe: transfer failed with %d\n", transferred);
        
        switch (transferred) {
            case -EINVAL:
                pkt->status = STATUS_INVALID_ADDR;
                break;
            case -ENOSYS:
                pkt->status = STATUS_NULL_SYMBOL;
                break;
            case -EFAULT:
                pkt->status = STATUS_VM_FAULT;
                break;
            case -ESRCH:
                pkt->status = STATUS_NO_MM;
                break;
            default:
                pkt->status = STATUS_INTERNAL_ERR;
                break;
        }
        g_total_errors++;
        return;
    }

    if (transferred == 0) {
        kpm_err("process_packet_safe: zero-byte transfer\n");
        pkt->status = STATUS_PROTECTION;
        g_total_errors++;
        return;
    }

    /* Copy data back for reads */
    if (!is_write) {
        memset(pkt->inline_data, 0, MAX_INLINE);
        memcpy(pkt->inline_data, scratch, (size_t)transferred);
    }

    /* Set final status */
    if ((uint32_t)transferred != pkt->size) {
        kpm_warn("process_packet_safe: PARTIAL %d/%u bytes\n",
                 transferred, pkt->size);
        pkt->size = (uint32_t)transferred;
        pkt->status = STATUS_PARTIAL_IO;
    } else {
        pkt->status = STATUS_SUCCESS;
        if (is_write)
            g_total_writes++;
        else
            g_total_reads++;
    }

    kpm_info("%s OK pid=%d addr=0x%llx size=%u [R:%lu W:%lu E:%lu]\n",
             is_write ? "WRITE" : "READ",
             target_pid, pkt->vaddr, pkt->size,
             g_total_reads, g_total_writes, g_total_errors);
}

/* ─── /proc handlers ───────────────────────────────────────────────────────── */
static int proc_open_cb(struct inode *inode, struct file *file)
{
    if (!g_module_active) {
        kpm_err("proc_open: module not active\n");
        return -EIO;
    }
    return 0;
}

static int proc_release_cb(struct inode *inode, struct file *file)
{
    return 0;
}

static ssize_t proc_read_cb(struct file *file, char __user *buf,
                             size_t count, loff_t *pos)
{
    /* Simple stats via read - using manual string formatting */
    char stats[256];
    int len = 0;
    
    if (*pos > 0)
        return 0;
    
    /* Manual string construction instead of snprintf */
    len = 0;
    memcpy(stats + len, "KPM Bridge v3.0 (ANTICRASH)\n", 27);
    len += 27;
    memcpy(stats + len, "Reads: ", 7);
    len += 7;
    
    /* Simple number conversion for stats */
    if (g_total_reads == 0) {
        stats[len++] = '0';
    } else {
        char tmp[32];
        int tmp_len = 0;
        unsigned long val = g_total_reads;
        while (val > 0) {
            tmp[tmp_len++] = '0' + (val % 10);
            val /= 10;
        }
        while (tmp_len > 0) {
            stats[len++] = tmp[--tmp_len];
        }
    }
    stats[len++] = '\n';
    
    memcpy(stats + len, "Writes: ", 8);
    len += 8;
    
    if (g_total_writes == 0) {
        stats[len++] = '0';
    } else {
        char tmp[32];
        int tmp_len = 0;
        unsigned long val = g_total_writes;
        while (val > 0) {
            tmp[tmp_len++] = '0' + (val % 10);
            val /= 10;
        }
        while (tmp_len > 0) {
            stats[len++] = tmp[--tmp_len];
        }
    }
    stats[len++] = '\n';
    
    memcpy(stats + len, "Errors: ", 8);
    len += 8;
    
    if (g_total_errors == 0) {
        stats[len++] = '0';
    } else {
        char tmp[32];
        int tmp_len = 0;
        unsigned long val = g_total_errors;
        while (val > 0) {
            tmp[tmp_len++] = '0' + (val % 10);
            val /= 10;
        }
        while (tmp_len > 0) {
            stats[len++] = tmp[--tmp_len];
        }
    }
    stats[len++] = '\n';
    
    if (len > count)
        len = count;
    
    if (sym_copy_to_user) {
        if (sym_copy_to_user(buf, stats, len))
            return -EFAULT;
    }
    
    *pos = len;
    return len;
}

static ssize_t proc_write_cb(struct file *file, const char __user *ubuf,
                              size_t count, loff_t *pos)
{
    struct k_packet local_pkt;
    struct task_struct *curr;
    pid_t caller_pid;
    unsigned long copy_ret;

    /* Validate module state */
    if (!g_module_active) {
        kpm_err("proc_write: module not active\n");
        return -EIO;
    }

    /* Size validation */
    if (count != sizeof(struct k_packet)) {
        kpm_err("proc_write: bad size %zu (expected %zu)\n",
                count, sizeof(struct k_packet));
        return -EINVAL;
    }

    /* Check required symbols */
    if (!sym_copy_from_user || !sym_copy_to_user) {
        kpm_err("proc_write: copy_from/to_user not available\n");
        return -ENOSYS;
    }

    /* Safe copy from user */
    memset(&local_pkt, 0, sizeof(local_pkt));
    copy_ret = sym_copy_from_user(&local_pkt, ubuf, sizeof(struct k_packet));
    if (copy_ret != 0) {
        kpm_err("proc_write: copy_from_user failed (%lu bytes)\n", copy_ret);
        return -EFAULT;
    }

    /* Get caller PID */
    curr = get_current_task_safe();
    if (!curr) {
        kpm_err("proc_write: cannot get current task\n");
        return -ESRCH;
    }

    if (!sym_task_pid_nr_ns) {
        kpm_err("proc_write: task_pid_nr_ns not available\n");
        return -ENOSYS;
    }

    caller_pid = sym_task_pid_nr_ns(curr, 0, NULL); /* PIDTYPE_PID = 0 */
    if (caller_pid <= 0) {
        kpm_err("proc_write: invalid caller PID\n");
        return -ESRCH;
    }

    /* Process packet */
    process_packet_safe(&local_pkt, caller_pid);

    /* Return result to user */
    copy_ret = sym_copy_to_user((void __user *)ubuf,
                                &local_pkt,
                                sizeof(struct k_packet));
    if (copy_ret != 0) {
        kpm_err("proc_write: copy_to_user failed (%lu bytes)\n", copy_ret);
        return -EFAULT;
    }

    return (ssize_t)count;
}

/* Custom proc_ops structure for compatibility */
struct kpm_proc_ops {
    unsigned int proc_flags;
    int (*proc_open)(struct inode *, struct file *);
    ssize_t (*proc_read)(struct file *, char __user *, size_t, loff_t *);
    ssize_t (*proc_read_iter)(void *, void *);
    ssize_t (*proc_write)(struct file *, const char __user *, size_t, loff_t *);
    loff_t (*proc_lseek)(struct file *, loff_t, int);
    int (*proc_release)(struct inode *, struct file *);
    void *proc_poll;
    long (*proc_ioctl)(struct file *, unsigned int, unsigned long);
    int (*proc_mmap)(struct file *, void *);
    unsigned long (*proc_get_unmapped_area)(struct file *, unsigned long,
                                            unsigned long, unsigned long,
                                            unsigned long);
};

static struct kpm_proc_ops kpm_proc_ops_safe = {
    .proc_flags = 0,
    .proc_open = proc_open_cb,
    .proc_read = proc_read_cb,
    .proc_read_iter = NULL,
    .proc_write = proc_write_cb,
    .proc_lseek = NULL,
    .proc_release = proc_release_cb,
    .proc_poll = NULL,
    .proc_ioctl = NULL,
    .proc_mmap = NULL,
    .proc_get_unmapped_area = NULL,
};

/* ─── Module init ─────────────────────────────────────────────────────────── */
static long kpm_bridge_init(const char *args, const char *event,
                             void __user *reserved)
{
    kpm_info("===========================================\n");
    kpm_info("  KPM BRIDGE v3.0 - ANTICRASH EDITION\n");
    kpm_info("===========================================\n");

    /* Resolve critical symbols */
    kpm_info("Resolving symbols...\n");

    /* Process creation/removal */
    sym_proc_create_data = (fn_proc_create_data)
        resolve_symbol_dynamic((const char *[]){"proc_create_data", "proc_create", NULL},
                               "proc_create_data");
    sym_remove_proc_entry = (fn_remove_proc_entry)
        resolve_symbol_dynamic((const char *[]){"remove_proc_entry", NULL},
                               "remove_proc_entry");

    /* User memory copy */
    sym_copy_from_user = (fn_copy_from_user)
        resolve_symbol_dynamic((const char *[]){"_copy_from_user", "copy_from_user",
                                                 "__copy_from_user", NULL},
                               "copy_from_user");
    sym_copy_to_user = (fn_copy_to_user)
        resolve_symbol_dynamic((const char *[]){"_copy_to_user", "copy_to_user",
                                                 "__copy_to_user", NULL},
                               "copy_to_user");

    /* Task management */
    sym_find_task_by_vpid = (fn_find_task_by_vpid)
        resolve_symbol_dynamic((const char *[]){"find_task_by_vpid", NULL},
                               "find_task_by_vpid");
    sym_get_task_mm = (fn_get_task_mm)
        resolve_symbol_dynamic((const char *[]){"get_task_mm", NULL},
                               "get_task_mm");
    sym_mmput = (fn_mmput)
        resolve_symbol_dynamic((const char *[]){"mmput", NULL},
                               "mmput");
    sym_get_task_struct = (fn_get_task_struct)
        resolve_symbol_dynamic((const char *[]){"get_task_struct", NULL},
                               "get_task_struct");
    sym_put_task_struct = (fn_put_task_struct)
        resolve_symbol_dynamic((const char *[]){"put_task_struct", NULL},
                               "put_task_struct");
    sym_task_pid_nr_ns = (fn_task_pid_nr_ns)
        resolve_symbol_dynamic((const char *[]){"__task_pid_nr_ns", "task_pid_nr_ns",
                                                 NULL},
                               "task_pid_nr_ns");

    /* RCU */
    sym_rcu_read_lock = (fn_rcu_read_lock)
        resolve_symbol_dynamic((const char *[]){"__rcu_read_lock", "rcu_read_lock",
                                                 NULL},
                               "rcu_read_lock");
    sym_rcu_read_unlock = (fn_rcu_read_unlock)
        resolve_symbol_dynamic((const char *[]){"__rcu_read_unlock", "rcu_read_unlock",
                                                 NULL},
                               "rcu_read_unlock");

    /* GUP */
    sym_get_user_pages_remote = (fn_get_user_pages_remote)
        resolve_symbol_dynamic((const char *[]){"get_user_pages_remote",
                                                 "__get_user_pages_remote",
                                                 "get_user_pages", NULL},
                               "get_user_pages_remote");

    /* Page mapping */
    sym_page_address = (fn_page_address)
        resolve_symbol_dynamic((const char *[]){"page_address", NULL},
                               "page_address");
    sym_kmap_atomic = (fn_kmap_atomic)
        resolve_symbol_dynamic((const char *[]){"kmap_atomic", "kmap_atomic_high",
                                                 "__kmap_atomic", NULL},
                               "kmap_atomic");
    sym_kunmap_atomic = (fn_kunmap_atomic)
        resolve_symbol_dynamic((const char *[]){"kunmap_atomic", "kunmap_atomic_high",
                                                 "__kunmap_atomic", NULL},
                               "kunmap_atomic");

    /* Page operations */
    sym_set_page_dirty = (fn_set_page_dirty)
        resolve_symbol_dynamic((const char *[]){"set_page_dirty", NULL},
                               "set_page_dirty");
    sym_flush_dcache_page = (fn_flush_dcache_page)
        resolve_symbol_dynamic((const char *[]){"flush_dcache_page",
                                                 "__flush_dcache_page", NULL},
                               "flush_dcache_page");
    sym_put_page = (fn_put_page)
        resolve_symbol_dynamic((const char *[]){"put_page", NULL},
                               "put_page");

    /* Optional: better mm handling */
    sym_atomic_read = (fn_atomic_read)
        resolve_symbol_dynamic((const char *[]){"atomic_read", NULL},
                               "atomic_read");
    sym_msleep = (fn_msleep)
        resolve_symbol_dynamic((const char *[]){"msleep", "msleep_interruptible",
                                                 NULL},
                               "msleep");
    sym_down_read_killable = (fn_down_read_killable)
        resolve_symbol_dynamic((const char *[]){"down_read_killable",
                                                 "down_read", NULL},
                               "down_read_killable");
    sym_up_read = (fn_up_read)
        resolve_symbol_dynamic((const char *[]){"up_read", NULL},
                               "up_read");

    /* Verify critical symbols */
    kpm_info("\nVerifying critical symbols...\n");

    #define CHECK_SYM(sym, name, critical) \
        do { \
            if (!(sym)) { \
                if (critical) { \
                    kpm_err("CRITICAL: %s not found - ABORTING\n", name); \
                    return -EFAULT; \
                } else { \
                    kpm_warn("OPTIONAL: %s not found - degraded mode\n", name); \
                } \
            } else { \
                kpm_info("  OK %s\n", name); \
            } \
        } while(0)

    CHECK_SYM(sym_proc_create_data, "proc_create_data", 1);
    CHECK_SYM(sym_remove_proc_entry, "remove_proc_entry", 1);
    CHECK_SYM(sym_copy_from_user, "copy_from_user", 1);
    CHECK_SYM(sym_copy_to_user, "copy_to_user", 1);
    CHECK_SYM(sym_find_task_by_vpid, "find_task_by_vpid", 1);
    CHECK_SYM(sym_get_task_mm, "get_task_mm", 1);
    CHECK_SYM(sym_mmput, "mmput", 1);
    CHECK_SYM(sym_put_page, "put_page", 1);
    CHECK_SYM(sym_get_user_pages_remote, "get_user_pages_remote", 1);
    CHECK_SYM(sym_task_pid_nr_ns, "task_pid_nr_ns", 1);
    CHECK_SYM(sym_rcu_read_lock, "rcu_read_lock", 0);
    CHECK_SYM(sym_rcu_read_unlock, "rcu_read_unlock", 0);
    CHECK_SYM(sym_page_address, "page_address", 0);
    CHECK_SYM(sym_kmap_atomic, "kmap_atomic", 0);
    CHECK_SYM(sym_kunmap_atomic, "kunmap_atomic", 0);
    CHECK_SYM(sym_set_page_dirty, "set_page_dirty", 0);
    CHECK_SYM(sym_flush_dcache_page, "flush_dcache_page", 0);
    CHECK_SYM(sym_get_task_struct, "get_task_struct", 0);
    CHECK_SYM(sym_put_task_struct, "put_task_struct", 0);
    CHECK_SYM(sym_atomic_read, "atomic_read", 0);
    CHECK_SYM(sym_msleep, "msleep", 0);
    CHECK_SYM(sym_down_read_killable, "down_read_killable", 0);
    CHECK_SYM(sym_up_read, "up_read", 0);

    #undef CHECK_SYM

    /* Must have at least one page mapping method */
    if (!sym_page_address && !sym_kmap_atomic) {
        kpm_err("CRITICAL: No page mapping method available\n");
        return -EFAULT;
    }

    /* Create proc entry */
    kpm_info("\nCreating /proc/%s...\n", PROC_NAME);
    
    proc_entry = sym_proc_create_data(PROC_NAME, 0666, NULL,
                                      &kpm_proc_ops_safe, NULL);
    if (!proc_entry) {
        kpm_err("CRITICAL: Failed to create /proc/%s\n", PROC_NAME);
        return -EFAULT;
    }

    g_module_active = 1;
    g_total_reads = 0;
    g_total_writes = 0;
    g_total_errors = 0;

    kpm_info("===========================================\n");
    kpm_info("  KPM BRIDGE v3.0 READY\n");
    kpm_info("  Device: /proc/%s\n", PROC_NAME);
    kpm_info("  Mode: ANTICRASH (retries: %d)\n", GUP_RETRY_COUNT);
    kpm_info("===========================================\n");

    return 0;
}

/* ─── Module exit ─────────────────────────────────────────────────────────── */
static long kpm_bridge_exit(void __user *reserved)
{
    kpm_info("===========================================\n");
    kpm_info("  KPM BRIDGE v3.0 EXIT\n");
    kpm_info("  Stats: R=%lu W=%lu E=%lu\n",
             g_total_reads, g_total_writes, g_total_errors);
    kpm_info("===========================================\n");

    g_module_active = 0;

    if (proc_entry && sym_remove_proc_entry) {
        sym_remove_proc_entry(PROC_NAME, NULL);
        proc_entry = NULL;
        kpm_info("Removed /proc/%s\n", PROC_NAME);
    }

    return 0;
}

KPM_INIT(kpm_bridge_init);
KPM_EXIT(kpm_bridge_exit);
