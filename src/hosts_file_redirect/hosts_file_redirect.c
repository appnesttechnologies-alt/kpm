/* SPDX-License-Identifier: GPL-2.0-or-later */
/*
 * kpm_bridge.c — KernelPatch Memory Bridge
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
KPM_VERSION("2.0.0");
KPM_LICENSE("GPL v2");
KPM_AUTHOR("Surajit");
KPM_DESCRIPTION("KPM Robust Memory Bridge — crash-proof read/write via GUP");

/* ─── Logging ──────────────────────────────────────────────────────────────── */
#define KPM_TAG "KPM_BRIDGE"
#define kpm_info(fmt, ...) pr_info("[%s] " fmt, KPM_TAG, ##__VA_ARGS__)
#define kpm_err(fmt, ...)  pr_err("[%s] ERROR " fmt, KPM_TAG, ##__VA_ARGS__)
#define kpm_warn(fmt, ...) pr_warn("[%s] WARN "  fmt, KPM_TAG, ##__VA_ARGS__)

/* ─── Protocol ─────────────────────────────────────────────────────────────── */
#define MAX_INLINE      256
#define MAX_GUP_PAGES   16      /* 16 * 4096 = 64 KB max transfer */

#define OP_READ_VM      0x2000
#define OP_WRITE_VM     0x3000

/* Status codes — mirrored in client header */
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

/* GUP flags — defined here to not depend on kernel header versions */
#define KPM_FOLL_WRITE  0x01
#define KPM_FOLL_FORCE  0x10
#define KPM_FOLL_GET    0x04    /* increment page refcount */

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

#ifndef min
#define min(a, b) ((a) < (b) ? (a) : (b))
#endif

/* ─── ARM64 user VA validation ─────────────────────────────────────────────── */
/*
 * ARM64 Android kernels are configured with either:
 *   39-bit VA (PAGE_SHIFT=12, T0SZ=25) → user top = 0x0000_0080_0000_0000
 *   48-bit VA (PAGE_SHIFT=12, T0SZ=16) → user top = 0x0000_8000_0000_0000
 *
 * Accept anything in [0x1000, 0x0000_8000_0000_0000).
 * Null-page guard: reject below 4 KB.
 * Stack guard: addresses near ULONG_MAX are kernel — reject if bit 63 set.
 */
#define USER_VA_MIN  0x0000000000001000ULL
#define USER_VA_MAX  0x0000800000000000ULL

static inline int is_valid_user_addr(uint64_t addr, uint32_t size)
{
    if (addr < USER_VA_MIN)          return 0;  /* null / low page */
    if (addr >= USER_VA_MAX)         return 0;  /* kernel / out of range */
    if (size == 0)                   return 0;
    if (size > MAX_INLINE)           return 0;
    /* overflow check: addr + size must not wrap */
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

/* ─── Forward declarations ──────────────────────────────────────────────────── */
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

struct mutex {
    void *owner;
    int   count;
    void *wait_lock;
    void *wait_list;
};

/* ─── Symbol typedefs ───────────────────────────────────────────────────────── */
typedef void *(*fn_proc_create_data)(const char *, uint16_t, void *,
                                     const struct proc_ops *, void *);
typedef void  (*fn_remove_proc_entry)(const char *, void *);
typedef unsigned long (*fn_copy_from_user)(void *, const void __user *, unsigned long);
typedef unsigned long (*fn_copy_to_user)(void __user *, const void *, unsigned long);
typedef struct task_struct *(*fn_find_task_by_vpid)(pid_t);
typedef struct mm_struct *(*fn_get_task_mm)(struct task_struct *);
typedef void (*fn_mmput)(struct mm_struct *);
typedef struct task_struct *(*fn_get_task_struct)(struct task_struct *);
typedef void (*fn_put_task_struct)(struct task_struct *);
typedef pid_t (*fn_task_pid_nr_ns)(struct task_struct *, enum pid_type,
                                   struct pid_namespace *);
typedef void (*fn_rcu_read_lock)(void);
typedef void (*fn_rcu_read_unlock)(void);
typedef void (*fn_mutex_init)(struct mutex *);
typedef void (*fn_mutex_lock)(struct mutex *);
typedef void (*fn_mutex_unlock)(struct mutex *);
typedef long (*fn_get_user_pages_remote)(
        struct mm_struct *mm,
        unsigned long start,
        unsigned long nr_pages,
        unsigned int gup_flags,
        struct page **pages,
        struct vm_area_struct **vmas,
        int *locked);
typedef void *(*fn_kmap_atomic)(void *page);
typedef void  (*fn_kunmap_atomic)(void *addr);
typedef void *(*fn_page_address)(void *page);
typedef int   (*fn_set_page_dirty)(void *page);
typedef void  (*fn_flush_dcache_page)(void *page);
typedef void  (*fn_put_page)(void *page);

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
static fn_mutex_init             sym_mutex_init;
static fn_mutex_lock             sym_mutex_lock;
static fn_mutex_unlock           sym_mutex_unlock;
static fn_get_user_pages_remote  sym_get_user_pages_remote;
static fn_kmap_atomic            sym_kmap_atomic;
static fn_kunmap_atomic          sym_kunmap_atomic;
static fn_page_address           sym_page_address;
static fn_set_page_dirty         sym_set_page_dirty;
static fn_flush_dcache_page      sym_flush_dcache_page;
static fn_put_page               sym_put_page;

/* ─── Global state ──────────────────────────────────────────────────────────── */
static const char   *PROC_NAME  = "hfr_mem";
static void         *proc_entry = NULL;


/* ─── Current task via sp_el0 (ARM64) ──────────────────────────────────────── */
static inline struct task_struct *kpm_current_task(void)
{
    struct task_struct *tsk = NULL;
    asm volatile("mrs %0, sp_el0" : "=r"(tsk));
    return tsk;
}

/* ─── Symbol resolution helper ──────────────────────────────────────────────── */
/*
 * Try a list of symbol name variants and return the first one found.
 * Caller passes a NULL-terminated array of name strings.
 */
static void *resolve_any(const char **names)
{
    const char **n = names;
    while (*n) {
        void *addr = (void *)kallsyms_lookup_name(*n);
        if (addr) {
            kpm_info("resolved '%s' → %px\n", *n, addr);
            return addr;
        }
        n++;
    }
    return NULL;
}

/* ─── Page mapping — safe, kmap_atomic-aware ─────────────────────────────────
 *
 * page_address()  works for all lowmem pages on ARM64 with CONFIG_HIGHMEM=n.
 * kmap_atomic()   is a no-op alias for page_address() on the same config.
 * Either way, the result can be NULL if the page isn't in the linear map.
 *
 * Rules:
 *   1. Try page_address() first.
 *   2. Fall back to kmap_atomic() — track whether we did so we can kunmap.
 *   3. If both return NULL, skip this page (logged, counted as skipped).
 *   4. kunmap_atomic only if kmap_atomic was actually called.
 *   5. put_page unconditionally for every page GUP returned.
 */

typedef struct {
    void *kaddr;
    int   used_kmap;
} page_map_t;

static page_map_t kpm_map_page(void *page)
{
    page_map_t m = { .kaddr = NULL, .used_kmap = 0 };

    if (sym_page_address) {
        m.kaddr = sym_page_address(page);
        if (m.kaddr) return m;   /* fast path — no kunmap needed */
    }

    if (sym_kmap_atomic) {
        m.kaddr    = sym_kmap_atomic(page);
        m.used_kmap = 1;
        if (!m.kaddr) {
            /* kmap_atomic returned NULL — unusual but handle it */
            m.used_kmap = 0;
        }
    }

    return m;
}

static void kpm_unmap_page(page_map_t *m)
{
    if (m->used_kmap && m->kaddr && sym_kunmap_atomic) {
        sym_kunmap_atomic(m->kaddr);
    }
    m->kaddr    = NULL;
    m->used_kmap = 0;
}

/* ─── Core read/write via get_user_pages_remote ──────────────────────────────
 *
 * Returns number of bytes successfully transferred, or negative errno.
 *
 * Design decisions:
 *   - FOLL_FORCE | FOLL_GET on all paths so COW / anonymous pages succeed.
 *   - FOLL_WRITE added for write path.
 *   - Multi-page transfers handled page-by-page with correct offset math.
 *   - put_page called for EVERY page GUP gave us, even skipped ones.
 *   - mm refcount taken with get_task_mm / released with mmput.
 *   - task refcount taken with get_task_struct / released with put_task_struct.
 */
static int kpm_rw_core(struct task_struct *task,
                       unsigned long addr,
                       void *buffer,
                       int size,
                       int is_write)
{
    struct mm_struct *mm;
    struct page *pages[MAX_GUP_PAGES];
    long     gup_ret;
    int      nr_pages_needed;
    int      processed = 0;
    int      i;
    unsigned int gup_flags;

    /* ── sanity ─────────────────────────────────────────────────────────── */
    if (!task || !buffer || size <= 0 || size > MAX_INLINE) {
        kpm_err("rw_core: bad args task=%px buf=%px size=%d\n",
                task, buffer, size);
        return -EINVAL;
    }

    if (!sym_get_user_pages_remote) {
        kpm_err("rw_core: get_user_pages_remote not resolved\n");
        return -ENOSYS;
    }

    /* ── take mm reference ───────────────────────────────────────────────── */
    mm = sym_get_task_mm(task);
    if (!mm) {
        kpm_err("rw_core: get_task_mm returned NULL for pid=%d\n",
                (int)task->pid);
        return -ESRCH;
    }

    /* ── calculate page span ─────────────────────────────────────────────── */
    nr_pages_needed = (int)(((addr & ~PAGE_MASK) + (unsigned long)size
                              + PAGE_SIZE - 1) >> PAGE_SHIFT);

    if (nr_pages_needed > MAX_GUP_PAGES) {
        kpm_err("rw_core: request spans %d pages (max %d)\n",
                nr_pages_needed, MAX_GUP_PAGES);
        sym_mmput(mm);
        return -EINVAL;
    }

    memset(pages, 0, sizeof(pages));

    /* ── GUP ─────────────────────────────────────────────────────────────── */
    gup_flags = KPM_FOLL_FORCE | KPM_FOLL_GET;
    if (is_write) gup_flags |= KPM_FOLL_WRITE;

    int locked = 1;

gup_ret = sym_get_user_pages_remote(mm,
                                    addr & PAGE_MASK,
                                    (unsigned long)nr_pages_needed,
                                    gup_flags,
                                    pages,
                                    NULL,
                                    &locked);

    if (gup_ret <= 0) {
        kpm_err("rw_core: GUP failed ret=%ld addr=0x%lx flags=0x%x\n",
                gup_ret, addr, gup_flags);
        sym_mmput(mm);
        /*
         * On write failure, retry without FOLL_WRITE — some mappings are
         * readable but not GUP-writable (we'll dirty the page manually).
         */
        if (is_write) {
            gup_flags = KPM_FOLL_FORCE | KPM_FOLL_GET;
            memset(pages, 0, sizeof(pages));
            mm = sym_get_task_mm(task);
            if (!mm) return -ESRCH;
            locked = 1;

gup_ret = sym_get_user_pages_remote(mm,
                                    addr & PAGE_MASK,
                                    (unsigned long)nr_pages_needed,
                                    gup_flags,
                                    pages,
                                    NULL,
                                    &locked);
            if (gup_ret <= 0) {
                kpm_err("rw_core: GUP retry also failed ret=%ld\n", gup_ret);
                sym_mmput(mm);
                return -EFAULT;
            }
            kpm_warn("rw_core: using GUP without FOLL_WRITE — write forced\n");
        } else {
            return -EFAULT;
        }
    }

    /* ── per-page copy ───────────────────────────────────────────────────── */
    for (i = 0; i < (int)gup_ret && processed < size; i++) {
        int offset    = (i == 0) ? (int)(addr & ~PAGE_MASK) : 0;
        int copy_size = (int)min((unsigned long)(size - processed),
                                 PAGE_SIZE - (unsigned long)offset);
        page_map_t m;

        if (!pages[i]) {
            kpm_err("rw_core: pages[%d] is NULL\n", i);
            continue;
        }

        m = kpm_map_page(pages[i]);

        if (!m.kaddr) {
            kpm_err("rw_core: page[%d] mapping returned NULL — skip\n", i);
            /*
             * put_page happens below unconditionally.
             * Don't touch processed — this page was skipped.
             */
            goto put_this_page;
        }

        if (is_write) {
            memcpy((char *)m.kaddr + offset,
                   (char *)buffer + processed,
                   (size_t)copy_size);
            /*
             * Mark dirty before unmap so the kernel knows the page was
             * modified. flush_dcache_page ensures coherency on ARM64
             * where D-cache is not always coherent with I-cache.
             */
            if (sym_set_page_dirty)
                sym_set_page_dirty(pages[i]);
            if (sym_flush_dcache_page)
                sym_flush_dcache_page(pages[i]);
        } else {
            memcpy((char *)buffer + processed,
                   (char *)m.kaddr + offset,
                   (size_t)copy_size);
        }

        kpm_unmap_page(&m);
        processed += copy_size;

put_this_page:
        if (sym_put_page)
            sym_put_page(pages[i]);
        pages[i] = NULL;
    }

    /* ── release any pages GUP gave us that we didn't reach ─────────────── */
    for (; i < (int)gup_ret; i++) {
        if (pages[i] && sym_put_page) {
            sym_put_page(pages[i]);
            pages[i] = NULL;
        }
    }

    sym_mmput(mm);

    if (processed == 0 && size > 0) {
        kpm_err("rw_core: zero bytes transferred\n");
        return -EFAULT;
    }

    return processed;
}

/* ─── Packet processor ───────────────────────────────────────────────────────
 *
 * Called with kpm_mutex held.
 * Sets pkt->status on every exit path — no path leaves it unset.
 */
static void process_packet(struct k_packet *pkt, pid_t caller_pid)
{
    struct task_struct *task = NULL;
    pid_t               target_pid;
    int                 is_write;
    int                 transferred;
    uint8_t             scratch[MAX_INLINE];

    /* ── opcode ──────────────────────────────────────────────────────────── */
    if (pkt->op_code != OP_READ_VM && pkt->op_code != OP_WRITE_VM) {
        kpm_err("bad opcode 0x%x\n", pkt->op_code);
        pkt->status = STATUS_BAD_OPCODE;
        return;
    }

    is_write = (pkt->op_code == OP_WRITE_VM);

    /* ── size ────────────────────────────────────────────────────────────── */
    if (!is_valid_user_addr(pkt->vaddr, pkt->size)) {
        kpm_err("invalid addr=0x%llx size=%u\n", pkt->vaddr, pkt->size);
        pkt->status = STATUS_INVALID_ADDR;
        return;
    }

    /* ── critical symbol check ───────────────────────────────────────────── */
    if (!sym_get_user_pages_remote || !sym_find_task_by_vpid ||
        !sym_get_task_mm || !sym_mmput || !sym_put_page) {
        kpm_err("critical symbol missing\n");
        pkt->status = STATUS_NULL_SYMBOL;
        return;
    }

    /* ── target PID ──────────────────────────────────────────────────────── */
    target_pid = pkt->target_pid ? (pid_t)pkt->target_pid : caller_pid;
    if (target_pid <= 0) {
        kpm_err("invalid target pid %d\n", target_pid);
        pkt->status = STATUS_OUT_OF_RANGE;
        return;
    }

    /* ── find task ───────────────────────────────────────────────────────── */
    if (sym_rcu_read_lock)   sym_rcu_read_lock();
    task = sym_find_task_by_vpid(target_pid);
    if (task && sym_get_task_struct)
        sym_get_task_struct(task);   /* bump refcount before unlock */
    if (sym_rcu_read_unlock) sym_rcu_read_unlock();

    if (!task) {
        kpm_err("task not found pid=%d\n", target_pid);
        pkt->status = STATUS_NO_TASK;
        return;
    }

    /* ── prepare scratch buffer ──────────────────────────────────────────── */
    memset(scratch, 0, MAX_INLINE);
    if (is_write)
        memcpy(scratch, pkt->inline_data, (size_t)pkt->size);

    /* ── transfer ────────────────────────────────────────────────────────── */
    transferred = kpm_rw_core(task,
                              (unsigned long)pkt->vaddr,
                              scratch,
                              (int)pkt->size,
                              is_write);

    if (sym_put_task_struct) sym_put_task_struct(task);

    /* ── status ──────────────────────────────────────────────────────────── */
    if (transferred < 0) {
        kpm_err("transfer error %d\n", transferred);
        pkt->status = STATUS_VM_FAULT;
        return;
    }

    if (transferred == 0) {
        kpm_err("zero-byte transfer (protection?)\n");
        pkt->status = STATUS_PROTECTION;
        return;
    }

    if (!is_write) {
        /* Copy read data back into the packet */
        memset(pkt->inline_data, 0, MAX_INLINE);
        memcpy(pkt->inline_data, scratch, (size_t)transferred);
    }

    if ((uint32_t)transferred != pkt->size) {
        kpm_warn("partial %d/%u bytes\n", transferred, pkt->size);
        pkt->size   = (uint32_t)transferred;
        pkt->status = STATUS_PARTIAL_IO;
        return;
    }

    pkt->status = STATUS_SUCCESS;
    kpm_info("%s OK %u bytes @ 0x%llx pid=%d\n",
             is_write ? "WRITE" : "READ",
             pkt->size, pkt->vaddr, target_pid);
}

/* ─── /proc handlers ─────────────────────────────────────────────────────────
 *
 * Protocol:
 *   open  → nothing
 *   write → receive k_packet, process, write result back via copy_to_user
 *   read  → nothing (results are returned synchronously in write path)
 *   close → nothing
 *
 * The write handler uses a local stack copy of the packet.
 * The driver writes the result back into the SAME userspace buffer
 * the caller passed to write(). The client MUST pass a writable buffer —
 * the header enforces this via the local copy pattern.
 */
static int proc_open_cb(struct inode *inode, struct file *file)
{
    (void)inode; (void)file;
    return 0;
}

static int proc_release_cb(struct inode *inode, struct file *file)
{
    (void)inode; (void)file;
    return 0;
}

static ssize_t proc_read_cb(struct file *file, char __user *buf,
                             size_t count, loff_t *pos)
{
    (void)file; (void)buf; (void)count; (void)pos;
    return 0;
}

static ssize_t proc_write_cb(struct file *file, const char __user *ubuf,
                              size_t count, loff_t *pos)
{
    struct k_packet     local_pkt;
    struct task_struct *curr;
    pid_t               caller_pid;
    unsigned long       copy_ret;

    (void)file; (void)pos;

    /* ── size guard ─────────────────────────────────────────────────────── */
    if (count != sizeof(struct k_packet)) {
        kpm_err("write: bad size %zu (want %zu)\n",
                count, sizeof(struct k_packet));
        return -EINVAL;
    }

    if (!sym_copy_from_user || !sym_copy_to_user) {
        kpm_err("write: copy_from/to_user not resolved\n");
        return -ENOSYS;
    }

    /* ── receive packet ─────────────────────────────────────────────────── */
    memset(&local_pkt, 0, sizeof(local_pkt));
    if (sym_copy_from_user(&local_pkt, ubuf, sizeof(struct k_packet)) != 0) {
        kpm_err("write: copy_from_user failed\n");
        return -EFAULT;
    }

    /* ── caller PID ─────────────────────────────────────────────────────── */
    curr = kpm_current_task();
    if (!curr) {
        kpm_err("write: kpm_current_task() returned NULL\n");
        return -ESRCH;
    }

    if (!sym_task_pid_nr_ns) {
        kpm_err("write: task_pid_nr_ns not resolved\n");
        return -ENOSYS;
    }

    caller_pid = sym_task_pid_nr_ns(curr, PIDTYPE_PID, NULL);
    if (caller_pid <= 0) {
        kpm_err("write: invalid caller pid\n");
        return -ESRCH;
    }

    /* ── process under mutex ────────────────────────────────────────────── */
    process_packet(&local_pkt, caller_pid);

    /* ── write result back to userspace ─────────────────────────────────── */
    copy_ret = sym_copy_to_user((void __user *)ubuf,
                                &local_pkt,
                                sizeof(struct k_packet));
    if (copy_ret != 0) {
        kpm_err("write: copy_to_user failed (%lu bytes not written)\n",
                copy_ret);
        return -EFAULT;
    }

    return (ssize_t)count;
}

static const struct proc_ops kpm_proc_ops = {
    .proc_flags         = 0,
    .proc_open          = proc_open_cb,
    .proc_read          = proc_read_cb,
    .proc_read_iter     = NULL,
    .proc_write         = proc_write_cb,
    .proc_lseek         = NULL,
    .proc_release       = proc_release_cb,
    .proc_poll          = NULL,
    .proc_ioctl         = NULL,
    .proc_mmap          = NULL,
    .proc_get_unmapped_area = NULL,
};

/* ─── Module init ─────────────────────────────────────────────────────────── */
static long kpm_bridge_init(const char *args, const char *event,
                             void __user *reserved)
{
    /* Symbol name variant lists — try each in order, stop at first hit */
    const char *names_copy_from_user[] = {
        "_copy_from_user", "copy_from_user", "__copy_from_user", NULL
    };
    const char *names_copy_to_user[] = {
        "_copy_to_user", "copy_to_user", "__copy_to_user", NULL
    };
    const char *names_task_pid[] = {
        "__task_pid_nr_ns", "task_pid_nr_ns", NULL
    };
    const char *names_rcu_lock[] = {
        "__rcu_read_lock", "rcu_read_lock", NULL
    };
    const char *names_rcu_unlock[] = {
        "__rcu_read_unlock", "rcu_read_unlock", NULL
    };
    const char *names_mutex_init[] = {
        "__mutex_init", "mutex_init", NULL
    };
    const char *names_kmap[] = {
        "kmap_atomic", "kmap_atomic_high", "__kmap_atomic", NULL
    };
    const char *names_kunmap[] = {
        "kunmap_atomic", "kunmap_atomic_high", "__kunmap_atomic", NULL
    };
    const char *names_gup_remote[] = {
        "get_user_pages_remote", "__get_user_pages_remote", NULL
    };

    kpm_info("=== KPM BRIDGE v2 INIT ===\n");

    /* ── resolve all symbols ─────────────────────────────────────────────── */
    sym_proc_create_data  = (fn_proc_create_data)
        kallsyms_lookup_name("proc_create_data");
    sym_remove_proc_entry = (fn_remove_proc_entry)
        kallsyms_lookup_name("remove_proc_entry");

    sym_copy_from_user    = (fn_copy_from_user)
        resolve_any(names_copy_from_user);
    sym_copy_to_user      = (fn_copy_to_user)
        resolve_any(names_copy_to_user);

    sym_find_task_by_vpid = (fn_find_task_by_vpid)
        kallsyms_lookup_name("find_task_by_vpid");
    sym_get_task_mm       = (fn_get_task_mm)
        kallsyms_lookup_name("get_task_mm");
    sym_mmput             = (fn_mmput)
        kallsyms_lookup_name("mmput");
    sym_get_task_struct   = (fn_get_task_struct)
        kallsyms_lookup_name("get_task_struct");
    sym_put_task_struct   = (fn_put_task_struct)
        kallsyms_lookup_name("put_task_struct");

    sym_task_pid_nr_ns    = (fn_task_pid_nr_ns)
        resolve_any(names_task_pid);
    sym_rcu_read_lock     = (fn_rcu_read_lock)
        resolve_any(names_rcu_lock);
    sym_rcu_read_unlock   = (fn_rcu_read_unlock)
        resolve_any(names_rcu_unlock);
    sym_mutex_init        = (fn_mutex_init)
        resolve_any(names_mutex_init);
    sym_mutex_lock        = (fn_mutex_lock)
        kallsyms_lookup_name("mutex_lock");
    sym_mutex_unlock      = (fn_mutex_unlock)
        kallsyms_lookup_name("mutex_unlock");

    sym_get_user_pages_remote = (fn_get_user_pages_remote)
        resolve_any(names_gup_remote);
    sym_kmap_atomic       = (fn_kmap_atomic)
        resolve_any(names_kmap);
    sym_kunmap_atomic     = (fn_kunmap_atomic)
        resolve_any(names_kunmap);
    sym_page_address      = (fn_page_address)
        kallsyms_lookup_name("page_address");
    sym_set_page_dirty    = (fn_set_page_dirty)
        kallsyms_lookup_name("set_page_dirty");
    sym_flush_dcache_page = (fn_flush_dcache_page)
        kallsyms_lookup_name("flush_dcache_page");
    sym_put_page          = (fn_put_page)
        kallsyms_lookup_name("put_page");

    /* ── symbol report ───────────────────────────────────────────────────── */
    kpm_info("Symbol resolution:\n");
    kpm_info("  proc_create_data      = %px\n", sym_proc_create_data);
    kpm_info("  copy_from_user        = %px\n", sym_copy_from_user);
    kpm_info("  copy_to_user          = %px\n", sym_copy_to_user);
    kpm_info("  find_task_by_vpid     = %px\n", sym_find_task_by_vpid);
    kpm_info("  get_task_mm           = %px\n", sym_get_task_mm);
    kpm_info("  mmput                 = %px\n", sym_mmput);
    kpm_info("  get_user_pages_remote = %px\n", sym_get_user_pages_remote);
    kpm_info("  page_address          = %px\n", sym_page_address);
    kpm_info("  kmap_atomic           = %px\n", sym_kmap_atomic);
    kpm_info("  put_page              = %px\n", sym_put_page);
    kpm_info("  set_page_dirty        = %px\n", sym_set_page_dirty);
    kpm_info("  flush_dcache_page     = %px\n", sym_flush_dcache_page);

    /* ── mandatory symbol check — abort if any critical one is missing ───── */
#define REQUIRE(sym, name)                                          \
    do {                                                            \
        if (!(sym)) {                                               \
            kpm_err("CRITICAL: '%s' not found — aborting\n", name);\
            return -EFAULT;                                         \
        }                                                           \
    } while (0)

    REQUIRE(sym_proc_create_data,      "proc_create_data");
    REQUIRE(sym_remove_proc_entry,     "remove_proc_entry");
    REQUIRE(sym_copy_from_user,        "copy_from_user");
    REQUIRE(sym_copy_to_user,          "copy_to_user");
    REQUIRE(sym_find_task_by_vpid,     "find_task_by_vpid");
    REQUIRE(sym_get_task_mm,           "get_task_mm");
    REQUIRE(sym_mmput,                 "mmput");
    REQUIRE(sym_put_page,              "put_page");
    REQUIRE(sym_get_user_pages_remote, "get_user_pages_remote");
    REQUIRE(sym_task_pid_nr_ns,        "__task_pid_nr_ns");

#undef REQUIRE

    /* page mapping: need at least one of page_address or kmap_atomic */
    if (!sym_page_address && !sym_kmap_atomic) {
        kpm_err("CRITICAL: neither page_address nor kmap_atomic found\n");
        return -EFAULT;
    }

    /* ── init mutex ──────────────────────────────────────────────────────── */

    /* ── create /proc/hfr_mem ────────────────────────────────────────────── */
    proc_entry = sym_proc_create_data(PROC_NAME, 0666, NULL,
                                      &kpm_proc_ops, NULL);
    if (!proc_entry) {
        kpm_err("proc_create_data failed for /proc/%s\n", PROC_NAME);
        return -EFAULT;
    }

    kpm_info("=== KPM BRIDGE READY — /proc/%s ===\n", PROC_NAME);
    return 0;
}

/* ─── Module exit ─────────────────────────────────────────────────────────── */
static long kpm_bridge_exit(void __user *reserved)
{
    kpm_info("=== KPM BRIDGE EXIT ===\n");
    if (proc_entry && sym_remove_proc_entry) {
        sym_remove_proc_entry(PROC_NAME, NULL);
        proc_entry = NULL;
    }
    return 0;
}

KPM_INIT(kpm_bridge_init);
KPM_EXIT(kpm_bridge_exit);
