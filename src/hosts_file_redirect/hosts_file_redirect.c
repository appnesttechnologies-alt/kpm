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
#include <linux/pid.h>
#include <linux/slab.h>
#include <linux/version.h>
#include <linux/fs.h>


KPM_NAME("hosts_file_redirect_shm");
KPM_VERSION(HFR_VERSION);
KPM_LICENSE("GPL v2");
KPM_AUTHOR("Surajit");
KPM_DESCRIPTION("KPM shared-memory memory bridge via char device + mmap ring buffer") ;

#define HFR_DEBUG
#ifdef HFR_DEBUG
#define kpm_info(fmt, ...) pr_info("HFR_SHM: " fmt, ##__VA_ARGS__)
#define kpm_err(fmt, ...)  pr_err("HFR_SHM: " fmt, ##__VA_ARGS__)
#else
#define kpm_info(fmt, ...)
#define kpm_err(fmt, ...)
#endif

#define MAX_INLINE       256
#define OP_READ_VM       0x2000
#define OP_WRITE_VM      0x3000

#define STATUS_SUCCESS      0x0000
#define STATUS_INVALID_SIZE 0x1005
#define STATUS_OUT_OF_RANGE 0x1006
#define STATUS_BAD_OPCODE   0x1007
#define STATUS_NO_TASK      0x1008
#define STATUS_NO_MM        0x1009
#define STATUS_VM_FAULT     0x100A
#define STATUS_PARTIAL_IO   0x100B
#define STATUS_PROTECTION   0x100C
#define STATUS_INVALID_ADDR 0x100D
#define STATUS_NULL_SYMBOL  0x100E
#define STATUS_RING_EMPTY   0x1010
#define STATUS_RING_FULL    0x1011

#define HFR_FOLL_WRITE      0x01
#define HFR_RING_ORDER      2
#define HFR_RING_BYTES      (4096UL << HFR_RING_ORDER)
#define HFR_RING_MAGIC      0x48465231u
#define HFR_RING_SLOTS      32
#define HFR_IOCTL_SUBMIT 0x48465200u



struct mutex {
    void *owner;
    int count;
    void *wait_lock;
    void *wait_list;
};

struct hfr_packet {
    uint32_t seq;
    uint32_t op_code;
    uint32_t target_pid;
    uint32_t size;
    uint64_t vaddr;
    uint32_t status;
    uint32_t reserved;
    uint8_t inline_data[MAX_INLINE];
} __attribute__((aligned(8), packed));

struct hfr_ring {
    uint32_t magic;
    uint32_t version;
    uint32_t req_head;
    uint32_t req_tail;
    uint32_t rsp_head;
    uint32_t rsp_tail;
    uint32_t slots;
    uint32_t elem_size;
    struct hfr_packet req[HFR_RING_SLOTS];
    struct hfr_packet rsp[HFR_RING_SLOTS];
} __attribute__((aligned(4096)));

struct hfr_ctx {
    struct hfr_ring *ring;
    void *ring_pages;
    struct mutex lock;
    int major;
    int stop;
};

static struct hfr_ctx g_ctx;


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
typedef int (*__register_chrdev_t)(
    unsigned int major,
    unsigned int baseminor,
    unsigned int count,
    const char *name,
    const struct file_operations *fops
);

typedef void (*__unregister_chrdev_t)(
    unsigned int major,
    unsigned int baseminor,
    unsigned int count,
    const char *name
);
typedef unsigned long (*virt_to_phys_t)(volatile void *address);
typedef int (*remap_pfn_range_t)(struct vm_area_struct *, unsigned long, unsigned long, unsigned long, unsigned long);
typedef void *(*__get_free_pages_t)(unsigned int, unsigned int);
typedef void (*free_pages_t)(unsigned long, unsigned int);

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
static __register_chrdev_t     p___register_chrdev;
static __unregister_chrdev_t   p___unregister_chrdev;
static virt_to_phys_t        p_virt_to_phys;
static remap_pfn_range_t     p_remap_pfn_range;
static __get_free_pages_t    p___get_free_pages;
static free_pages_t          p_free_pages;

static inline struct task_struct *hfr_get_current(void)
{
    struct task_struct *tsk;
    asm volatile("mrs %0, sp_el0" : "=r" (tsk));
    return tsk;
}

static inline int is_valid_user_address(uint64_t addr)
{
    if (!addr) return 0;
    if (addr >= (1ULL << 63)) return 0;
    return 1;
}

static inline uint32_t ring_next(uint32_t idx)
{
    return (idx + 1u) % HFR_RING_SLOTS;
}

static void process_packet(struct hfr_packet *pkt, pid_t caller_pid)
{
    struct task_struct *task = NULL;
    struct mm_struct *mm = NULL;
    pid_t target_pid;
    int transferred;
    unsigned int gup_flags;
    int is_write_op = 0;
    uint8_t temp_buffer[MAX_INLINE];

    if (pkt->op_code != OP_READ_VM && pkt->op_code != OP_WRITE_VM) {
        pkt->status = STATUS_BAD_OPCODE;
        return;
    }
    if (!pkt->size || pkt->size > MAX_INLINE) {
        pkt->status = STATUS_INVALID_SIZE;
        return;
    }
    if (!is_valid_user_address(pkt->vaddr)) {
        pkt->status = STATUS_INVALID_ADDR;
        return;
    }
    if (!p_access_process_vm || !p_find_task_by_vpid || !p_get_task_mm || !p_mmput) {
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
        if (p_put_task_struct && task) p_put_task_struct(task);
        return;
    }

    is_write_op = (pkt->op_code == OP_WRITE_VM);
    memset(temp_buffer, 0, sizeof(temp_buffer));
    if (is_write_op) {
        memcpy(temp_buffer, pkt->inline_data, pkt->size);
        gup_flags = HFR_FOLL_WRITE;
    } else {
        gup_flags = 0;
    }

    transferred = p_access_process_vm(task, (unsigned long)pkt->vaddr, temp_buffer, (int)pkt->size, gup_flags);

    p_mmput(mm);
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
    pkt->status = STATUS_SUCCESS;
}

static int hfr_open(struct inode *inode, struct file *file) { return 0; }
static int hfr_release(struct inode *inode, struct file *file) { return 0; }
static ssize_t hfr_read(struct file *file, char __user *buf, size_t count, loff_t *ppos) { return 0; }

static ssize_t hfr_write(struct file *file, const char __user *buf, size_t count, loff_t *ppos)
{
    struct hfr_packet pkt;
    pid_t caller_pid;
    struct task_struct *curr_task;
    uint32_t next_rsp;

    if (count != sizeof(pkt)) return -EINVAL;
    if (!p_copy_from_user || !p_copy_to_user) return -EFAULT;
    if (p_copy_from_user(&pkt, buf, sizeof(pkt)) != 0) return -EFAULT;

    curr_task = hfr_get_current();
    if (!curr_task || !p_task_pid_nr_ns) return -ESRCH;
    caller_pid = p_task_pid_nr_ns(curr_task, PIDTYPE_PID, NULL);
    if (caller_pid <= 0) return -ESRCH;

    if (p_mutex_lock) p_mutex_lock(&g_ctx.lock);
    process_packet(&pkt, caller_pid);
    if (g_ctx.ring) {
        next_rsp = ring_next(g_ctx.ring->rsp_head);
        if (next_rsp != g_ctx.ring->rsp_tail) {
            memcpy(&g_ctx.ring->rsp[g_ctx.ring->rsp_head], &pkt, sizeof(pkt));
            g_ctx.ring->rsp_head = next_rsp;
        }
    }
    if (p_mutex_unlock) p_mutex_unlock(&g_ctx.lock);

    if (p_copy_to_user((void __user *)buf, &pkt, sizeof(pkt)) != 0) return -EFAULT;
    return (ssize_t)count;
}

static long hfr_ioctl(struct file *file, unsigned int cmd, unsigned long arg)
{
    struct hfr_packet pkt;
    pid_t caller_pid;
    struct task_struct *curr_task;
    uint32_t next_rsp;

    if (!p_copy_from_user || !p_copy_to_user) return -EFAULT;
    if (cmd != HFR_IOCTL_SUBMIT) return -EINVAL;
    if (p_copy_from_user(&pkt, (void __user *)arg, sizeof(pkt)) != 0) return -EFAULT;

    curr_task = hfr_get_current();
    if (!curr_task || !p_task_pid_nr_ns) return -ESRCH;
    caller_pid = p_task_pid_nr_ns(curr_task, PIDTYPE_PID, NULL);
    if (caller_pid <= 0) return -ESRCH;

    if (p_mutex_lock) p_mutex_lock(&g_ctx.lock);
    process_packet(&pkt, caller_pid);
    if (g_ctx.ring) {
        next_rsp = ring_next(g_ctx.ring->rsp_head);
        if (next_rsp != g_ctx.ring->rsp_tail) {
            memcpy(&g_ctx.ring->rsp[g_ctx.ring->rsp_head], &pkt, sizeof(pkt));
            g_ctx.ring->rsp_head = next_rsp;
        }
    }
    if (p_mutex_unlock) p_mutex_unlock(&g_ctx.lock);

    if (p_copy_to_user((void __user *)arg, &pkt, sizeof(pkt)) != 0) return -EFAULT;
    return 0;
}

static int hfr_mmap(struct file *file, struct vm_area_struct *vma)
{
    unsigned long phys;
    unsigned long size = HFR_RING_BYTES;
    if (!g_ctx.ring || !p_virt_to_phys || !p_remap_pfn_range) return -EFAULT;
    phys = p_virt_to_phys((volatile void *)g_ctx.ring);
    return p_remap_pfn_range(vma, 0, phys >> 12, size, 0);
}

static const struct file_operations hfr_fops = {
    .owner = 0,
    .llseek = 0,
    .read = hfr_read,
    .write = hfr_write,
    .unlocked_ioctl = hfr_ioctl,
    .compat_ioctl = hfr_ioctl,
    .mmap = hfr_mmap,
    .poll = 0,
    .open = hfr_open,
    .release = hfr_release,
};

static void hfr_ring_init(struct hfr_ring *ring)
{
    memset(ring, 0, HFR_RING_BYTES);
    ring->magic = HFR_RING_MAGIC;
    ring->version = 1;
    ring->slots = HFR_RING_SLOTS;
    ring->elem_size = sizeof(struct hfr_packet);
}

static long hfr_memory_init(const char *args, const char *event, void __user *reserved)
{
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
    p___register_chrdev = (__register_chrdev_t)kallsyms_lookup_name("__register_chrdev");
p___unregister_chrdev = (__unregister_chrdev_t)kallsyms_lookup_name("__unregister_chrdev");
    p_virt_to_phys = (virt_to_phys_t)kallsyms_lookup_name("__virt_to_phys");
    if (!p_virt_to_phys) p_virt_to_phys = (virt_to_phys_t)kallsyms_lookup_name("virt_to_phys");
    p_remap_pfn_range = (remap_pfn_range_t)kallsyms_lookup_name("remap_pfn_range");
    p___get_free_pages = (__get_free_pages_t)kallsyms_lookup_name("__get_free_pages");
    p_free_pages = (free_pages_t)kallsyms_lookup_name("free_pages");

    if (!p_copy_from_user || !p_copy_to_user || !p_access_process_vm || !p_find_task_by_vpid ||
        !p_get_task_mm || !p_mmput || !p_task_pid_nr_ns || !p___get_free_pages || !p_free_pages) {
        kpm_err("critical symbol missing\n");
        return -EFAULT;
    }

    if (p_mutex_init) p_mutex_init(&g_ctx.lock);

    g_ctx.ring_pages = p___get_free_pages(0, HFR_RING_ORDER);
    if (!g_ctx.ring_pages) {
        kpm_err("ring alloc failed\n");
        return -ENOMEM;
    }
    g_ctx.ring = (struct hfr_ring *)g_ctx.ring_pages;
    hfr_ring_init(g_ctx.ring);

    if (p___register_chrdev) {
    g_ctx.major = p___register_chrdev(0, 0, 1, "hfr_mem_shm", &hfr_fops);
    if (g_ctx.major < 0) {
        kpm_err("register_chrdev failed: %d", g_ctx.major);
        p_free_pages((unsigned long)g_ctx.ring_pages, HFR_RING_ORDER);
        g_ctx.ring_pages = 0;
        g_ctx.ring = 0;
        return g_ctx.major;
    }
} else {
    p_free_pages((unsigned long)g_ctx.ring_pages, HFR_RING_ORDER);
    g_ctx.ring_pages = 0;
    g_ctx.ring = 0;
    kpm_err("__register_chrdev missing");
    return -EFAULT;
}

    kpm_info("initialized major=%d ring=%px size=%lu\n", g_ctx.major, g_ctx.ring, (unsigned long)HFR_RING_BYTES);
    return 0;
}

static long hfr_memory_exit(void __user *reserved)
{
    if (p___unregister_chrdev && g_ctx.major > 0)
    p___unregister_chrdev((unsigned int)g_ctx.major, 0, 1, "hfr_mem_shm");
    if (g_ctx.ring_pages && p_free_pages)
        p_free_pages((unsigned long)g_ctx.ring_pages, HFR_RING_ORDER);
    g_ctx.ring_pages = 0;
    g_ctx.ring = 0;
    g_ctx.major = 0;
    return 0;
}

KPM_INIT(hfr_memory_init);
KPM_EXIT(hfr_memory_exit);
