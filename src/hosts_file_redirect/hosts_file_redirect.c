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

KPM_NAME("hosts_file_redirect");
KPM_VERSION(HFR_VERSION);
KPM_LICENSE("GPL v2");
KPM_AUTHOR("Surajit");
KPM_DESCRIPTION("SAFE MODULE - NEVER CRASH");

#define HFR_DEBUG
#ifdef HFR_DEBUG
#define hfr_log(fmt, ...) pr_info("HFR: " fmt, ##__VA_ARGS__)
#define hfr_err(fmt, ...)  pr_err("HFR: " fmt, ##__VA_ARGS__)
#else
#define hfr_log(fmt, ...)
#define hfr_err(fmt, ...)
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
#define STATUS_NULL_SYMBOL    0x100E

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
typedef struct task_struct *(*find_task_by_vpid_t)(pid_t);
typedef struct mm_struct *(*get_task_mm_t)(struct task_struct *);
typedef void (*mmput_t)(struct mm_struct *);
typedef struct task_struct *(*get_task_struct_t)(struct task_struct *);
typedef void (*put_task_struct_t)(struct task_struct *);
typedef pid_t (*task_pid_nr_ns_t)(struct task_struct *, enum pid_type, struct pid_namespace *);

static proc_create_data_t    p_proc_create_data = NULL;
static remove_proc_entry_t   p_remove_proc_entry = NULL;
static copy_from_user_t      p_copy_from_user = NULL;
static copy_to_user_t        p_copy_to_user = NULL;
static find_task_by_vpid_t   p_find_task_by_vpid = NULL;
static get_task_mm_t         p_get_task_mm = NULL;
static mmput_t               p_mmput = NULL;
static get_task_struct_t     p_get_task_struct = NULL;
static put_task_struct_t     p_put_task_struct = NULL;
static task_pid_nr_ns_t      p_task_pid_nr_ns = NULL;

static const char *proc_filename = "hfr_mem";
static void       *proc_entry    = NULL;

static inline struct task_struct *hfr_get_current(void)
{
    struct task_struct *tsk;
    asm volatile("mrs %0, sp_el0" : "=r" (tsk));
    return tsk;
}

// SAFE function call - returns 0 if function pointer is NULL
#define SAFE_CALL(func, ...) (func ? func(__VA_ARGS__) : 0)
#define SAFE_CALL_PTR(func, ...) (func ? func(__VA_ARGS__) : NULL)

static void process_packet(struct k_packet *pkt, pid_t caller_pid)
{
    struct task_struct *task = NULL;
    struct mm_struct *mm = NULL;
    pid_t target_pid;
    uint8_t temp_buffer[MAX_INLINE];

    hfr_log(">>> op=0x%x pid=%u addr=0x%llx size=%u caller=%d",
             pkt->op_code, pkt->target_pid, pkt->vaddr, pkt->size, caller_pid);

    if (pkt->op_code != OP_READ_VM && pkt->op_code != OP_WRITE_VM) {
        pkt->status = STATUS_BAD_OPCODE;
        return;
    }
    if (!pkt->size || pkt->size > MAX_INLINE) {
        pkt->status = STATUS_INVALID_SIZE;
        return;
    }
    if (pkt->vaddr == 0 || pkt->vaddr >= (1ULL << 39)) {
        pkt->status = STATUS_INVALID_ADDR;
        return;
    }
    
    // Check all function pointers before using
    if (!p_find_task_by_vpid || !p_get_task_mm || !p_mmput) {
        hfr_err("Required symbols not available!");
        pkt->status = STATUS_NULL_SYMBOL;
        return;
    }

    target_pid = pkt->target_pid ? (pid_t)pkt->target_pid : caller_pid;
    if (target_pid <= 0) {
        pkt->status = STATUS_OUT_OF_RANGE;
        return;
    }

    // SAFE: find task
    task = SAFE_CALL_PTR(p_find_task_by_vpid, target_pid);
    hfr_log("find_task_by_vpid(%d) = %px", target_pid, task);
    
    if (!task) {
        pkt->status = STATUS_NO_TASK;
        return;
    }

    // SAFE: get mm
    if (p_get_task_struct)
        p_get_task_struct(task);
    
    mm = p_get_task_mm(task);
    hfr_log("get_task_mm = %px", mm);
    
    if (!mm) {
        pkt->status = STATUS_NO_MM;
        if (p_put_task_struct)
            p_put_task_struct(task);
        return;
    }

    // SKIP ALL PGD WALK - Just return dummy success for now
    hfr_log("mm is valid, but skipping PGD walk for safety");
    
    memset(temp_buffer, 0, MAX_INLINE);
    pkt->status = STATUS_SUCCESS;
    
    // Return empty data for read
    if (pkt->op_code == OP_READ_VM) {
        memset(pkt->inline_data, 0xAA, min(pkt->size, MAX_INLINE));
    }

    // Cleanup
    if (p_mmput)
        p_mmput(mm);
    if (p_put_task_struct)
        p_put_task_struct(task);
}

static int proc_open_handler(struct inode *inode, struct file *file) { return 0; }
static int proc_release_handler(struct inode *inode, struct file *file) { return 0; }
static ssize_t proc_read_handler(struct file *file, char __user *buffer, size_t count, loff_t *pos) { return 0; }

static ssize_t proc_write_handler(struct file *file, const char __user *buffer, size_t count, loff_t *pos)
{
    struct k_packet local_pkt;
    pid_t caller_pid;
    struct task_struct *curr_task;

    if (count != sizeof(struct k_packet)) return -EINVAL;
    if (!p_copy_from_user) return -EFAULT;
    if (p_copy_from_user(&local_pkt, buffer, sizeof(struct k_packet)) != 0) return -EFAULT;

    curr_task = hfr_get_current();
    if (!curr_task) return -ESRCH;
    if (!p_task_pid_nr_ns) return -EFAULT;

    caller_pid = p_task_pid_nr_ns(curr_task, PIDTYPE_PID, NULL);
    if (caller_pid <= 0) return -ESRCH;

    process_packet(&local_pkt, caller_pid);

    if (!p_copy_to_user) return -EFAULT;
    if (p_copy_to_user((void __user *)buffer, &local_pkt, sizeof(struct k_packet)) != 0) return -EFAULT;
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
    hfr_log("=== SAFE MODULE INIT ===");
    
    // Resolve symbols with NULL checks
    p_proc_create_data = (proc_create_data_t)kallsyms_lookup_name("proc_create_data");
    hfr_log("proc_create_data: %px", p_proc_create_data);
    
    p_remove_proc_entry = (remove_proc_entry_t)kallsyms_lookup_name("remove_proc_entry");
    p_copy_from_user = (copy_from_user_t)kallsyms_lookup_name("_copy_from_user");
    if (!p_copy_from_user) p_copy_from_user = (copy_from_user_t)kallsyms_lookup_name("copy_from_user");
    p_copy_to_user = (copy_to_user_t)kallsyms_lookup_name("_copy_to_user");
    if (!p_copy_to_user) p_copy_to_user = (copy_to_user_t)kallsyms_lookup_name("copy_to_user");
    
    p_find_task_by_vpid = (find_task_by_vpid_t)kallsyms_lookup_name("find_task_by_vpid");
    hfr_log("find_task_by_vpid: %px", p_find_task_by_vpid);
    
    p_get_task_mm = (get_task_mm_t)kallsyms_lookup_name("get_task_mm");
    hfr_log("get_task_mm: %px", p_get_task_mm);
    
    p_mmput = (mmput_t)kallsyms_lookup_name("mmput");
    hfr_log("mmput: %px", p_mmput);
    
    p_get_task_struct = (get_task_struct_t)kallsyms_lookup_name("get_task_struct");
    p_put_task_struct = (put_task_struct_t)kallsyms_lookup_name("put_task_struct");
    p_task_pid_nr_ns = (task_pid_nr_ns_t)kallsyms_lookup_name("__task_pid_nr_ns");
    hfr_log("task_pid_nr_ns: %px", p_task_pid_nr_ns);

    // Check critical symbols
    if (!p_proc_create_data) {
        hfr_err("proc_create_data not found!");
        return -EFAULT;
    }
    
    hfr_log("Available: find_task=%px get_task_mm=%px mmput=%px",
             p_find_task_by_vpid, p_get_task_mm, p_mmput);

    proc_entry = p_proc_create_data(proc_filename, 0666, NULL, &p_ops, NULL);
    if (!proc_entry) {
        hfr_err("proc_create FAILED");
        return -EFAULT;
    }

    hfr_log("=== /proc/%s CREATED - SAFE MODE ===", proc_filename);
    hfr_log("=== NO PGD WALK, NO CRASH! ===");
    return 0;
}

static long hfr_memory_exit(void __user *reserved)
{
    hfr_log("=== EXIT ===");
    if (proc_entry && p_remove_proc_entry)
        p_remove_proc_entry(proc_filename, NULL);
    return 0;
}

KPM_INIT(hfr_memory_init);
KPM_EXIT(hfr_memory_exit);
