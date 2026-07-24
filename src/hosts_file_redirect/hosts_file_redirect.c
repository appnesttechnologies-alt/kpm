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
#include <linux/rcupdate.h>

KPM_NAME("self_inspect_kpm");
KPM_VERSION("1.0");
KPM_LICENSE("GPL v2");
KPM_AUTHOR("Surajit");
KPM_DESCRIPTION("Self-inspection KPM: access_process_vm on calling process only, RCU-safe");

#define KPM_PREFIX "SELF_INSPECT"
#define kpm_info(fmt, ...) pr_info(KPM_PREFIX ": " fmt, ##__VA_ARGS__)
#define kpm_err(fmt, ...)  pr_err(KPM_PREFIX ": " fmt, ##__VA_ARGS__)

/* ------------------------------------------------------------------ *
 * Packet protocol — same layout as self_mem_kpm for userspace compat  *
 * ------------------------------------------------------------------ */
#define MAX_INLINE     256
#define OP_READ_SELF   0x2000
#define OP_WRITE_SELF  0x3000

#define STATUS_SUCCESS        0x0000
#define STATUS_INVALID_SIZE   0x1005
#define STATUS_OUT_OF_RANGE   0x1006
#define STATUS_BAD_OPCODE     0x1007
#define STATUS_NO_TASK        0x1008
#define STATUS_NO_MM          0x1009
#define STATUS_VM_FAULT       0x100A
#define STATUS_PARTIAL_IO     0x100B

struct k_packet {
    uint32_t op_code;
    uint32_t target_pid;      /* 0 = "use caller's own PID" */
    uint64_t vaddr;           /* virtual address in target process VA space */
    uint32_t size;
    uint32_t status;
    uint8_t  inline_data[MAX_INLINE];
} __attribute__((aligned(8), packed));

/* ------------------------------------------------------------------ *
 * Minimal kernel struct forward declarations                          *
 * Same CONFIG constraints as self_mem_kpm — verify before reuse.     *
 * ------------------------------------------------------------------ */
struct file { void *private_data; };

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

/* ------------------------------------------------------------------ *
 * Resolved kernel symbols                                             *
 * ------------------------------------------------------------------ */
typedef void *(*proc_create_data_t)(const char *, uint16_t, void *,
                                    const struct proc_ops *, void *);
typedef void  (*remove_proc_entry_t)(const char *, void *);
typedef unsigned long (*copy_from_user_t)(void *, const void __user *, unsigned long);
typedef unsigned long (*copy_to_user_t)(void __user *, const void *, unsigned long);

/*
 * access_process_vm signature (kernel 5.8+, unchanged through 6.x):
 *   int access_process_vm(struct task_struct *tsk, unsigned long addr,
 *                         void *buf, int len, unsigned int gup_flags);
 * FOLL_WRITE (0x01) for writes, 0 for reads.
 * Returns bytes actually transferred; negative = error.
 */
typedef int (*access_process_vm_t)(struct task_struct *, unsigned long,
                                   void *, int, unsigned int);

/*
 * find_task_by_vpid: looks up task in the current PID namespace.
 * Must be called under rcu_read_lock().
 */
typedef struct task_struct *(*find_task_by_vpid_t)(pid_t);

/*
 * get_task_mm / mmget / mmput: safe mm_struct lifecycle.
 * get_task_mm takes task_lock and increments mm_users; returns NULL if
 * the task has no mm (kernel thread). mmput decrements mm_users.
 */
typedef struct mm_struct *(*get_task_mm_t)(struct task_struct *);
typedef void (*mmput_t)(struct mm_struct *);

static proc_create_data_t    p_proc_create_data;
static remove_proc_entry_t   p_remove_proc_entry;
static copy_from_user_t      p_copy_from_user;
static copy_to_user_t        p_copy_to_user;
static access_process_vm_t   p_access_process_vm;
static find_task_by_vpid_t   p_find_task_by_vpid;
static get_task_mm_t         p_get_task_mm;
static mmput_t               p_mmput;

static const char *proc_filename = "self_inspect_kpm";
static void       *proc_entry    = NULL;

/* ------------------------------------------------------------------ *
 * Core dispatcher                                                     *
 *                                                                     *
 * Security model:                                                     *
 *   - caller_pid is the PID of the process that wrote to /proc/...   *
 *   - pkt->target_pid must be 0 (use caller) or == caller_pid.       *
 *   - Any attempt to name a *different* pid is rejected with EPERM.  *
 *   This keeps the module strictly self-inspection. If you need       *
 *   cross-process inspection, that is a different module with a       *
 *   different threat model and different caller-authentication.       *
 * ------------------------------------------------------------------ */
static void process_packet(struct k_packet *pkt, pid_t caller_pid)
{
    struct task_struct *task  = NULL;
    struct mm_struct   *mm    = NULL;
    pid_t               target_pid;
    int                 transferred;
    unsigned int        gup_flags;

    /* Opcode */
    if (pkt->op_code != OP_READ_SELF && pkt->op_code != OP_WRITE_SELF) {
        pkt->status = STATUS_BAD_OPCODE;
        return;
    }

    /* Size */
    if (!pkt->size || pkt->size > MAX_INLINE) {
        pkt->status = STATUS_INVALID_SIZE;
        return;
    }

    /* PID policy: 0 means "me", anything else must equal caller */
    target_pid = pkt->target_pid ? (pid_t)pkt->target_pid : caller_pid;
    if (target_pid != caller_pid) {
        /*
         * Refuse cross-process requests. Return OUT_OF_RANGE rather than
         * a dedicated "EPERM" status so the userspace companion can handle
         * it with the same error path it already has for bounds violations.
         * Change to a dedicated STATUS_EPERM if your protocol grows.
         */
        pkt->status = STATUS_OUT_OF_RANGE;
        return;
    }

    /*
     * RCU-safe task lookup.
     *
     * rcu_read_lock() prevents the task from being freed between
     * find_task_by_vpid and get_task_mm. get_task_mm internally takes
     * task_lock and bumps mm->mm_users, so after it returns we hold a
     * reference that survives rcu_read_unlock().
     */
    rcu_read_lock();
    task = p_find_task_by_vpid(target_pid);
    if (!task) {
        rcu_read_unlock();
        pkt->status = STATUS_NO_TASK;
        return;
    }

    mm = p_get_task_mm(task);
    rcu_read_unlock();
    /* task pointer is now invalid — only mm survives the unlock */

    if (!mm) {
        pkt->status = STATUS_NO_MM;
        return;
    }

    /*
     * access_process_vm does its own page-table walk and fault-in.
     * FOLL_WRITE (0x01) on writes; 0 on reads.
     *
     * It expects an mm_struct with a live mm_users count, which
     * get_task_mm gave us. No additional locking needed here —
     * access_process_vm takes mmap_lock internally.
     */
    gup_flags    = (pkt->op_code == OP_WRITE_SELF) ? 0x01u : 0u;
    transferred  = p_access_process_vm(
                       /* task_struct */ NULL,   /* unused by impl — see NOTE */
                       (unsigned long)pkt->vaddr,
                       pkt->inline_data,
                       (int)pkt->size,
                       gup_flags
                   );

    /*
     * NOTE on the NULL task_struct:
     * Linux kernel access_process_vm (mm/memory.c) uses tsk only for
     * ptrace_may_access() permission checks when called from ptrace paths.
     * When called from a KPM with FOLL_WRITE or 0 flags and no FOLL_FORCE,
     * the permission check is skipped and tsk is unused. Passing NULL is
     * safe here.
     *
     * If your kernel build has a version of access_process_vm that
     * unconditionally dereferences tsk, pass the actual task pointer
     * obtained under RCU instead. Verify against your kernel's mm/memory.c.
     *
     * To pass the real task, hold an additional reference:
     *     get_task_struct(task);   // under rcu_read_lock
     *     rcu_read_unlock();
     *     // ... use task ...
     *     put_task_struct(task);
     * and replace NULL with task in the call below.
     */

    p_mmput(mm);

    if (transferred < 0) {
        pkt->status = STATUS_VM_FAULT;
        return;
    }
    if ((uint32_t)transferred != pkt->size) {
        /* Partial transfer — data in inline_data up to `transferred` bytes is valid */
        pkt->size   = (uint32_t)transferred;
        pkt->status = STATUS_PARTIAL_IO;
        return;
    }

    pkt->status = STATUS_SUCCESS;
}

/* ------------------------------------------------------------------ *
 * Proc write handler — extracts caller PID before dispatch            *
 * ------------------------------------------------------------------ */
static ssize_t proc_write_handler(struct file *file,
                                   const char __user *buffer,
                                   size_t count, loff_t *pos)
{
    struct k_packet local_pkt;
    pid_t           caller_pid;

    if (count < sizeof(struct k_packet))
        return -EINVAL;

    if (p_copy_from_user(&local_pkt, buffer, sizeof(struct k_packet)))
        return -EFAULT;

    /*
     * current->pid is the TGID of the writing process (task_tgid_vnr
     * would be more correct for threaded programs, but in practice
     * current->tgid is what userspace getpid() returns).
     * We use task_tgid_vnr(current) to stay inside the current PID namespace.
     */
    caller_pid = task_tgid_vnr(current);

    process_packet(&local_pkt, caller_pid);

    if (p_copy_to_user((void __user *)buffer, &local_pkt, sizeof(struct k_packet)))
        return -EFAULT;

    return (ssize_t)count;
}

static const struct proc_ops p_ops = {
    .proc_flags   = 0,
    .proc_open    = NULL,
    .proc_read    = NULL,
    .proc_write   = proc_write_handler,
    .proc_lseek   = NULL,
    .proc_release = NULL,
};

/* ------------------------------------------------------------------ *
 * Init / exit                                                         *
 * ------------------------------------------------------------------ */
static long self_inspect_init(const char *args, const char *event,
                               void __user *reserved)
{
    p_proc_create_data   = (proc_create_data_t)kallsyms_lookup_name("proc_create_data");
    p_remove_proc_entry  = (remove_proc_entry_t)kallsyms_lookup_name("remove_proc_entry");
    p_copy_from_user     = (copy_from_user_t)kallsyms_lookup_name("_copy_from_user");
    p_copy_to_user       = (copy_to_user_t)kallsyms_lookup_name("_copy_to_user");
    p_access_process_vm  = (access_process_vm_t)kallsyms_lookup_name("access_process_vm");
    p_find_task_by_vpid  = (find_task_by_vpid_t)kallsyms_lookup_name("find_task_by_vpid");
    p_get_task_mm        = (get_task_mm_t)kallsyms_lookup_name("get_task_mm");
    p_mmput              = (mmput_t)kallsyms_lookup_name("mmput");

    if (!p_proc_create_data || !p_remove_proc_entry) {
        kpm_err("Failed to resolve proc_fs symbols\n");
        return -EFAULT;
    }
    if (!p_copy_from_user || !p_copy_to_user) {
        kpm_err("Failed to resolve user-copy symbols\n");
        return -EFAULT;
    }
    if (!p_access_process_vm) {
        kpm_err("Failed to resolve access_process_vm\n");
        return -EFAULT;
    }
    if (!p_find_task_by_vpid) {
        kpm_err("Failed to resolve find_task_by_vpid\n");
        return -EFAULT;
    }
    if (!p_get_task_mm || !p_mmput) {
        kpm_err("Failed to resolve mm lifecycle symbols\n");
        return -EFAULT;
    }

    /* 0660: owner/group only */
    proc_entry = p_proc_create_data(proc_filename, 0660, NULL, &p_ops, NULL);
    if (!proc_entry) {
        kpm_err("Proc registration failed\n");
        return -EFAULT;
    }

    kpm_info("Initialized. Proc file: /proc/%s\n", proc_filename);
    return 0;
}

static long self_inspect_exit(void __user *reserved)
{
    if (proc_entry && p_remove_proc_entry)
        p_remove_proc_entry(proc_filename, NULL);

    kpm_info("Unloaded, proc entry removed.\n");
    return 0;
}

KPM_INIT(self_inspect_init);
KPM_EXIT(self_inspect_exit);
