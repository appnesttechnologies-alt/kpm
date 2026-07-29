#include <compiler.h>
#include <hook.h>
#include <kpmodule.h>
#include <kputils.h>
#include <linux/errno.h>
#include <linux/printk.h>
#include <linux/string.h>
#include <linux/sched.h>
#include <linux/pid.h>
#include <linux/rcupdate.h>

KPM_NAME("core_helper_kpm");
KPM_VERSION("1.0");
KPM_LICENSE("GPL v2");
KPM_AUTHOR("Surajit");
KPM_DESCRIPTION("Core Helper Module");

#define KPM_PREFIX "CORE_HLP"
#define kpm_info(fmt, ...) pr_info(KPM_PREFIX ": " fmt, ##__VA_ARGS__)
#define kpm_err(fmt, ...)  pr_err(KPM_PREFIX ": " fmt, ##__VA_ARGS__)

#define OP_FETCH_DATA  0x4000

#define STATUS_SUCCESS        0x0000
#define STATUS_PROC_NOT_FOUND 0x1008
#define STATUS_BAD_OPCODE     0x1007

/*
 * Real proc_ops layout for kernel 5.10.x (confirmed from your own
 * include/linux/proc_fs.h, and matching hosts_file_redirect.c in this
 * same repo). This build environment has no linux/proc_fs.h at all, so
 * this MUST be defined locally - the earlier crash was because two
 * fields (proc_read_iter, proc_lseek) were missing here, which shifted
 * every field after proc_read to the wrong byte offset.
 */
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

/* Never dereferenced - only ever passed as an opaque pointer. */
struct file;

/*
 * NOTE: p_state and p_flags are kept in the wire format for compatibility
 * with your original userspace tool, but this framework's headers do
 * NOT expose task->state or task->flags generically - see
 * src/cgroupv2_freeze/cfv2_offsets.c: getting those requires disassembling
 * real kernel functions at runtime to recover the byte offset, because
 * there's no debug-info shortcut here. That's a heavier, kernel-version-
 * specific technique. This version fills p_state/p_flags with 0 and
 * focuses on what IS reliably available: pid, tgid, comm. Say the word
 * if you want state/flags added using the offset-scanning approach -
 * it's doable but a bigger, more fragile piece of code.
 */
struct k_packet {
    uint32_t op_code;
    int32_t  target_pid;
    uint32_t status;
    pid_t    p_pid;
    pid_t    p_tgid;
    long     p_state;
    unsigned int p_flags;
    char     comm[16];
} __attribute__((aligned(8), packed));

typedef void *(*proc_create_data_t)(const char *, uint16_t, void *, const struct proc_ops *, void *);
typedef void (*remove_proc_entry_t)(const char *, void *);
typedef unsigned long (*copy_from_user_t)(void *to, const void __user *from, unsigned long n);
typedef unsigned long (*copy_to_user_t)(void __user *to, const void *from, unsigned long n);

static proc_create_data_t   p_proc_create_data;
static remove_proc_entry_t  p_remove_proc_entry;
static copy_from_user_t     p_copy_from_user;
static copy_to_user_t       p_copy_to_user;

static const char *proc_filename = "core_helper_kpm";
static void *proc_entry = NULL;

static int fetch_process_data(struct k_packet *pkt)
{
    struct task_struct *task;

    rcu_read_lock();
    task = find_task_by_vpid(pkt->target_pid);
    if (!task) {
        rcu_read_unlock();
        return -ESRCH;
    }

    pkt->p_pid  = task_pid_vnr(task);
    pkt->p_tgid = __task_pid_nr_ns(task, PIDTYPE_TGID, NULL);

    const char *comm = get_task_comm(task);
    memset(pkt->comm, 0, sizeof(pkt->comm));
    if (comm)
        memcpy(pkt->comm, comm, sizeof(pkt->comm) - 1);

    /* Not available without runtime offset-scanning - see comment above. */
    pkt->p_state = 0;
    pkt->p_flags = 0;

    rcu_read_unlock();
    return 0;
}

static void process_packet(struct k_packet *pkt)
{
    if (pkt->op_code != OP_FETCH_DATA) {
        pkt->status = STATUS_BAD_OPCODE;
        return;
    }

    if (fetch_process_data(pkt) != 0) {
        pkt->status = STATUS_PROC_NOT_FOUND;
        return;
    }

    pkt->status = STATUS_SUCCESS;
}

static ssize_t proc_write_handler(struct file *file, const char __user *buffer, size_t count, loff_t *pos)
{
    struct k_packet local_pkt;

    if (count != sizeof(struct k_packet))
        return -EINVAL;

    memset(&local_pkt, 0, sizeof(local_pkt));

    if (p_copy_from_user(&local_pkt, buffer, sizeof(struct k_packet)))
        return -EFAULT;

    process_packet(&local_pkt);

    if (p_copy_to_user((void __user *)buffer, &local_pkt, sizeof(struct k_packet)))
        return -EFAULT;

    return count;
}

static const struct proc_ops p_ops = {
    .proc_flags   = 0,
    .proc_open    = NULL,
    .proc_read    = NULL,
    .proc_read_iter = NULL,
    .proc_write   = proc_write_handler,
    .proc_lseek   = NULL,
    .proc_release = NULL,
    .proc_poll    = NULL,
    .proc_ioctl   = NULL,
    .proc_mmap    = NULL,
    .proc_get_unmapped_area = NULL,
};

static long core_init(const char *args, const char *event, void __user *reserved)
{
    p_proc_create_data  = (proc_create_data_t)kallsyms_lookup_name("proc_create_data");
    p_remove_proc_entry = (remove_proc_entry_t)kallsyms_lookup_name("remove_proc_entry");
    p_copy_from_user    = (copy_from_user_t)kallsyms_lookup_name("_copy_from_user");
    p_copy_to_user      = (copy_to_user_t)kallsyms_lookup_name("_copy_to_user");

    if (!p_proc_create_data || !p_remove_proc_entry || !p_copy_from_user || !p_copy_to_user) {
        kpm_err("Failed to resolve symbols\n");
        return -EFAULT;
    }

    /*
     * These resolve the underlying real kernel functions that
     * find_task_by_vpid() / __task_pid_nr_ns() / rcu_read_lock() /
     * rcu_read_unlock() call through internally (via this framework's
     * kfunc mechanism, matching the pattern used in cgroupv2_freeze.c's
     * init - e.g. kfunc_lookup_name(wake_up_process)).
     *
     * I could not 100% verify the exact macro name/behavior of
     * kfunc_lookup_name from what you've shared so far (only its usage
     * site, not its definition in ksyms.h). If this line doesn't
     * compile, paste kernel/patch/include/ksyms.h and I'll correct it
     * precisely rather than guess again.
     */
    kfunc_lookup_name(find_task_by_vpid);
    kfunc_lookup_name(__task_pid_nr_ns);
    kfunc_lookup_name(__rcu_read_lock);
    kfunc_lookup_name(__rcu_read_unlock);

    proc_entry = p_proc_create_data(proc_filename, 0660, NULL, &p_ops, NULL);
    if (!proc_entry) {
        kpm_err("Proc registration failed\n");
        return -EFAULT;
    }

    kpm_info("Initialized. Proc file: /proc/%s\n", proc_filename);
    return 0;
}

static long core_exit(void __user *reserved)
{
    if (proc_entry && p_remove_proc_entry) {
        p_remove_proc_entry(proc_filename, NULL);
    }
    kpm_info("Unloaded.\n");
    return 0;
}

KPM_INIT(core_init);
KPM_EXIT(core_exit);
