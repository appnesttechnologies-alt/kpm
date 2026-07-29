#include <compiler.h>
#include <hook.h>
#include <kpmodule.h>
#include <kputils.h>
#include <linux/errno.h>
#include <linux/printk.h>
#include <linux/string.h>
#include <linux/sched.h>
#include <linux/pid.h>

KPM_NAME("core_helper_kpm");
KPM_VERSION("1.0");
KPM_LICENSE("GPL v2");
KPM_AUTHOR("Surajit");
KPM_DESCRIPTION("Core Helper Module");

#define KPM_PREFIX "CORE_HLP"
#define kpm_info(fmt, ...) pr_info(KPM_PREFIX ": " fmt, ##__VA_ARGS__)
#define kpm_err(fmt, ...)  pr_err(KPM_PREFIX ": " fmt, ##__VA_ARGS__)

#define MAX_INLINE     256
#define OP_FETCH_DATA  0x4000

#define STATUS_SUCCESS        0x0000
#define STATUS_INVALID_SIZE   0x1005
#define STATUS_PROC_NOT_FOUND 0x1008
#define STATUS_BAD_OPCODE     0x1007

/*
 * This build environment (KernelPatch's minimal KPM headers) has no
 * linux/proc_fs.h at all - confirmed by the CI failure on
 * hosts_file_redirect.c. So struct proc_ops MUST be defined locally.
 *
 * The bug in the original file was NOT that it defined this locally -
 * that's required here. The bug was that it was MISSING two fields
 * that the real kernel's struct proc_ops has: proc_read_iter and
 * proc_lseek. Because proc_create_data() is a REAL kernel function,
 * it reads/writes this struct using the REAL layout. Our local struct
 * must match that layout field-for-field, in the same order, or
 * proc_write ends up at the wrong byte offset and the kernel jumps
 * into garbage when something calls it -> crash.
 *
 * This layout matches what you confirmed from your own
 * include/linux/proc_fs.h on kernel 5.10.252, and matches the working
 * hosts_file_redirect.c module in this same repo.
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

/*
 * struct file is never dereferenced anywhere in this module - it's only
 * ever passed around as an opaque pointer (matching what the real kernel
 * gives us). So we just forward-declare it instead of defining fake
 * members; there's no struct-layout risk since we never touch its fields.
 */
struct file;

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
    task = pid_task(find_vpid(pkt->target_pid), PIDTYPE_PID);
    if (!task) {
        rcu_read_unlock();
        return -ESRCH;
    }
    get_task_struct(task);
    rcu_read_unlock();

    pkt->p_pid = task_pid_nr(task);
    pkt->p_tgid = task_tgid_nr(task);
    pkt->p_state = task->__state;
    pkt->p_flags = task->flags;
    get_task_comm(pkt->comm, task);

    put_task_struct(task);
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

    /* reject anything that isn't exactly one packet, both directions */
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
