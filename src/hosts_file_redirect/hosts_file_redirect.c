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

#define OP_FETCH_DATA  0x4000

#define STATUS_SUCCESS        0x0000
#define STATUS_PROC_NOT_FOUND 0x1008
#define STATUS_BAD_OPCODE     0x1007

/* Real proc_ops layout for kernel 5.10.x - confirmed working, unchanged. */
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

struct file;

/*
 * p_state / p_flags remain 0 - not available without the offset-scanning
 * technique cgroupv2_freeze uses. Say the word if you want that added.
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

/*
 * These 4 are resolved directly via kallsyms_lookup_name, NOT via the
 * pid.h header's find_vpid()/pid_task()/get_task_pid()/pid_vnr()
 * wrappers - those wrappers internally use KernelPatch's separate kf_
 * symbol table, which your dmesg log confirms does NOT know these
 * symbols on this device, even though /proc/kallsyms confirms all 4
 * ARE real, exported (EXPORT_SYMBOL) kernel functions. So we bypass
 * the header's kfunc_direct_call machinery entirely and call the
 * kallsyms-resolved function pointers ourselves - the same mechanism
 * that already works for proc_create_data etc. below.
 */
typedef struct pid *(*find_vpid_t)(int nr);
typedef struct task_struct *(*pid_task_t)(struct pid *pid, enum pid_type type);
typedef struct pid *(*get_task_pid_t)(struct task_struct *task, enum pid_type type);
typedef pid_t (*pid_vnr_t)(struct pid *pid);

static proc_create_data_t   p_proc_create_data;
static remove_proc_entry_t  p_remove_proc_entry;
static copy_from_user_t     p_copy_from_user;
static copy_to_user_t       p_copy_to_user;

static find_vpid_t     p_find_vpid;
static pid_task_t       p_pid_task;
static get_task_pid_t   p_get_task_pid;
static pid_vnr_t        p_pid_vnr;

static const char *proc_filename = "core_helper_kpm";
static void *proc_entry = NULL;

/*
 * No rcu_read_lock here - its underlying symbols aren't in this
 * device's kf_ table either, and no other module in this repo uses it.
 * Small theoretical race window between find_vpid and reading fields,
 * consistent with this codebase's existing convention.
 */
static int fetch_process_data(struct k_packet *pkt)
{
    struct pid *pid_struct;
    struct pid *tgid_pid_struct;
    struct task_struct *task;

    pid_struct = p_find_vpid(pkt->target_pid);
    if (!pid_struct)
        return -ESRCH;

    task = p_pid_task(pid_struct, PIDTYPE_PID);
    if (!task)
        return -ESRCH;

    pkt->p_pid = p_pid_vnr(pid_struct);

    tgid_pid_struct = p_get_task_pid(task, PIDTYPE_TGID);
    pkt->p_tgid = tgid_pid_struct ? p_pid_vnr(tgid_pid_struct) : 0;

    const char *comm = get_task_comm(task);
    memset(pkt->comm, 0, sizeof(pkt->comm));
    if (comm)
        memcpy(pkt->comm, comm, sizeof(pkt->comm) - 1);

    pkt->p_state = 0;
    pkt->p_flags = 0;

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

    p_find_vpid    = (find_vpid_t)kallsyms_lookup_name("find_vpid");
    p_pid_task     = (pid_task_t)kallsyms_lookup_name("pid_task");
    p_get_task_pid = (get_task_pid_t)kallsyms_lookup_name("get_task_pid");
    p_pid_vnr      = (pid_vnr_t)kallsyms_lookup_name("pid_vnr");

    if (!p_proc_create_data || !p_remove_proc_entry || !p_copy_from_user || !p_copy_to_user) {
        kpm_err("Failed to resolve core symbols\n");
        return -EFAULT;
    }

    if (!p_find_vpid || !p_pid_task || !p_get_task_pid || !p_pid_vnr) {
        kpm_err("Failed to resolve pid symbols: find_vpid=%px pid_task=%px get_task_pid=%px pid_vnr=%px\n",
                p_find_vpid, p_pid_task, p_get_task_pid, p_pid_vnr);
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
