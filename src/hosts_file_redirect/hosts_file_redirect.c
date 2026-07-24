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

KPM_NAME("hosts_file_redirect");
KPM_VERSION(HFR_VERSION);
KPM_LICENSE("GPL v2");
KPM_AUTHOR("Surajit");
KPM_DESCRIPTION("KPM Dynamic Symbol Resolved Memory Bridge via access_process_vm");

#define KPM_PREFIX "HFR_MEM"
#define kpm_info(fmt, ...) pr_info(KPM_PREFIX ": " fmt, ##__VA_ARGS__)
#define kpm_err(fmt, ...)  pr_err(KPM_PREFIX ": " fmt, ##__VA_ARGS__)

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
#define STATUS_PARTIAL_IO     0x100B

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
    unsigned long (*proc_get_unmapped_area)(struct file *, unsigned long,
                                            unsigned long, unsigned long,
                                            unsigned long);
};

typedef void *(*proc_create_data_t)(const char *, uint16_t, void *, const struct proc_ops *, void *);
typedef void  (*remove_proc_entry_t)(const char *, void *);
typedef unsigned long (*copy_from_user_t)(void *, const void __user *, unsigned long);
typedef unsigned long (*copy_to_user_t)(void __user *, const void *, unsigned long);

typedef int (*access_process_vm_t)(struct task_struct *, unsigned long, void *, int, unsigned int);
typedef struct task_struct *(*find_task_by_vpid_t)(pid_t);
typedef struct mm_struct *(*get_task_mm_t)(struct task_struct *);
typedef void (*mmput_t)(struct mm_struct *);
typedef pid_t (*task_pid_vnr_t)(struct task_struct *);
typedef struct task_struct *(*get_current_t)(void);

/* RCU Dynamic Typedefs */
typedef void (*rcu_read_lock_t)(void);
typedef void (*rcu_read_unlock_t)(void);

static proc_create_data_t    p_proc_create_data;
static remove_proc_entry_t   p_remove_proc_entry;
static copy_from_user_t      p_copy_from_user;
static copy_to_user_t        p_copy_to_user;
static access_process_vm_t   p_access_process_vm;
static find_task_by_vpid_t   p_find_task_by_vpid;
static get_task_mm_t         p_get_task_mm;
static mmput_t               p_mmput;
static task_pid_vnr_t        p_task_pid_vnr;
static get_current_t         p_get_current;
static rcu_read_lock_t       p_rcu_read_lock;
static rcu_read_unlock_t     p_rcu_read_unlock;

static const char *proc_filename = "hfr_mem";
static void       *proc_entry    = NULL;

static ssize_t proc_read_handler(struct file *file, char __user *buffer, size_t count, loff_t *pos)
{
    return 0;
}

static void process_packet(struct k_packet *pkt, pid_t caller_pid)
{
    struct task_struct *task  = NULL;
    struct mm_struct   *mm    = NULL;
    pid_t               target_pid;
    int                 transferred;
    unsigned int        gup_flags;

    if (pkt->op_code != OP_READ_VM && pkt->op_code != OP_WRITE_VM) {
        pkt->status = STATUS_BAD_OPCODE;
        return;
    }

    if (!pkt->size || pkt->size > MAX_INLINE) {
        pkt->status = STATUS_INVALID_SIZE;
        return;
    }

    target_pid = pkt->target_pid ? (pid_t)pkt->target_pid : caller_pid;
    if (target_pid != caller_pid) {
        pkt->status = STATUS_OUT_OF_RANGE;
        return;
    }

    if (p_rcu_read_lock)
        p_rcu_read_lock();

    task = p_find_task_by_vpid(target_pid);
    if (!task) {
        if (p_rcu_read_unlock)
            p_rcu_read_unlock();
        pkt->status = STATUS_NO_TASK;
        return;
    }

    mm = p_get_task_mm(task);

    if (p_rcu_read_unlock)
        p_rcu_read_unlock();

    if (!mm) {
        pkt->status = STATUS_NO_MM;
        return;
    }

    gup_flags   = (pkt->op_code == OP_WRITE_VM) ? 0x01u : 0u;
    transferred = p_access_process_vm(NULL, (unsigned long)pkt->vaddr, pkt->inline_data, (int)pkt->size, gup_flags);

    p_mmput(mm);

    if (transferred < 0) {
        pkt->status = STATUS_VM_FAULT;
        return;
    }
    if ((uint32_t)transferred != pkt->size) {
        pkt->size   = (uint32_t)transferred;
        pkt->status = STATUS_PARTIAL_IO;
        return;
    }

    pkt->status = STATUS_SUCCESS;
}

static ssize_t proc_write_handler(struct file *file, const char __user *buffer, size_t count, loff_t *pos)
{
    struct k_packet local_pkt;
    pid_t           caller_pid;
    struct task_struct *curr_task;

    if (count < sizeof(struct k_packet))
        return -EINVAL;

    if (p_copy_from_user(&local_pid_check_dummy_or_copy_here, buffer, sizeof(struct k_packet)) == 0) // handled via p_copy_from_user below correctly
    if (p_copy_from_user(&local_pkt, buffer, sizeof(struct k_packet)))
        return -EFAULT;

    curr_task = p_get_current ? p_get_current() : NULL;
    if (!curr_task)
        return -ESRCH;

    caller_pid = p_task_pid_vnr(curr_task);

    process_packet(&local_pkt, caller_pid);

    if (p_copy_to_user((void __user *)buffer, &local_pkt, sizeof(struct k_packet)))
        return -EFAULT;

    return (ssize_t)count;
}

static const struct proc_ops p_ops = {
    .proc_flags   = 0,
    .proc_open    = NULL,
    .proc_read    = proc_read_handler,
    .proc_write   = proc_write_handler,
    .proc_lseek   = NULL,
    .proc_release = NULL,
};

static long hfr_memory_init(const char *args, const char *event, void __user *reserved)
{
    p_proc_create_data   = (proc_create_data_t)kallsyms_lookup_name("proc_create_data");
    p_remove_proc_entry  = (remove_proc_entry_t)kallsyms_lookup_name("remove_proc_entry");
    p_copy_from_user     = (copy_from_user_t)kallsyms_lookup_name("_copy_from_user");
    p_copy_to_user       = (copy_to_user_t)kallsyms_lookup_name("_copy_to_user");
    
    p_access_process_vm  = (access_process_vm_t)kallsyms_lookup_name("access_process_vm");
    p_find_task_by_vpid  = (find_task_by_vpid_t)kallsyms_lookup_name("find_task_by_vpid");
    p_get_task_mm        = (get_task_mm_t)kallsyms_lookup_name("get_task_mm");
    p_mmput              = (mmput_t)kallsyms_lookup_name("mmput");
    p_task_pid_vnr       = (task_pid_vnr_t)kallsyms_lookup_name("task_pid_vnr");
    p_get_current        = (get_current_t)kallsyms_lookup_name("get_current");
    
    p_rcu_read_lock      = (rcu_read_lock_t)kallsyms_lookup_name("__rcu_read_lock");
    p_rcu_read_unlock    = (rcu_read_unlock_t)kallsyms_lookup_name("__rcu_read_unlock");

    if (!p_proc_create_data || !p_access_process_vm || !p_find_task_by_vpid || !p_task_pid_vnr) {
        kpm_err("Core dynamic symbol resolution failed\n");
        return -EFAULT;
    }

    if (!p_rcu_read_lock || !p_rcu_read_unlock) {
        kpm_err("Failed to resolve RCU symbols\n");
        return -EFAULT;
    }

    kpm_info("proc_create_data  = %px\n", p_proc_create_data);
    kpm_info("access_process_vm = %px\n", p_access_process_vm);
    kpm_info("find_task_by_vpid = %px\n", p_find_task_by_vpid);
    kpm_info("rcu_read_lock     = %px\n", p_rcu_read_lock);
    kpm_info("rcu_read_unlock   = %px\n", p_rcu_read_unlock);

    proc_entry = p_proc_create_data(proc_filename, 0666, NULL, &p_ops, NULL);
    if (!proc_entry) {
        kpm_err("Proc registration node failure.\n");
        return -EFAULT;
    }

    kpm_info("KPM Fully Resolved Dynamic Memory Bridge initialized successfully!\n");
    return 0;
}

static long hfr_memory_exit(void __user *reserved)
{
    if (proc_entry && p_remove_proc_entry) {
        p_remove_proc_entry(proc_filename, NULL);
    }
    kpm_info("Proc pipeline unlinked safely!\n");
    return 0;
}

KPM_INIT(hfr_memory_init);
KPM_EXIT(hfr_memory_exit);
