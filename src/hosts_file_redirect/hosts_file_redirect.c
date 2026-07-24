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
#include <linux/mutex.h>
#include <linux/version.h>
#include <linux/slab.h>

KPM_NAME("hosts_file_redirect");
KPM_VERSION(HFR_VERSION);
KPM_LICENSE("GPL v2");
KPM_AUTHOR("Surajit");
KPM_DESCRIPTION("KPM Dynamic Symbol Resolved Memory Bridge via access_process_vm");

/* TESTING MODE - Enable for initial verification, disable for production */
#define HFR_DEBUG
#ifdef HFR_DEBUG
#define kpm_info(fmt, ...) pr_info("HFR: " fmt, ##__VA_ARGS__)
#define kpm_err(fmt, ...)  pr_err("HFR: " fmt, ##__VA_ARGS__)
#else
#define kpm_info(fmt, ...)
#define kpm_err(fmt, ...)
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
#define STATUS_PARTIAL_IO     0x100B
#define STATUS_PROTECTION     0x100C
#define STATUS_INVALID_ADDR   0x100D
#define STATUS_NULL_SYMBOL    0x100E

/* Verified from kernel 5.10 source: FOLL_WRITE = 1 */
#define HFR_FOLL_WRITE        0x01

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

/* Exact proc_ops for kernel 5.10 from include/linux/proc_fs.h */
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

typedef void *(*proc_create_data_t)(const char *, uint16_t, void *, const struct proc_ops *, void *);
typedef void  (*remove_proc_entry_t)(const char *, void *);
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

static proc_create_data_t    p_proc_create_data;
static remove_proc_entry_t   p_remove_proc_entry;
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

static const char *proc_filename = "hfr_mem";
static void       *proc_entry    = NULL;
static DEFINE_MUTEX(hfr_mutex);

/* ARM64 direct current task retrieval without needing kallsyms get_current */
static inline struct task_struct *hfr_get_current(void)
{
    struct task_struct *tsk;
    asm volatile(
        "mrs %0, sp_el0"
        : "=r" (tsk)
    );
    return tsk;
}

/* Validate user address - prevent kernel space access */
static inline int is_valid_user_address(uint64_t addr)
{
    if (addr == 0)
        return 0;
    
    /* ARM64: Bit 63 set = kernel space */
    if (addr >= (1ULL << 63))
        return 0;
    
    return 1;
}

static void process_packet(struct k_packet *pkt, pid_t caller_pid)
{
    struct task_struct *task = NULL;
    struct mm_struct *mm = NULL;
    pid_t target_pid;
    int transferred;
    unsigned int gup_flags;
    int is_write_op = 0;
    uint8_t temp_buffer[MAX_INLINE];

    /* Validate opcode */
    if (pkt->op_code != OP_READ_VM && pkt->op_code != OP_WRITE_VM) {
        pkt->status = STATUS_BAD_OPCODE;
        return;
    }

    /* Validate size */
    if (!pkt->size || pkt->size > MAX_INLINE) {
        pkt->status = STATUS_INVALID_SIZE;
        return;
    }

    /* Validate virtual address */
    if (!is_valid_user_address(pkt->vaddr)) {
        pkt->status = STATUS_INVALID_ADDR;
        return;
    }

    /* Check critical symbol availability */
    if (!p_access_process_vm || !p_find_task_by_vpid || !p_get_task_mm || !p_mmput) {
        pkt->status = STATUS_NULL_SYMBOL;
        kpm_err("Critical symbols not available\n");
        return;
    }

    /* Determine target PID */
    target_pid = pkt->target_pid ? (pid_t)pkt->target_pid : caller_pid;
    
    /* Validate PID */
    if (target_pid <= 0) {
        pkt->status = STATUS_OUT_OF_RANGE;
        return;
    }

    /* Find task with RCU protection */
    if (p_rcu_read_lock)
        p_rcu_read_lock();

    task = p_find_task_by_vpid(target_pid);
    if (!task) {
        if (p_rcu_read_unlock)
            p_rcu_read_unlock();
        pkt->status = STATUS_NO_TASK;
        return;
    }

    /* Get task_struct reference to keep task alive */
    if (p_get_task_struct)
        p_get_task_struct(task);

    /* Get mm while task is still valid */
    mm = p_get_task_mm(task);

    if (p_rcu_read_unlock)
        p_rcu_read_unlock();

    if (!mm) {
        pkt->status = STATUS_NO_MM;
        if (p_put_task_struct && task)
            p_put_task_struct(task);
        return;
    }

    is_write_op = (pkt->op_code == OP_WRITE_VM);
    
    memset(temp_buffer, 0, MAX_INLINE);
    
    if (is_write_op) {
        memcpy(temp_buffer, pkt->inline_data, pkt->size);
        gup_flags = HFR_FOLL_WRITE;
    } else {
        gup_flags = 0;
    }

    /* Perform memory access with correct task pointer */
    transferred = p_access_process_vm(task, 
                                     (unsigned long)pkt->vaddr, 
                                     temp_buffer, 
                                     (int)pkt->size, 
                                     gup_flags);

    /* Safe cleanup */
    if (mm)
        p_mmput(mm);
    
    if (p_put_task_struct && task)
        p_put_task_struct(task);

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

static int proc_open_handler(struct inode *inode, struct file *file)
{
    return 0;
}

static int proc_release_handler(struct inode *inode, struct file *file)
{
    return 0;
}

static ssize_t proc_read_handler(struct file *file, char __user *buffer, size_t count, loff_t *pos)
{
    return 0;
}

static ssize_t proc_write_handler(struct file *file, const char __user *buffer, size_t count, loff_t *pos)
{
    struct k_packet *local_pkt;
    pid_t caller_pid;
    struct task_struct *curr_task;
    int ret = 0;

    if (count != sizeof(struct k_packet))
        return -EINVAL;

    local_pkt = kzalloc(sizeof(struct k_packet), GFP_KERNEL);
    if (!local_pkt)
        return -ENOMEM;

    if (!p_copy_from_user) {
        kfree(local_pkt);
        return -EFAULT;
    }

    if (p_copy_from_user(local_pkt, buffer, sizeof(struct k_packet)) != 0) {
        kfree(local_pkt);
        return -EFAULT;
    }

    curr_task = hfr_get_current();
    if (!curr_task) {
        kfree(local_pkt);
        return -ESRCH;
    }

    if (!p_task_pid_nr_ns) {
        kfree(local_pkt);
        return -EFAULT;
    }

    caller_pid = p_task_pid_nr_ns(curr_task, PIDTYPE_PID, NULL);
    if (caller_pid <= 0) {
        kfree(local_pkt);
        return -ESRCH;
    }

    mutex_lock(&hfr_mutex);
    process_packet(local_pkt, caller_pid);
    mutex_unlock(&hfr_mutex);

    if (!p_copy_to_user) {
        kfree(local_pkt);
        return -EFAULT;
    }

    ret = p_copy_to_user((void __user *)buffer, local_pkt, sizeof(struct k_packet));
    
    kfree(local_pkt);

    if (ret != 0)
        return -EFAULT;

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
    kpm_info("Initializing HFR Memory Bridge...\n");

    p_proc_create_data = (proc_create_data_t)kallsyms_lookup_name("proc_create_data");
    p_remove_proc_entry = (remove_proc_entry_t)kallsyms_lookup_name("remove_proc_entry");
    
    p_copy_from_user = (copy_from_user_t)kallsyms_lookup_name("_copy_from_user");
    if (!p_copy_from_user)
        p_copy_from_user = (copy_from_user_t)kallsyms_lookup_name("copy_from_user");

    p_copy_to_user = (copy_to_user_t)kallsyms_lookup_name("_copy_to_user");
    if (!p_copy_to_user)
        p_copy_to_user = (copy_to_user_t)kallsyms_lookup_name("copy_to_user");
    
    p_access_process_vm = (access_process_vm_t)kallsyms_lookup_name("access_process_vm");
    p_find_task_by_vpid = (find_task_by_vpid_t)kallsyms_lookup_name("find_task_by_vpid");
    p_get_task_mm = (get_task_mm_t)kallsyms_lookup_name("get_task_mm");
    p_mmput = (mmput_t)kallsyms_lookup_name("mmput");
    p_get_task_struct = (get_task_struct_t)kallsyms_lookup_name("get_task_struct");
    p_put_task_struct = (put_task_struct_t)kallsyms_lookup_name("put_task_struct");
    p_task_pid_nr_ns = (task_pid_nr_ns_t)kallsyms_lookup_name("__task_pid_nr_ns");
    
    p_rcu_read_lock = (rcu_read_lock_t)kallsyms_lookup_name("__rcu_read_lock");
    p_rcu_read_unlock = (rcu_read_unlock_t)kallsyms_lookup_name("__rcu_read_unlock");

    kpm_info("Symbols resolved:\n");
    kpm_info("  proc_create_data: %px\n", p_proc_create_data);
    kpm_info("  access_process_vm: %px\n", p_access_process_vm);
    kpm_info("  find_task_by_vpid: %px\n", p_find_task_by_vpid);
    kpm_info("  task_pid_nr_ns: %px\n", p_task_pid_nr_ns);
    kpm_info("  get_task_mm: %px\n", p_get_task_mm);
    kpm_info("  get_task_struct: %px\n", p_get_task_struct);
    kpm_info("  put_task_struct: %px\n", p_put_task_struct);

    if (!p_proc_create_data || !p_access_process_vm || 
        !p_find_task_by_vpid || !p_task_pid_nr_ns ||
        !p_get_task_mm || !p_mmput || !p_copy_from_user || !p_copy_to_user) {
        kpm_err("Critical symbol resolution failed\n");
        return -EFAULT;
    }

    mutex_init(&hfr_mutex);

    proc_entry = p_proc_create_data(proc_filename, 0660, NULL, &p_ops, NULL);
    if (!proc_entry) {
        kpm_err("Failed to create /proc/%s\n", proc_filename);
        return -EFAULT;
    }

    kpm_info("HFR Memory Bridge initialized at /proc/%s\n", proc_filename);
    return 0;
}

static long hfr_memory_exit(void __user *reserved)
{
    kpm_info("Shutting down HFR Memory Bridge...\n");

    if (proc_entry && p_remove_proc_entry)
        p_remove_proc_entry(proc_filename, NULL);

    kpm_info("HFR Memory Bridge removed\n");
    return 0;
}

KPM_INIT(hfr_memory_init);
KPM_EXIT(hfr_memory_exit);
