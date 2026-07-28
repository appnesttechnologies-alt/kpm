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

KPM_NAME("hosts_file_redirect");
KPM_VERSION("2.0.3");
KPM_LICENSE("GPL v2");
KPM_AUTHOR("Surajit");
KPM_DESCRIPTION("Kernel Memory Bridge");

#define HFR_DEBUG
#ifdef HFR_DEBUG
#define kpm_info(fmt, ...) pr_info("HFR: " fmt, ##__VA_ARGS__)
#define kpm_err(fmt, ...)  pr_err("HFR: " fmt, ##__VA_ARGS__)
#else
#define kpm_info(fmt, ...)
#define kpm_err(fmt, ...)
#endif

#define MAX_INLINE      256
#define MAX_CMDLINE     512

#define OP_READ_VM      0x2000
#define OP_WRITE_VM     0x2001
#define OP_FIND_PROCESS 0x2002
#define OP_CHECK_PROCESS 0x2003
#define OP_READ_MAPS    0x2004

#define HFR_FOLL_WRITE  0x01
#define FOLL_FORCE      0x10
#define HFR_O_RDONLY    00

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
#define STATUS_NOT_FOUND      0x100F
#define STATUS_NO_FILE        0x1010
#define STATUS_EOF            0x1011

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
typedef struct file *(*filp_open_t)(const char *, int, umode_t);
typedef int (*filp_close_t)(struct file *, void *);
typedef ssize_t (*kernel_read_t)(struct file *, void *, size_t, loff_t *);
typedef const char *(*get_task_comm_t)(struct task_struct *);

static proc_create_data_t    p_proc_create_data = NULL;
static remove_proc_entry_t   p_remove_proc_entry = NULL;
static copy_from_user_t      p_copy_from_user = NULL;
static copy_to_user_t        p_copy_to_user = NULL;
static access_process_vm_t   p_access_process_vm = NULL;
static find_task_by_vpid_t   p_find_task_by_vpid = NULL;
static get_task_mm_t         p_get_task_mm = NULL;
static mmput_t               p_mmput = NULL;
static get_task_struct_t     p_get_task_struct = NULL;
static put_task_struct_t     p_put_task_struct = NULL;
static task_pid_nr_ns_t      p_task_pid_nr_ns = NULL;
static rcu_read_lock_t       p_rcu_read_lock = NULL;
static rcu_read_unlock_t     p_rcu_read_unlock = NULL;
static mutex_init_t          p_mutex_init = NULL;
static mutex_lock_t          p_mutex_lock = NULL;
static mutex_unlock_t        p_mutex_unlock = NULL;
static filp_open_t           p_filp_open = NULL;
static filp_close_t          p_filp_close = NULL;
static kernel_read_t         p_kernel_read = NULL;
static get_task_comm_t       p_get_task_comm_fn = NULL;

static const char *proc_filename = "hfr_mem";
static void       *proc_entry    = NULL;
static struct mutex hfr_mutex;

static inline struct task_struct *hfr_get_current(void)
{
    struct task_struct *tsk;
    asm volatile("mrs %0, sp_el0" : "=r" (tsk));
    return tsk;
}

static inline int is_valid_user_address(uint64_t addr)
{
    return (addr >= 0x1000 && addr < (1ULL << 63));
}

static int kstr_nmatch(const char *a, const char *b, int n)
{
    int i;
    for (i = 0; i < n; i++) {
        if (a[i] != b[i]) return 0;
        if (!a[i]) break;
    }
    return 1;
}

static void build_path(int pid, const char *suffix, char *buf, int buf_size)
{
    const char *pre = "/proc/";
    int pos = 0, i, pl = 0;
    char ps[16];
    int tp = pid;
    while (pre[pos] && pos < buf_size - 1) { buf[pos] = pre[pos]; pos++; }
    if (tp == 0) { ps[pl++] = '0'; }
    while (tp > 0) { ps[pl++] = '0' + (tp % 10); tp /= 10; }
    for (i = pl - 1; i >= 0; i--) { if (pos < buf_size - 1) buf[pos++] = ps[i]; }
    for (i = 0; suffix[i] && pos < buf_size - 1; i++) buf[pos++] = suffix[i];
    buf[pos] = '\0';
}

// ╔══════════════════════════════════════════════════════════════╗
// ║  PID SCAN - find_task_by_vpid + __get_task_comm             ║
// ╚══════════════════════════════════════════════════════════════╝

static int find_process_by_pid_scan(const char *proc_name, pid_t *out_pid)
{
    struct task_struct *task;
    const char *comm;
    pid_t pid;
    int name_len, i;
    
    if (!p_find_task_by_vpid || !p_get_task_comm_fn) {
        kpm_err("Symbols NULL: find_task=%px get_comm=%px\n",
                p_find_task_by_vpid, p_get_task_comm_fn);
        return -EFAULT;
    }
    
    name_len = 0;
    while (proc_name[name_len]) name_len++;
    
    kpm_info("PID scan for '%s' (len=%d)\n", proc_name, name_len);
    
    for (pid = 1; pid < 32768; pid++) {
        task = p_find_task_by_vpid(pid);
        if (!task) continue;
        
        comm = p_get_task_comm_fn(task);
        if (!comm) continue;
        
        // comm is max 15 chars, match accordingly
        int match_len = (name_len < 15) ? name_len : 15;
        if (kstr_nmatch(comm, proc_name, match_len) && (name_len <= 15 || comm[15] == '\0' || comm[14] == '\0')) {
            kpm_info("FOUND: PID=%d comm='%s'\n", pid, comm);
            *out_pid = pid;
            return 0;
        }
    }
    
    kpm_err("PID scan complete, not found\n");
    return -ESRCH;
}

// ╔══════════════════════════════════════════════════════════════╗
// ║  CMDLINE SCAN - filp_open /proc/PID/cmdline                 ║
// ╚══════════════════════════════════════════════════════════════╝

static int find_process_by_cmdline(const char *proc_name, pid_t *out_pid)
{
    char path[64];
    char buf[MAX_CMDLINE];
    struct file *f;
    ssize_t rd;
    loff_t pos;
    pid_t pid;
    int i;
    
    if (!p_filp_open || !p_filp_close || !p_kernel_read) {
        kpm_err("VFS symbols NULL: open=%px close=%px read=%px\n",
                p_filp_open, p_filp_close, p_kernel_read);
        return -EFAULT;
    }
    
    kpm_info("Cmdline scan for '%s'\n", proc_name);
    
    for (pid = 1; pid < 32768; pid++) {
        build_path(pid, "/cmdline", path, sizeof(path));
        
        f = p_filp_open(path, HFR_O_RDONLY, 0);
        if (!f || (unsigned long)f >= (unsigned long)(-4095)) continue;
        
        pos = 0;
        rd = p_kernel_read(f, buf, sizeof(buf) - 1, &pos);
        p_filp_close(f, NULL);
        
        if (rd <= 0) continue;
        
        buf[rd] = '\0';
        // Replace null separators with spaces
        for (i = 0; i < rd; i++) if (buf[i] == '\0') buf[i] = ' ';
        
        // Check if proc_name is substring
        for (i = 0; buf[i]; i++) {
            int j;
            for (j = 0; proc_name[j]; j++) {
                if (buf[i + j] != proc_name[j]) break;
            }
            if (!proc_name[j]) {
                kpm_info("FOUND by cmdline: PID=%d\n", pid);
                *out_pid = pid;
                return 0;
            }
        }
    }
    
    kpm_err("Cmdline scan complete, not found\n");
    return -ESRCH;
}

static void process_rw_packet(struct k_packet *pkt)
{
    struct task_struct *task = NULL;
    struct mm_struct *mm = NULL;
    int transferred;
    unsigned int gup_flags;
    int is_write_op;
    uint8_t temp_buffer[MAX_INLINE];

    if (!pkt->size || pkt->size > MAX_INLINE) { pkt->status = STATUS_INVALID_SIZE; return; }
    if (!is_valid_user_address(pkt->vaddr)) { pkt->status = STATUS_INVALID_ADDR; return; }
    if (!p_access_process_vm || !p_find_task_by_vpid || !p_get_task_mm || !p_mmput) { pkt->status = STATUS_NULL_SYMBOL; return; }
    if (pkt->target_pid <= 0) { pkt->status = STATUS_OUT_OF_RANGE; return; }

    if (p_rcu_read_lock) p_rcu_read_lock();
    task = p_find_task_by_vpid(pkt->target_pid);
    if (!task) { if (p_rcu_read_unlock) p_rcu_read_unlock(); pkt->status = STATUS_NO_TASK; return; }
    if (p_get_task_struct) p_get_task_struct(task);
    mm = p_get_task_mm(task);
    if (p_rcu_read_unlock) p_rcu_read_unlock();
    if (!mm) { pkt->status = STATUS_NO_MM; if (p_put_task_struct && task) p_put_task_struct(task); return; }

    is_write_op = (pkt->op_code == OP_WRITE_VM);
    memset(temp_buffer, 0, MAX_INLINE);
    if (is_write_op) { memcpy(temp_buffer, pkt->inline_data, pkt->size); gup_flags = HFR_FOLL_WRITE | FOLL_FORCE; }
    else { gup_flags = FOLL_FORCE; }

    transferred = p_access_process_vm(task, (unsigned long)pkt->vaddr, temp_buffer, (int)pkt->size, gup_flags);

    if (mm) p_mmput(mm);
    if (p_put_task_struct && task) p_put_task_struct(task);

    if (transferred < 0) { pkt->status = STATUS_VM_FAULT; return; }
    if (transferred == 0 && pkt->size > 0) { pkt->status = STATUS_PROTECTION; return; }
    if (!is_write_op && transferred > 0) { memset(pkt->inline_data, 0, MAX_INLINE); memcpy(pkt->inline_data, temp_buffer, transferred); }
    if ((uint32_t)transferred != pkt->size) { pkt->size = (uint32_t)transferred; pkt->status = STATUS_PARTIAL_IO; return; }
    pkt->status = STATUS_SUCCESS;
}

static void process_find_packet(struct k_packet *pkt)
{
    pid_t found_pid = -1;
    char proc_name[256];
    int name_len = (int)pkt->size;
    
    if (name_len > 255) name_len = 255;
    memcpy(proc_name, pkt->inline_data, name_len);
    proc_name[name_len] = '\0';
    
    kpm_info("Finding: '%s'\n", proc_name);
    
    // Method 1: find_task_by_vpid + __get_task_comm scan
    if (find_process_by_pid_scan(proc_name, &found_pid) == 0 && found_pid > 0)
        goto success;
    
    // Method 2: /proc/PID/cmdline VFS scan
    if (find_process_by_cmdline(proc_name, &found_pid) == 0 && found_pid > 0)
        goto success;
    
    // Not found
    pkt->target_pid = 0;
    pkt->vaddr = 0;
    pkt->size = 0;
    pkt->status = STATUS_NOT_FOUND;
    kpm_err("NOT FOUND: '%s'\n", proc_name);
    return;
    
success:
    pkt->target_pid = (uint32_t)found_pid;
    pkt->vaddr = (uint64_t)found_pid;
    pkt->size = (uint32_t)found_pid;
    pkt->status = STATUS_SUCCESS;
    kpm_info("SUCCESS: PID=%d\n", found_pid);
}

static int read_process_maps(pid_t pid, char *buffer, size_t buf_size, loff_t offset, size_t *bytes_read)
{
    char path[64];
    struct file *f = NULL;
    ssize_t rd;
    loff_t pos = offset;
    
    if (!p_filp_open || !p_filp_close || !p_kernel_read) return -EFAULT;
    
    build_path(pid, "/maps", path, sizeof(path));
    f = p_filp_open(path, HFR_O_RDONLY, 0);
    if (!f || (unsigned long)f >= (unsigned long)(-4095)) return -ENOENT;
    rd = p_kernel_read(f, buffer, buf_size, &pos);
    p_filp_close(f, NULL);
    if (rd < 0) return -EIO;
    *bytes_read = (size_t)rd;
    return 0;
}

static void process_maps_packet(struct k_packet *pkt)
{
    size_t bytes_read = 0;
    int ret;
    if (pkt->target_pid <= 0) { pkt->status = STATUS_OUT_OF_RANGE; return; }
    ret = read_process_maps(pkt->target_pid, (char *)pkt->inline_data, MAX_INLINE, (loff_t)pkt->vaddr, &bytes_read);
    if (ret == 0) {
        pkt->size = (uint32_t)bytes_read;
        pkt->vaddr = (loff_t)pkt->vaddr + bytes_read;
        pkt->status = (bytes_read == 0) ? STATUS_EOF : STATUS_SUCCESS;
    } else { pkt->size = 0; pkt->status = STATUS_NO_FILE; }
}

static void process_check_packet(struct k_packet *pkt)
{
    struct task_struct *task;
    if (pkt->target_pid <= 0 || !p_find_task_by_vpid) { pkt->status = STATUS_OUT_OF_RANGE; return; }
    task = p_find_task_by_vpid(pkt->target_pid);
    pkt->status = task ? STATUS_SUCCESS : STATUS_NO_TASK;
}

static void process_packet(struct k_packet *pkt, pid_t caller_pid)
{
    switch (pkt->op_code) {
        case OP_READ_VM: case OP_WRITE_VM: process_rw_packet(pkt); break;
        case OP_FIND_PROCESS: process_find_packet(pkt); break;
        case OP_READ_MAPS: process_maps_packet(pkt); break;
        case OP_CHECK_PROCESS: process_check_packet(pkt); break;
        default: pkt->status = STATUS_BAD_OPCODE; break;
    }
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
    if (!p_copy_from_user || p_copy_from_user(&local_pkt, buffer, sizeof(struct k_packet)) != 0) return -EFAULT;
    curr_task = hfr_get_current();
    if (!curr_task || !p_task_pid_nr_ns) return -ESRCH;
    caller_pid = p_task_pid_nr_ns(curr_task, PIDTYPE_PID, NULL);
    if (caller_pid <= 0) return -ESRCH;
    if (p_mutex_lock) p_mutex_lock(&hfr_mutex);
    process_packet(&local_pkt, caller_pid);
    if (p_mutex_unlock) p_mutex_unlock(&hfr_mutex);
    if (p_copy_to_user((void __user *)buffer, &local_pkt, sizeof(struct k_packet)) != 0) return -EFAULT;
    return (ssize_t)count;
}

static const struct proc_ops p_ops = {
    .proc_open = proc_open_handler,
    .proc_read = proc_read_handler,
    .proc_write = proc_write_handler,
    .proc_release = proc_release_handler,
};

static long hfr_memory_init(const char *args, const char *event, void __user *reserved)
{
    kpm_info("=== INIT v2.0.3 ===\n");
    
    p_proc_create_data = (proc_create_data_t)kallsyms_lookup_name("proc_create_data");
    p_remove_proc_entry = (remove_proc_entry_t)kallsyms_lookup_name("remove_proc_entry");
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
    p_mutex_init = (mutex_init_t)kallsyms_lookup_name("__mutex_init");
    p_mutex_lock = (mutex_lock_t)kallsyms_lookup_name("mutex_lock");
    p_mutex_unlock = (mutex_unlock_t)kallsyms_lookup_name("mutex_unlock");
    p_filp_open = (filp_open_t)kallsyms_lookup_name("filp_open");
    p_filp_close = (filp_close_t)kallsyms_lookup_name("filp_close");
    p_kernel_read = (kernel_read_t)kallsyms_lookup_name("kernel_read");
    
    // 🔥 Use __get_task_comm (your kernel has this, not get_task_comm)
    p_get_task_comm_fn = (get_task_comm_t)kallsyms_lookup_name("__get_task_comm");
    if (!p_get_task_comm_fn) p_get_task_comm_fn = (get_task_comm_t)kallsyms_lookup_name("get_task_comm");
    
    kpm_info("Symbols: proc=%px vm=%px task=%px mm=%px comm=%px open=%px read=%px\n",
             p_proc_create_data, p_access_process_vm, p_find_task_by_vpid,
             p_get_task_mm, p_get_task_comm_fn, p_filp_open, p_kernel_read);

    if (!p_proc_create_data || !p_access_process_vm || !p_find_task_by_vpid || 
        !p_task_pid_nr_ns || !p_get_task_mm || !p_mmput || !p_copy_from_user || !p_copy_to_user) {
        kpm_err("CRITICAL SYMBOL MISSING\n");
        return -EFAULT;
    }
    
    if (p_mutex_init) p_mutex_init(&hfr_mutex);
    proc_entry = p_proc_create_data(proc_filename, 0666, NULL, &p_ops, NULL);
    if (!proc_entry) { kpm_err("proc_create FAILED\n"); return -EFAULT; }
    
    kpm_info("=== SUCCESS /proc/%s ===\n", proc_filename);
    return 0;
}

static long hfr_memory_exit(void __user *reserved)
{
    if (proc_entry && p_remove_proc_entry) p_remove_proc_entry(proc_filename, NULL);
    return 0;
}

KPM_INIT(hfr_memory_init);
KPM_EXIT(hfr_memory_exit);
