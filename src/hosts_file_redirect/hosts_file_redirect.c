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
#include <linux/uaccess.h>
#include <linux/dcache.h>
#include <linux/path.h>
#include <linux/fs.h>

KPM_NAME("hosts_file_redirect");
KPM_VERSION("2.0.0");
KPM_LICENSE("GPL v2");
KPM_AUTHOR("Surajit");
KPM_DESCRIPTION("Complete Kernel Memory Bridge - No Root Syscalls");

#define HFR_DEBUG
#ifdef HFR_DEBUG
#define kpm_info(fmt, ...) pr_info("HFR: " fmt, ##__VA_ARGS__)
#define kpm_err(fmt, ...)  pr_err("HFR: " fmt, ##__VA_ARGS__)
#else
#define kpm_info(fmt, ...)
#define kpm_err(fmt, ...)
#endif

// ╔══════════════════════════════════════════════════════════════╗
// ║                     CONSTANTS                                ║
// ╚══════════════════════════════════════════════════════════════╝

#define MAX_INLINE           256
#define MAX_PATH_LEN         512
#define HFR_FOLL_WRITE       0x01
#define FOLL_FORCE           0x10

// Opcodes
#define OP_READ_VM           0x2000
#define OP_WRITE_VM          0x2001
#define OP_FIND_PROCESS      0x2002
#define OP_GET_MODULE_BASE   0x2003
#define OP_CHECK_PROCESS     0x2004

// Status codes
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
#define STATUS_NO_MODULE      0x1010

// ╔══════════════════════════════════════════════════════════════╗
// ║                PACKET STRUCTURE                              ║
// ╚══════════════════════════════════════════════════════════════╝

struct k_packet {
    uint32_t op_code;
    uint32_t target_pid;
    uint64_t vaddr;
    uint32_t size;
    uint32_t status;
    uint8_t  inline_data[MAX_INLINE];
} __attribute__((aligned(8), packed));

// ╔══════════════════════════════════════════════════════════════╗
// ║             PROCFS STRUCTURES (Android KPM)                  ║
// ╚══════════════════════════════════════════════════════════════╝

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

// ╔══════════════════════════════════════════════════════════════╗
// ║               FUNCTION POINTER TYPEDEFS                      ║
// ╚══════════════════════════════════════════════════════════════╝

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
typedef struct task_struct *(*next_task_t)(struct task_struct *);

// ╔══════════════════════════════════════════════════════════════╗
// ║               GLOBAL FUNCTION POINTERS                       ║
// ╚══════════════════════════════════════════════════════════════╝

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
static mutex_init_t          p_mutex_init;
static mutex_lock_t          p_mutex_lock;
static mutex_unlock_t        p_mutex_unlock;
static next_task_t           p_next_task;

static const char *proc_filename = "hfr_mem";
static void       *proc_entry    = NULL;
static struct mutex hfr_mutex;

// ╔══════════════════════════════════════════════════════════════╗
// ║                   HELPER FUNCTIONS                           ║
// ╚══════════════════════════════════════════════════════════════╝

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

// Simple kernel-side string comparison
static int kstr_match(const char *a, const char *b)
{
    while (*a && *b) {
        if (*a != *b) return 0;
        a++; b++;
    }
    return (*a == *b);
}

// Check if needle is at the end of haystack
static int kstr_ends_with(const char *haystack, const char *needle)
{
    int hlen = 0, nlen = 0;
    while (haystack[hlen]) hlen++;
    while (needle[nlen]) nlen++;
    
    if (nlen > hlen) return 0;
    
    for (int i = 0; i < nlen; i++) {
        if (haystack[hlen - nlen + i] != needle[i]) return 0;
    }
    return 1;
}

// ╔══════════════════════════════════════════════════════════════╗
// ║           OP_FIND_PROCESS - Find PID by task_struct scan     ║
// ╚══════════════════════════════════════════════════════════════╝

static int find_process_by_comm(const char *proc_name, pid_t *out_pid)
{
    struct task_struct *task;
    char comm[TASK_COMM_LEN];
    
    if (!p_next_task || !p_rcu_read_lock || !p_rcu_read_unlock || !p_task_pid_nr_ns) {
        kpm_err("Missing symbols for process scan\n");
        return -EFAULT;
    }
    
    p_rcu_read_lock();
    
    for (task = hfr_get_current(); task; task = p_next_task(task)) {
        if (!task) break;
        
        // get_task_comm is a kernel macro, not a symbol lookup
        get_task_comm(comm, task);
        
        if (kstr_match(comm, proc_name)) {
            if (p_get_task_struct) p_get_task_struct(task);
            *out_pid = p_task_pid_nr_ns(task, PIDTYPE_PID, NULL);
            if (p_put_task_struct) p_put_task_struct(task);
            p_rcu_read_unlock();
            kpm_info("Found process '%s': PID=%d\n", proc_name, *out_pid);
            return 0;
        }
    }
    
    p_rcu_read_unlock();
    kpm_err("Process '%s' not found in task list\n", proc_name);
    return -ESRCH;
}

// ╔══════════════════════════════════════════════════════════════╗
// ║     OP_GET_MODULE_BASE - Find library base from VMA tree     ║
// ╚══════════════════════════════════════════════════════════════╝

static int get_module_base_from_vma(pid_t pid, const char *lib_name, 
                                     uint64_t *out_base, uint32_t *out_size)
{
    struct task_struct *task;
    struct mm_struct *mm;
    struct vm_area_struct *vma;
    uint64_t found_base = 0;
    uint32_t found_size = 0;
    
    if (!p_find_task_by_vpid || !p_get_task_mm || !p_mmput) {
        kpm_err("Missing symbols for module scan\n");
        return -EFAULT;
    }
    
    if (p_rcu_read_lock) p_rcu_read_lock();
    task = p_find_task_by_vpid(pid);
    if (!task) {
        if (p_rcu_read_unlock) p_rcu_read_unlock();
        kpm_err("Task not found for PID %d\n", pid);
        return -ESRCH;
    }
    
    if (p_get_task_struct) p_get_task_struct(task);
    mm = p_get_task_mm(task);
    if (p_rcu_read_unlock) p_rcu_read_unlock();
    
    if (!mm) {
        kpm_err("No mm_struct for PID %d\n", pid);
        if (p_put_task_struct && task) p_put_task_struct(task);
        return -ESRCH;
    }
    
    // Lock mmap_sem
    #if LINUX_VERSION_CODE >= KERNEL_VERSION(5, 8, 0)
    mmap_read_lock(mm);
    #else
    down_read(&mm->mmap_sem);
    #endif
    
    for (vma = mm->mmap; vma; vma = vma->vm_next) {
        if (vma->vm_file) {
            char *path_buf = NULL;
            char *path;
            
            path_buf = (char *)kmalloc(PATH_MAX, GFP_KERNEL);
            if (!path_buf) continue;
            
            path = d_path(&vma->vm_file->f_path, path_buf, PATH_MAX);
            if (!IS_ERR(path)) {
                // Check if path ends with our library name
                if (kstr_ends_with(path, lib_name)) {
                    uint64_t vma_size = vma->vm_end - vma->vm_start;
                    
                    // Take the first readable+executable mapping as base
                    if (found_base == 0 && (vma->vm_flags & VM_READ)) {
                        found_base = vma->vm_start;
                        // Calculate total size by looking at contiguous mappings
                        // of the same file
                        found_size = (uint32_t)vma_size;
                        kpm_info("Library '%s' found: base=0x%llx size=0x%llx flags=0x%lx path=%s\n",
                                 lib_name, vma->vm_start, vma_size, vma->vm_flags, path);
                    }
                }
            }
            kfree(path_buf);
        }
    }
    
    #if LINUX_VERSION_CODE >= KERNEL_VERSION(5, 8, 0)
    mmap_read_unlock(mm);
    #else
    up_read(&mm->mmap_sem);
    #endif
    
    if (mm) p_mmput(mm);
    if (p_put_task_struct && task) p_put_task_struct(task);
    
    if (found_base > 0) {
        *out_base = found_base;
        *out_size = found_size;
        return 0;
    }
    
    kpm_err("Library '%s' not found in process %d\n", lib_name, pid);
    return -ENOENT;
}

// ╔══════════════════════════════════════════════════════════════╗
// ║              OP_READ_VM / OP_WRITE_VM                        ║
// ╚══════════════════════════════════════════════════════════════╝

static void process_rw_packet(struct k_packet *pkt)
{
    struct task_struct *task = NULL;
    struct mm_struct *mm = NULL;
    pid_t target_pid;
    int transferred;
    unsigned int gup_flags;
    int is_write_op;
    uint8_t temp_buffer[MAX_INLINE];

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

    target_pid = pkt->target_pid;
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
    memset(temp_buffer, 0, MAX_INLINE);
    
    if (is_write_op) {
        memcpy(temp_buffer, pkt->inline_data, pkt->size);
        gup_flags = HFR_FOLL_WRITE | FOLL_FORCE;
    } else {
        gup_flags = FOLL_FORCE;
    }

    transferred = p_access_process_vm(task, (unsigned long)pkt->vaddr, 
                                       temp_buffer, (int)pkt->size, gup_flags);

    if (mm) p_mmput(mm);
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

// ╔══════════════════════════════════════════════════════════════╗
// ║               OP_FIND_PROCESS HANDLER                        ║
// ╚══════════════════════════════════════════════════════════════╝

static void process_find_packet(struct k_packet *pkt)
{
    pid_t found_pid = -1;
    char proc_name[256];
    int name_len;
    int ret;
    
    name_len = (int)pkt->size;
    if (name_len > 255) name_len = 255;
    memcpy(proc_name, pkt->inline_data, name_len);
    proc_name[name_len] = '\0';
    
    kpm_info("Finding process: '%s'\n", proc_name);
    
    ret = find_process_by_comm(proc_name, &found_pid);
    
    if (ret == 0 && found_pid > 0) {
        pkt->target_pid = (uint32_t)found_pid;
        pkt->vaddr = (uint64_t)found_pid;  // Extra copy for safety
        pkt->status = STATUS_SUCCESS;
    } else {
        pkt->target_pid = 0;
        pkt->vaddr = 0;
        pkt->status = STATUS_NOT_FOUND;
    }
}

// ╔══════════════════════════════════════════════════════════════╗
// ║               OP_GET_MODULE_BASE HANDLER                     ║
// ╚══════════════════════════════════════════════════════════════╝

static void process_module_packet(struct k_packet *pkt)
{
    uint64_t module_base = 0;
    uint32_t module_size = 0;
    char lib_name[256];
    int name_len;
    int ret;
    
    name_len = (int)pkt->size;
    if (name_len > 255) name_len = 255;
    memcpy(lib_name, pkt->inline_data, name_len);
    lib_name[name_len] = '\0';
    
    kpm_info("Finding module '%s' for PID %d\n", lib_name, pkt->target_pid);
    
    ret = get_module_base_from_vma(pkt->target_pid, lib_name, &module_base, &module_size);
    
    if (ret == 0 && module_base > 0) {
        pkt->vaddr = module_base;
        pkt->size = module_size;
        pkt->status = STATUS_SUCCESS;
    } else {
        pkt->vaddr = 0;
        pkt->size = 0;
        pkt->status = STATUS_NO_MODULE;
    }
}

// ╔══════════════════════════════════════════════════════════════╗
// ║               OP_CHECK_PROCESS HANDLER                       ║
// ╚══════════════════════════════════════════════════════════════╝

static void process_check_packet(struct k_packet *pkt)
{
    struct task_struct *task;
    
    if (pkt->target_pid <= 0) {
        pkt->status = STATUS_OUT_OF_RANGE;
        return;
    }
    
    if (!p_find_task_by_vpid) {
        pkt->status = STATUS_NULL_SYMBOL;
        return;
    }
    
    if (p_rcu_read_lock) p_rcu_read_lock();
    task = p_find_task_by_vpid((pid_t)pkt->target_pid);
    if (p_rcu_read_unlock) p_rcu_read_unlock();
    
    pkt->status = task ? STATUS_SUCCESS : STATUS_NO_TASK;
}

// ╔══════════════════════════════════════════════════════════════╗
// ║               MAIN PACKET DISPATCHER                         ║
// ╚══════════════════════════════════════════════════════════════╝

static void process_packet(struct k_packet *pkt, pid_t caller_pid)
{
    kpm_info("Packet: op=0x%x pid=%u addr=0x%llx size=%u caller=%d\n",
             pkt->op_code, pkt->target_pid, pkt->vaddr, pkt->size, caller_pid);

    switch (pkt->op_code) {
        case OP_READ_VM:
        case OP_WRITE_VM:
            process_rw_packet(pkt);
            break;
            
        case OP_FIND_PROCESS:
            process_find_packet(pkt);
            break;
            
        case OP_GET_MODULE_BASE:
            process_module_packet(pkt);
            break;
            
        case OP_CHECK_PROCESS:
            process_check_packet(pkt);
            break;
            
        default:
            kpm_err("Unknown opcode: 0x%x\n", pkt->op_code);
            pkt->status = STATUS_BAD_OPCODE;
            break;
    }
}

// ╔══════════════════════════════════════════════════════════════╗
// ║               PROCFS FILE HANDLERS                           ║
// ╚══════════════════════════════════════════════════════════════╝

static int proc_open_handler(struct inode *inode, struct file *file) 
{ 
    return 0; 
}

static int proc_release_handler(struct inode *inode, struct file *file) 
{ 
    return 0; 
}

static ssize_t proc_read_handler(struct file *file, char __user *buffer, 
                                  size_t count, loff_t *pos) 
{ 
    return 0; 
}

static ssize_t proc_write_handler(struct file *file, const char __user *buffer, 
                                   size_t count, loff_t *pos)
{
    struct k_packet local_pkt;
    pid_t caller_pid;
    struct task_struct *curr_task;

    if (count != sizeof(struct k_packet)) {
        kpm_err("SIZE MISMATCH: got %zu expected %zu\n", count, sizeof(struct k_packet));
        return -EINVAL;
    }

    if (!p_copy_from_user) {
        kpm_err("copy_from_user NULL\n");
        return -EFAULT;
    }
    
    if (p_copy_from_user(&local_pkt, buffer, sizeof(struct k_packet)) != 0) {
        kpm_err("copy_from_user failed\n");
        return -EFAULT;
    }

    curr_task = hfr_get_current();
    if (!curr_task) {
        kpm_err("get_current failed\n");
        return -ESRCH;
    }

    if (!p_task_pid_nr_ns) {
        kpm_err("task_pid_nr_ns NULL\n");
        return -EFAULT;
    }

    caller_pid = p_task_pid_nr_ns(curr_task, PIDTYPE_PID, NULL);
    
    if (caller_pid <= 0) {
        kpm_err("Invalid caller_pid: %d\n", caller_pid);
        return -ESRCH;
    }

    if (p_mutex_lock) p_mutex_lock(&hfr_mutex);
    process_packet(&local_pkt, caller_pid);
    if (p_mutex_unlock) p_mutex_unlock(&hfr_mutex);

    if (!p_copy_to_user) {
        kpm_err("copy_to_user NULL\n");
        return -EFAULT;
    }
    
    if (p_copy_to_user((void __user *)buffer, &local_pkt, sizeof(struct k_packet)) != 0) {
        kpm_err("copy_to_user failed\n");
        return -EFAULT;
    }

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

// ╔══════════════════════════════════════════════════════════════╗
// ║               INIT / EXIT                                    ║
// ╚══════════════════════════════════════════════════════════════╝

static long hfr_memory_init(const char *args, const char *event, void __user *reserved)
{
    kpm_info("=== INIT START ===\n");
    
    // Resolve all kernel symbols
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
    p_rcu_read_lock = (rcu_read_lock_t)kallsyms_lookup_name("__rcu_read_lock");
    p_rcu_read_unlock = (rcu_read_unlock_t)kallsyms_lookup_name("__rcu_read_unlock");
    p_mutex_init = (mutex_init_t)kallsyms_lookup_name("__mutex_init");
    p_mutex_lock = (mutex_lock_t)kallsyms_lookup_name("mutex_lock");
    p_mutex_unlock = (mutex_unlock_t)kallsyms_lookup_name("mutex_unlock");
    p_next_task = (next_task_t)kallsyms_lookup_name("next_task");

    kpm_info("Symbols: proc_create=%px access_vm=%px find_task=%px get_mm=%px next_task=%px\n",
             p_proc_create_data, p_access_process_vm, p_find_task_by_vpid, 
             p_get_task_mm, p_next_task);

    // Critical symbols check
    if (!p_proc_create_data || !p_access_process_vm || !p_find_task_by_vpid || 
        !p_task_pid_nr_ns || !p_get_task_mm || !p_mmput || !p_copy_from_user || 
        !p_copy_to_user) {
        kpm_err("CRITICAL SYMBOL MISSING\n");
        kpm_err("proc=%px vm=%px task=%px pid=%px mm=%px mmput=%px cfu=%px ctu=%px\n",
                p_proc_create_data, p_access_process_vm, p_find_task_by_vpid,
                p_task_pid_nr_ns, p_get_task_mm, p_mmput, p_copy_from_user, p_copy_to_user);
        return -EFAULT;
    }
    
    if (!p_next_task) {
        kpm_err("WARNING: next_task not found - process scanning will fail\n");
        // Don't hard fail - R/W will still work
    }

    if (p_mutex_init) p_mutex_init(&hfr_mutex);

    proc_entry = p_proc_create_data(proc_filename, 0666, NULL, &p_ops, NULL);
    if (!proc_entry) {
        kpm_err("proc_create FAILED\n");
        return -EFAULT;
    }

    kpm_info("=== INIT SUCCESS /proc/%s ===\n", proc_filename);
    return 0;
}

static long hfr_memory_exit(void __user *reserved)
{
    kpm_info("=== EXIT ===\n");
    if (proc_entry && p_remove_proc_entry) {
        p_remove_proc_entry(proc_filename, NULL);
    }
    return 0;
}

KPM_INIT(hfr_memory_init);
KPM_EXIT(hfr_memory_exit);
