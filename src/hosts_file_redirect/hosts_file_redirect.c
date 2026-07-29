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
#include <linux/sched.h>
#include <linux/sched/task.h>

KPM_NAME("hosts_file_redirect");
KPM_VERSION(HFR_VERSION);
KPM_LICENSE("GPL v2");
KPM_AUTHOR("Surajit");
KPM_DESCRIPTION("KPM Dynamic Symbol Resolved Memory Bridge via access_process_vm");

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
#define OP_FIND_PID_BY_NAME  0x4000
#define OP_FIND_LIB_BASE     0x5000

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
#define STATUS_LIB_NOT_FOUND  0x100F

#define HFR_FOLL_WRITE        0x01
#define FOLL_FORCE            0x10

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

// Function pointer typedefs
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
typedef void (*mutex_init_t)(struct mutex *);
typedef void (*mutex_lock_t)(struct mutex *);
typedef void (*mutex_unlock_t)(struct mutex *);
typedef void *(*kmalloc_t)(unsigned long, int);
typedef void (*kfree_t)(const void *);
typedef int (*strcmp_t)(const char *, const char *);
typedef char *(*strstr_t)(const char *, const char *);
typedef void *(*memset_t)(void *, int, unsigned long);
typedef void *(*memcpy_t)(void *, const void *, unsigned long);
typedef char *(*dentry_path_raw_t)(void *, char *, int);
typedef void (*down_read_t)(void *);
typedef void (*up_read_t)(void *);
typedef struct task_struct *(*next_task_t)(struct task_struct *);
typedef pid_t (*task_tgid_nr_ns_t)(struct task_struct *, enum pid_type, struct pid_namespace *);
typedef char *(*get_task_comm_t)(char *, struct task_struct *);

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
static mutex_init_t          p_mutex_init;
static mutex_lock_t          p_mutex_lock;
static mutex_unlock_t        p_mutex_unlock;
static kmalloc_t             p_kmalloc;
static kfree_t               p_kfree;
static strcmp_t              p_strcmp;
static strstr_t              p_strstr;
static memset_t              p_memset;
static memcpy_t              p_memcpy;
static dentry_path_raw_t     p_dentry_path_raw;
static down_read_t           p_down_read;
static up_read_t             p_up_read;
static next_task_t           p_next_task;
static task_tgid_nr_ns_t     p_task_tgid_nr_ns;
static get_task_comm_t       p_get_task_comm;

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
    if (addr == 0) return 0;
    if (addr >= (1ULL << 63)) return 0;
    return 1;
}
//FF PID FINDING

static pid_t find_pid_by_name(const char *name)
{
    struct task_struct *task;
    struct task_struct *init_task_ptr;
    pid_t found_pid = 0;

    char comm[TASK_COMM_LEN];

    if (!name || !name[0])
        return 0;

    if (!p_next_task || !p_get_task_comm || !p_task_pid_nr_ns)
        return 0;

    init_task_ptr = (struct task_struct *)kallsyms_lookup_name("init_task");

    if (!init_task_ptr)
        return 0;


    task = init_task_ptr;

    do {

        task = p_next_task(task);

        if (!task)
            break;


        memset(comm, 0, sizeof(comm));

        p_get_task_comm(comm, task);


        if (strcmp(comm, name) == 0) {

            found_pid = p_task_pid_nr_ns(
                task,
                PIDTYPE_PID,
                NULL
            );

            kpm_info("FOUND %s pid=%d\n",
                     comm,
                     found_pid);

            break;
        }


    } while (task != init_task_ptr);


    return found_pid;
}

// Find library base address using dynamic functions
static unsigned long find_lib_base_by_name(struct task_struct *task, const char *lib_name)
{
    struct mm_struct *mm;
    unsigned long base = 0;
    void *path_buffer = NULL;
    unsigned long vma_addr;

    if (!task || !lib_name || !lib_name[0] || !p_dentry_path_raw || !p_down_read || !p_up_read || !p_kmalloc || !p_kfree || !p_strstr)
        return 0;

    mm = p_get_task_mm(task);
    if (!mm) {
        kpm_err("find_lib_base: no mm for task\n");
        return 0;
    }

    path_buffer = p_kmalloc(512, 0xCC0); // GFP_KERNEL = 0xCC0
    if (!path_buffer) {
        p_mmput(mm);
        return 0;
    }

    // Lock mmap_sem
    p_down_read((void *)((unsigned long)mm + 104)); // offset of mmap_sem in mm_struct

    // Get mmap pointer from mm_struct (offset 0 in mm_struct for aarch64)
    vma_addr = *(unsigned long *)mm;

    while (vma_addr) {
        unsigned long vm_start = *(unsigned long *)(vma_addr + 0);
        unsigned long vm_next = *(unsigned long *)(vma_addr + 16);
        void *vm_file = *(void **)(vma_addr + 96);

        if (vm_file) {
            // f_path.dentry is at offset 24 in struct file
            void *dentry = *(void **)((unsigned long)vm_file + 24);
            
            if (dentry) {
                char *path = p_dentry_path_raw(dentry, (char *)path_buffer, 512);
                if (path && (unsigned long)path > 0x1000 && (unsigned long)path < 0xffff000000000000ULL) {
                    if (p_strstr(path, lib_name)) {
                        base = vm_start;
                        kpm_info("Found lib '%s' at 0x%lx\n", lib_name, base);
                        break;
                    }
                }
            }
        }
        
        vma_addr = vm_next;
    }

    p_up_read((void *)((unsigned long)mm + 104));
    p_kfree(path_buffer);
    p_mmput(mm);
    
    return base;
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

    kpm_info(">>> process_packet ENTER: op=0x%x pid=%u addr=0x%llx size=%u caller_pid=%d\n",
             pkt->op_code, pkt->target_pid, pkt->vaddr, pkt->size, caller_pid);

        // Handle OP_FIND_PID_BY_NAME
    if (pkt->op_code == OP_FIND_PID_BY_NAME) {
        char name[TASK_COMM_LEN];
        if (p_memset) p_memset(name, 0, sizeof(name));
        else memset(name, 0, sizeof(name));
        
        strncpy(name, (const char *)pkt->inline_data, sizeof(name) - 1);
        name[sizeof(name) - 1] = '\0';

        pid_t pid = find_pid_by_name(name);
        if (pid <= 0) {
            kpm_err("Process not found for name: '%s'\n", name);
            pkt->status = STATUS_NO_TASK;
        } else {
            pkt->target_pid = (uint32_t)pid;
            pkt->status = STATUS_SUCCESS;
            kpm_info("OP_FIND_PID_BY_NAME SUCCESS: pid=%d\n", pid);
        }
        return;
    }

    // Handle OP_FIND_LIB_BASE
    if (pkt->op_code == OP_FIND_LIB_BASE) {
        char lib_name[64];
        if (p_memset) p_memset(lib_name, 0, sizeof(lib_name));
        else memset(lib_name, 0, sizeof(lib_name));
        
        strncpy(lib_name, (const char *)pkt->inline_data, sizeof(lib_name) - 1);
        lib_name[sizeof(lib_name) - 1] = '\0';

        target_pid = pkt->target_pid ? (pid_t)pkt->target_pid : caller_pid;
        if (target_pid <= 0) {
            pkt->status = STATUS_OUT_OF_RANGE;
            return;
        }

        task = p_find_task_by_vpid(target_pid);
        if (!task) {
            pkt->status = STATUS_NO_TASK;
            return;
        }

        unsigned long base = find_lib_base_by_name(task, lib_name);
        if (base == 0) {
            pkt->status = STATUS_LIB_NOT_FOUND;
        } else {
            pkt->vaddr = (uint64_t)base;
            pkt->status = STATUS_SUCCESS;
            kpm_info("OP_FIND_LIB_BASE SUCCESS: lib=%s base=0x%lx\n", lib_name, base);
        }
        return;
    }


        

    // Existing READ/WRITE logic
    if (pkt->op_code != OP_READ_VM && pkt->op_code != OP_WRITE_VM) {
        kpm_err("BAD_OPCODE: 0x%x\n", pkt->op_code);
        pkt->status = STATUS_BAD_OPCODE;
        return;
    }

    if (!pkt->size || pkt->size > MAX_INLINE) {
        kpm_err("INVALID_SIZE: %u\n", pkt->size);
        pkt->status = STATUS_INVALID_SIZE;
        return;
    }

    if (!is_valid_user_address(pkt->vaddr)) {
        kpm_err("INVALID_ADDR: 0x%llx\n", pkt->vaddr);
        pkt->status = STATUS_INVALID_ADDR;
        return;
    }

    if (!p_access_process_vm || !p_find_task_by_vpid || !p_get_task_mm || !p_mmput) {
        kpm_err("NULL_SYMBOL\n");
        pkt->status = STATUS_NULL_SYMBOL;
        return;
    }

    target_pid = pkt->target_pid ? (pid_t)pkt->target_pid : caller_pid;
    kpm_info("target_pid resolved: %d\n", target_pid);
    
    if (target_pid <= 0) {
        kpm_err("OUT_OF_RANGE: pid=%d\n", target_pid);
        pkt->status = STATUS_OUT_OF_RANGE;
        return;
    }

    task = p_find_task_by_vpid(target_pid);
    kpm_info("find_task_by_vpid(%d) = %px\n", target_pid, task);
    
    if (!task) {
        kpm_err("NO_TASK for pid=%d\n", target_pid);
        pkt->status = STATUS_NO_TASK;
        return;
    }

    if (p_get_task_struct) p_get_task_struct(task);
    mm = p_get_task_mm(task);
    kpm_info("get_task_mm = %px\n", mm);

    if (!mm) {
        kpm_err("NO_MM\n");
        pkt->status = STATUS_NO_MM;
        if (p_put_task_struct && task) p_put_task_struct(task);
        return;
    }

    is_write_op = (pkt->op_code == OP_WRITE_VM);
    if (p_memset) p_memset(temp_buffer, 0, MAX_INLINE);
    else memset(temp_buffer, 0, MAX_INLINE);
    
    if (is_write_op) {
        if (p_memcpy) p_memcpy(temp_buffer, pkt->inline_data, pkt->size);
        else memcpy(temp_buffer, pkt->inline_data, pkt->size);
        gup_flags = HFR_FOLL_WRITE | FOLL_FORCE; 
    } else {
        gup_flags = FOLL_FORCE;                  
    }

    kpm_info("Calling access_process_vm: task=%px addr=0x%llx size=%d write=%d\n",
             task, (unsigned long)pkt->vaddr, (int)pkt->size, is_write_op);
    
    transferred = p_access_process_vm(task, (unsigned long)pkt->vaddr, temp_buffer, (int)pkt->size, gup_flags);
    kpm_info("access_process_vm returned: %d\n", transferred);

    if (mm) p_mmput(mm);
    if (p_put_task_struct && task) p_put_task_struct(task);

    if (transferred < 0) {
        kpm_err("VM_FAULT: %d\n", transferred);
        pkt->status = STATUS_VM_FAULT;
        return;
    }

    if (transferred == 0 && pkt->size > 0) {
        kpm_err("PROTECTION\n");
        pkt->status = STATUS_PROTECTION;
        return;
    }

    if (!is_write_op && transferred > 0) {
        if (p_memset) p_memset(pkt->inline_data, 0, MAX_INLINE);
        else memset(pkt->inline_data, 0, MAX_INLINE);
        
        if (p_memcpy) p_memcpy(pkt->inline_data, temp_buffer, transferred);
        else memcpy(pkt->inline_data, temp_buffer, transferred);
    }

    if ((uint32_t)transferred != pkt->size) {
        kpm_info("PARTIAL_IO: wanted %u got %d\n", pkt->size, transferred);
        pkt->size = (uint32_t)transferred;
        pkt->status = STATUS_PARTIAL_IO;
        return;
    }

    kpm_info("<<< process_packet SUCCESS\n");
    pkt->status = STATUS_SUCCESS;
}

static int proc_open_handler(struct inode *inode, struct file *file) { return 0; }
static int proc_release_handler(struct inode *inode, struct file *file) { return 0; }
static ssize_t proc_read_handler(struct file *file, char __user *buffer, size_t count, loff_t *pos) { return 0; }

static ssize_t proc_write_handler(struct file *file, const char __user *buffer, size_t count, loff_t *pos)
{
    struct k_packet local_pkt;
    pid_t caller_pid;
    struct task_struct *curr_task;

    kpm_info("*** proc_write_handler: count=%zu expected=%zu\n", count, sizeof(struct k_packet));

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
    kpm_info("caller_pid from current task: %d\n", caller_pid);
    
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

    kpm_info("*** proc_write_handler SUCCESS\n");
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
    kpm_info("=== INIT START ===\n");
    
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
    
    // Additional dynamic functions
    p_kmalloc = (kmalloc_t)kallsyms_lookup_name("__kmalloc");
    if (!p_kmalloc) p_kmalloc = (kmalloc_t)kallsyms_lookup_name("kmalloc");
    p_kfree = (kfree_t)kallsyms_lookup_name("kfree");
    p_strcmp = (strcmp_t)kallsyms_lookup_name("strcmp");
    p_strstr = (strstr_t)kallsyms_lookup_name("strstr");
    p_memset = (memset_t)kallsyms_lookup_name("memset");
    p_memcpy = (memcpy_t)kallsyms_lookup_name("memcpy");
    p_dentry_path_raw = (dentry_path_raw_t)kallsyms_lookup_name("dentry_path_raw");
    p_down_read = (down_read_t)kallsyms_lookup_name("down_read");
    p_up_read = (up_read_t)kallsyms_lookup_name("up_read");
    p_next_task = (next_task_t)kallsyms_lookup_name("next_task");
    p_task_tgid_nr_ns = (task_tgid_nr_ns_t)kallsyms_lookup_name("task_tgid_nr_ns");
    if (!p_task_tgid_nr_ns) p_task_tgid_nr_ns = (task_tgid_nr_ns_t)kallsyms_lookup_name("__task_tgid_nr_ns");
    p_get_task_comm = (get_task_comm_t)kallsyms_lookup_name("get_task_comm");

    kpm_info("Symbols resolved: proc=%px vm=%px task=%px\n",
             p_proc_create_data, p_access_process_vm, p_find_task_by_vpid);

    if (!p_proc_create_data || !p_access_process_vm || !p_find_task_by_vpid || 
        !p_task_pid_nr_ns || !p_get_task_mm || !p_mmput || !p_copy_from_user || !p_copy_to_user) {
        kpm_err("CRITICAL SYMBOL MISSING\n");
        return -EFAULT;
    }

    if (p_mutex_init) p_mutex_init(&hfr_mutex);

    proc_entry = p_proc_create_data(proc_filename, 0600, NULL, &p_ops, NULL);
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
    if (proc_entry && p_remove_proc_entry) p_remove_proc_entry(proc_filename, NULL);
    return 0;
}

KPM_INIT(hfr_memory_init);
KPM_EXIT(hfr_memory_exit);
