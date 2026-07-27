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
KPM_DESCRIPTION("INFO COLLECTOR - NO CRASH");

#define HFR_DEBUG
#ifdef HFR_DEBUG
#define hfr_log(fmt, ...) pr_info("HFR: " fmt, ##__VA_ARGS__)
#define hfr_err(fmt, ...)  pr_err("HFR: " fmt, ##__VA_ARGS__)
#else
#define hfr_log(fmt, ...)
#define hfr_err(fmt, ...)
#endif

struct k_packet {
    uint32_t op_code;
    uint32_t target_pid;
    uint64_t vaddr;
    uint32_t size;
    uint32_t status;
    uint8_t  inline_data[256];
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
typedef struct task_struct *(*find_task_by_vpid_t)(pid_t);
typedef struct mm_struct *(*get_task_mm_t)(struct task_struct *);
typedef void (*mmput_t)(struct mm_struct *);
typedef struct task_struct *(*get_task_struct_t)(struct task_struct *);
typedef void (*put_task_struct_t)(struct task_struct *);

static proc_create_data_t    p_proc_create_data = NULL;
static remove_proc_entry_t   p_remove_proc_entry = NULL;
static find_task_by_vpid_t   p_find_task_by_vpid = NULL;
static get_task_mm_t         p_get_task_mm = NULL;
static mmput_t               p_mmput = NULL;
static get_task_struct_t     p_get_task_struct = NULL;
static put_task_struct_t     p_put_task_struct = NULL;

static const char *proc_filename = "hfr_mem";
static void       *proc_entry    = NULL;

static inline struct task_struct *hfr_get_current(void)
{
    struct task_struct *tsk;
    asm volatile("mrs %0, sp_el0" : "=r" (tsk));
    return tsk;
}

static long hfr_memory_init(const char *args, const char *event, void __user *reserved)
{
    hfr_log("========================================");
    hfr_log("=== INFO COLLECTOR START ===");
    hfr_log("========================================");
    
    // 1. Resolve symbols
    p_proc_create_data = (proc_create_data_t)kallsyms_lookup_name("proc_create_data");
    p_remove_proc_entry = (remove_proc_entry_t)kallsyms_lookup_name("remove_proc_entry");
    p_find_task_by_vpid = (find_task_by_vpid_t)kallsyms_lookup_name("find_task_by_vpid");
    p_get_task_mm = (get_task_mm_t)kallsyms_lookup_name("get_task_mm");
    p_mmput = (mmput_t)kallsyms_lookup_name("mmput");
    p_get_task_struct = (get_task_struct_t)kallsyms_lookup_name("get_task_struct");
    p_put_task_struct = (put_task_struct_t)kallsyms_lookup_name("put_task_struct");
    
    hfr_log("Symbols: proc=%px find=%px get_mm=%px mmput=%px",
             p_proc_create_data, p_find_task_by_vpid, p_get_task_mm, p_mmput);
    
    // 2. Get memstart_addr VALUE
    unsigned long *memstart_ptr = (unsigned long *)kallsyms_lookup_name("memstart_addr");
    if (memstart_ptr) {
        unsigned long memstart_val = *memstart_ptr;
        hfr_log("memstart_addr ptr=%px value=0x%llx", memstart_ptr, memstart_val);
    } else {
        hfr_log("memstart_addr: NOT FOUND");
    }
    
    // 3. Get kimage_voffset
    unsigned long *kimage_ptr = (unsigned long *)kallsyms_lookup_name("kimage_voffset");
    if (kimage_ptr) {
        hfr_log("kimage_voffset ptr=%px value=0x%llx", kimage_ptr, *kimage_ptr);
    } else {
        hfr_log("kimage_voffset: NOT FOUND");
    }
    
    // 4. Get physvirt_offset
    unsigned long *physvirt_ptr = (unsigned long *)kallsyms_lookup_name("physvirt_offset");
    if (physvirt_ptr) {
        hfr_log("physvirt_offset ptr=%px value=0x%llx", physvirt_ptr, *physvirt_ptr);
    } else {
        hfr_log("physvirt_offset: NOT FOUND");
    }
    
    // 5. Get _text (kernel start)
    unsigned long *text_ptr = (unsigned long *)kallsyms_lookup_name("_text");
    if (text_ptr) {
        hfr_log("_text: %px", text_ptr);
    }
    
    // 6. Get swapper_pg_dir
    unsigned long *swapper_ptr = (unsigned long *)kallsyms_lookup_name("swapper_pg_dir");
    if (swapper_ptr) {
        hfr_log("swapper_pg_dir: %px", swapper_ptr);
    }
    
    // 7. Calculated PAGE_OFFSET
    unsigned long page_offset_calc = -(1UL << 39);
    hfr_log("Calculated PAGE_OFFSET (39-bit): 0x%llx", page_offset_calc);
    
    // 8. Dump current task's mm_struct
    struct task_struct *curr = hfr_get_current();
    if (curr) {
        hfr_log("Current task: %px", curr);
        
        if (p_get_task_mm) {
            struct mm_struct *mm = p_get_task_mm(curr);
            if (mm) {
                hfr_log("mm_struct: %px", mm);
                hfr_log("Dumping mm_struct first 20 unsigned longs:");
                unsigned long *mm_ptr = (unsigned long *)mm;
                for (int i = 0; i < 20; i++) {
                    hfr_log("  mm[%2d] @ +0x%02x = 0x%016llx", i, i*8, mm_ptr[i]);
                }
                p_mmput(mm);
            } else {
                hfr_log("get_task_mm returned NULL!");
            }
        }
    } else {
        hfr_log("get_current returned NULL!");
    }
    
    // 9. Create proc entry
    if (p_proc_create_data) {
        proc_entry = p_proc_create_data(proc_filename, 0666, NULL, NULL, NULL);
        if (proc_entry) {
            hfr_log("/proc/%s created", proc_filename);
        }
    }
    
    hfr_log("========================================");
    hfr_log("=== INFO COLLECTOR DONE ===");
    hfr_log("========================================");
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
