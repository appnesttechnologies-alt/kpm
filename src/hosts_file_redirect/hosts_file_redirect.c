/* SPDX-License-Identifier: GPL-2.0-or-later */
/* Custom syscall 449 - Direct Panel Connection */

#include <compiler.h>
#include <hook.h>
#include <kpmodule.h>
#include <kputils.h>
#include <linux/sched.h>
#include <linux/errno.h>
#include <linux/printk.h>
#include <linux/string.h>

KPM_NAME("hosts_file_redirect");
KPM_VERSION(HFR_VERSION);
KPM_LICENSE("GPL v2");
KPM_AUTHOR("Surajit");
KPM_DESCRIPTION("Kernel memory r/w via custom syscall 449");

#define KPM_PREFIX "HFR_MEM"
#define kpm_info(fmt, ...) pr_info(KPM_PREFIX ": " fmt, ##__VA_ARGS__)
#define kpm_err(fmt, ...) pr_err(KPM_PREFIX ": " fmt, ##__VA_ARGS__)

#define GFP_KERNEL 0xcc0
#define MAX_INLINE 256
#define HFR_SYSCALL 449

#define OP_READ_VM 0x2000
#define OP_WRITE_VM 0x3000

#define STATUS_SUCCESS 0x0000
#define STATUS_INVALID_PID 0x1001
#define STATUS_PAGE_FAULT 0x1004

struct k_packet {
    uint32_t op_code;
    uint32_t target_pid;
    uint64_t target_addr;
    uint32_t size;
    uint32_t status;
    uint8_t inline_data[MAX_INLINE];
} __attribute__((aligned(8), packed));

typedef int (*access_process_vm_t)(void *, unsigned long, void *, int, int);
typedef void *(*find_task_by_vpid_t)(int);
typedef void *(*get_task_struct_t)(void *);
typedef void (*put_task_struct_t)(void *);
typedef void *(*kmalloc_t)(unsigned long, unsigned int);
typedef void (*kfree_t)(const void *);
typedef long (*sys_call_ptr_t)(long, long, long, long, long, long);

static access_process_vm_t p_vm;
static find_task_by_vpid_t p_find;
static get_task_struct_t p_get;
static put_task_struct_t p_put;
static kmalloc_t p_malloc;
static kfree_t p_free;

/* sys_call_table pointer - resolved via kallsyms */
static sys_call_ptr_t *sys_call_table = NULL;
static sys_call_ptr_t original_syscall = NULL;

/* Custom syscall handler */
static long hfr_syscall_handler(long a1, long a2, long a3, long a4, long a5, long a6)
{
    struct k_packet __user *user_pkt = (struct k_packet __user *)a1;
    struct k_packet pkt;
    
    if (!user_pkt) return -EINVAL;
    
    /* Copy from user */
    {
        const unsigned char __user *s = (void __user *)user_pkt;
        unsigned char *d = (unsigned char *)&pkt;
        long i;
        for (i = 0; i < sizeof(pkt); i++) {
            unsigned char byte;
            if (compat_copy_to_user(&byte, &s[i], 1)) return -EFAULT;
            d[i] = byte;
        }
    }
    
    pkt.status = STATUS_INVALID_PID;
    
    if (pkt.op_code == OP_READ_VM) {
        void *kbuf = p_malloc(pkt.size, GFP_KERNEL);
        if (kbuf) {
            void *t = p_find(pkt.target_pid);
            if (t) {
                p_get(t);
                int r = p_vm(t, pkt.target_addr, kbuf, pkt.size, 0);
                p_put(t);
                if (r == pkt.size) {
                    unsigned char *s = kbuf, *d = pkt.inline_data;
                    long i;
                    for (i = 0; i < pkt.size; i++) d[i] = s[i];
                    pkt.status = STATUS_SUCCESS;
                } else pkt.status = STATUS_PAGE_FAULT;
            }
            p_free(kbuf);
        }
    }
    else if (pkt.op_code == OP_WRITE_VM) {
        void *t = p_find(pkt.target_pid);
        if (t) {
            p_get(t);
            int r = p_vm(t, pkt.target_addr, pkt.inline_data, pkt.size, 1);
            p_put(t);
            pkt.status = (r == pkt.size) ? STATUS_SUCCESS : STATUS_PAGE_FAULT;
        }
    }
    
    /* Copy back to user */
    if (compat_copy_to_user(user_pkt, &pkt, sizeof(pkt))) return -EFAULT;
    return 0;
}

static long hfr_memory_init(const char *args, const char *event, void __user *reserved)
{
    p_vm = (access_process_vm_t)kallsyms_lookup_name("access_process_vm");
    p_find = (find_task_by_vpid_t)kallsyms_lookup_name("find_task_by_vpid");
    p_get = (get_task_struct_t)kallsyms_lookup_name("get_task_struct");
    p_put = (put_task_struct_t)kallsyms_lookup_name("put_task_struct");
    p_malloc = (kmalloc_t)kallsyms_lookup_name("__kmalloc");
    p_free = (kfree_t)kallsyms_lookup_name("kfree");
    
    /* Get sys_call_table */
    sys_call_table = (sys_call_ptr_t *)kallsyms_lookup_name("sys_call_table");
    
    if (!p_vm || !p_find || !p_malloc || !sys_call_table) {
        kpm_err("Symbol resolution failed\n");
        return -EFAULT;
    }
    
    /* Replace syscall 449 with our handler */
    original_syscall = sys_call_table[HFR_SYSCALL];
    sys_call_table[HFR_SYSCALL] = (sys_call_ptr_t)hfr_syscall_handler;
    
    kpm_info("Loaded! syscall %d hooked. Panel: syscall(%d, &pkt)\n", HFR_SYSCALL, HFR_SYSCALL);
    return 0;
}

static long hfr_memory_exit(void __user *reserved)
{
    if (sys_call_table && original_syscall) {
        sys_call_table[HFR_SYSCALL] = original_syscall;
    }
    kpm_info("Unloaded!\n");
    return 0;
}

KPM_INIT(hfr_memory_init);
KPM_EXIT(hfr_memory_exit);
