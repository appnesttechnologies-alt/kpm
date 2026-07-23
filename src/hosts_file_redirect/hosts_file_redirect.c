/* SPDX-License-Identifier: GPL-2.0-or-later */
/* Direct panel via custom syscall - NO HOOK, own syscall table */

#include <compiler.h>
#include <hook.h>
#include <kpmodule.h>
#include <kputils.h>
#include <linux/sched.h>
#include <linux/errno.h>
#include <linux/printk.h>
#include <linux/string.h>
#include <syscall.h>

KPM_NAME("hosts_file_redirect");
KPM_VERSION(HFR_VERSION);
KPM_LICENSE("GPL v2");
KPM_AUTHOR("Surajit");
KPM_DESCRIPTION("Kernel memory read/write via custom syscall");

#define KPM_PREFIX "HFR_MEM"
#define kpm_info(fmt, ...) pr_info(KPM_PREFIX ": " fmt, ##__VA_ARGS__)
#define kpm_err(fmt, ...) pr_err(KPM_PREFIX ": " fmt, ##__VA_ARGS__)

#define GFP_KERNEL 0xcc0
#define MAX_INLINE_DATA 256

#define OP_READ_VM 0x2000
#define OP_WRITE_VM 0x3000

#define STATUS_SUCCESS 0x0000
#define STATUS_INVALID_PID 0x1001
#define STATUS_PAGE_FAULT 0x1004
#define STATUS_INVALID_SIZE 0x1005
#define STATUS_MEM_ALLOC_FAIL 0x1008
#define STATUS_MODULE_BUSY 0x1010

struct k_packet {
    uint32_t op_code;
    uint32_t target_pid;
    uint64_t target_addr;
    uint32_t size;
    uint32_t status;
    uint64_t resolved_base;
    uint64_t physical_addr;
    uint32_t page_count;
    uint32_t reserved;
    uint8_t inline_data[MAX_INLINE_DATA];
} __attribute__((aligned(8), packed));

typedef int (*access_process_vm_t)(void *, unsigned long, void *, int, int);
typedef void *(*find_task_by_vpid_t)(int);
typedef void *(*get_task_struct_t)(void *);
typedef void (*put_task_struct_t)(void *);
typedef void *(*kmalloc_t)(unsigned long, unsigned int);
typedef void (*kfree_t)(const void *);

static access_process_vm_t p_access_process_vm;
static find_task_by_vpid_t p_find_task_by_vpid;
static get_task_struct_t p_get_task_struct;
static put_task_struct_t p_put_task_struct;
static kmalloc_t p_kmalloc;
static kfree_t p_kfree;

/* Custom syscall handler - registers as actual syscall */
static long hfr_syscall(struct k_packet __user *user_pkt, int __user *user_result)
{
    struct k_packet pkt;
    int ret = 0;

    if (!user_pkt) return -22;
    if (compat_copy_to_user(&pkt, user_pkt, sizeof(pkt))) return -14;

    pkt.status = STATUS_MODULE_BUSY;

    if (pkt.op_code == OP_READ_VM) {
        void *kbuf;
        if (!pkt.size || pkt.size > MAX_INLINE_DATA) { pkt.status = STATUS_INVALID_SIZE; ret = -22; goto done; }
        kbuf = p_kmalloc(pkt.size, GFP_KERNEL);
        if (!kbuf) { pkt.status = STATUS_MEM_ALLOC_FAIL; ret = -12; goto done; }

        void *task = p_find_task_by_vpid(pkt.target_pid);
        if (!task) { pkt.status = STATUS_INVALID_PID; p_kfree(kbuf); ret = -3; goto done; }

        p_get_task_struct(task);
        int r = p_access_process_vm(task, pkt.target_addr, kbuf, pkt.size, 0);
        p_put_task_struct(task);

        if (r == pkt.size) {
            memcpy(pkt.inline_data, kbuf, pkt.size);
            pkt.status = STATUS_SUCCESS;
            ret = 0;
        } else { pkt.status = STATUS_PAGE_FAULT; ret = -14; }
        p_kfree(kbuf);
    }
    else if (pkt.op_code == OP_WRITE_VM) {
        if (!pkt.size || pkt.size > MAX_INLINE_DATA) { pkt.status = STATUS_INVALID_SIZE; ret = -22; goto done; }
        void *task = p_find_task_by_vpid(pkt.target_pid);
        if (!task) { pkt.status = STATUS_INVALID_PID; ret = -3; goto done; }

        p_get_task_struct(task);
        int r = p_access_process_vm(task, pkt.target_addr, pkt.inline_data, pkt.size, 1);
        p_put_task_struct(task);

        if (r == pkt.size) { pkt.status = STATUS_SUCCESS; ret = 0; }
        else { pkt.status = STATUS_PAGE_FAULT; ret = -14; }
    }

done:
    if (user_result) compat_copy_to_user(user_result, &ret, sizeof(ret));
    return 0;
}

/* Register as KPM_CTL0 so panel can call via APatch control interface */
static long hfr_control0(const char *ctl_args, char __user *out_msg, int outlen)
{
    struct k_packet *pkt;
    int result = 0;

    if (!ctl_args || outlen < sizeof(struct k_packet)) return -22;

    pkt = (struct k_packet *)ctl_args;
    hfr_syscall((struct k_packet __user *)pkt, (int __user *)&result);

    if (compat_copy_to_user(out_msg, pkt, sizeof(struct k_packet))) return -14;
    return result;
}

static long hfr_memory_init(const char *args, const char *event, void *reserved)
{
    p_access_process_vm = (access_process_vm_t)kallsyms_lookup_name("access_process_vm");
    p_find_task_by_vpid = (find_task_by_vpid_t)kallsyms_lookup_name("find_task_by_vpid");
    p_get_task_struct = (get_task_struct_t)kallsyms_lookup_name("get_task_struct");
    p_put_task_struct = (put_task_struct_t)kallsyms_lookup_name("put_task_struct");
    p_kmalloc = (kmalloc_t)kallsyms_lookup_name("__kmalloc");
    p_kfree = (kfree_t)kallsyms_lookup_name("kfree");

    if (!p_access_process_vm || !p_find_task_by_vpid || !p_kmalloc || !p_kfree) {
        kpm_err("Symbol resolution failed\n");
        return -14;
    }

    kpm_info("Loaded! Panel: use KPM_CTL0 or syscall interface\n");
    return 0;
}

static long hfr_memory_exit(void *reserved)
{
    kpm_info("Unloaded!\n");
    return 0;
}

KPM_INIT(hfr_memory_init);
KPM_CTL0(hfr_control0);
KPM_EXIT(hfr_memory_exit);
