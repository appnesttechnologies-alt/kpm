/* SPDX-License-Identifier: GPL-2.0-or-later */
/* Direct panel connection via KPM_CTL0 - ctl_args is kernel pointer */

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
KPM_DESCRIPTION("Kernel memory read/write debugger");

#define KPM_PREFIX "HFR_MEM"
#define kpm_info(fmt, ...) pr_info(KPM_PREFIX ": " fmt, ##__VA_ARGS__)
#define kpm_err(fmt, ...) pr_err(KPM_PREFIX ": " fmt, ##__VA_ARGS__)

#define GFP_KERNEL 0xcc0
#define PAGE_SIZE 4096
#define MAX_INLINE_DATA 256

#define OP_RESOLVE_BASE 0x1000
#define OP_READ_VM 0x2000
#define OP_WRITE_VM 0x3000
#define OP_QUERY_PHYS 0x4000

#define STATUS_SUCCESS 0x0000
#define STATUS_INVALID_PID 0x1001
#define STATUS_INVALID_ADDR 0x1002
#define STATUS_ACCESS_DENIED 0x1003
#define STATUS_PAGE_FAULT 0x1004
#define STATUS_INVALID_SIZE 0x1005
#define STATUS_MEM_ALLOC_FAIL 0x1008
#define STATUS_COPY_FAIL 0x1009
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

/* Function pointers */
typedef int (*access_process_vm_t)(struct task_struct *, unsigned long, void *, int, int);
typedef struct task_struct *(*get_task_struct_t)(struct task_struct *);
typedef void (*put_task_struct_t)(struct task_struct *);
typedef struct task_struct *(*find_task_by_vpid_t)(pid_t);
typedef void *(*kmalloc_t)(unsigned long, unsigned int);
typedef void (*kfree_t)(const void *);

static access_process_vm_t p_access_process_vm;
static get_task_struct_t p_get_task_struct;
static put_task_struct_t p_put_task_struct;
static find_task_by_vpid_t p_find_task_by_vpid;
static kmalloc_t p_kmalloc;
static kfree_t p_kfree;

/* Process packet - works on kernel pointer */
static void process_packet(struct k_packet *pkt)
{
    int ret;

    if (!pkt) return;
    pkt->status = STATUS_MODULE_BUSY;

    if (pkt->op_code == OP_READ_VM) {
        void *kbuf;
        if (!pkt->size || pkt->size > MAX_INLINE_DATA) {
            pkt->status = STATUS_INVALID_SIZE;
            return;
        }
        kbuf = p_kmalloc(pkt->size, GFP_KERNEL);
        if (!kbuf) {
            pkt->status = STATUS_MEM_ALLOC_FAIL;
            return;
        }

        struct task_struct *task = p_find_task_by_vpid(pkt->target_pid);
        if (!task) {
            pkt->status = STATUS_INVALID_PID;
            p_kfree(kbuf);
            return;
        }

        p_get_task_struct(task);
        ret = p_access_process_vm(task, pkt->target_addr, kbuf, pkt->size, 0);
        p_put_task_struct(task);

        if (ret == pkt->size) {
            memcpy(pkt->inline_data, kbuf, pkt->size);
            pkt->status = STATUS_SUCCESS;
            pkt->page_count = (pkt->size + PAGE_SIZE - 1) / PAGE_SIZE;
        } else {
            pkt->status = STATUS_PAGE_FAULT;
        }
        p_kfree(kbuf);
    }
    else if (pkt->op_code == OP_WRITE_VM) {
        if (!pkt->size || pkt->size > MAX_INLINE_DATA) {
            pkt->status = STATUS_INVALID_SIZE;
            return;
        }

        struct task_struct *task = p_find_task_by_vpid(pkt->target_pid);
        if (!task) {
            pkt->status = STATUS_INVALID_PID;
            return;
        }

        p_get_task_struct(task);
        ret = p_access_process_vm(task, pkt->target_addr, pkt->inline_data, pkt->size, 1);
        p_put_task_struct(task);

        if (ret == pkt->size) {
            pkt->status = STATUS_SUCCESS;
            pkt->page_count = (pkt->size + PAGE_SIZE - 1) / PAGE_SIZE;
        } else {
            pkt->status = STATUS_PAGE_FAULT;
        }
    }
    else if (pkt->op_code == OP_RESOLVE_BASE) {
        pkt->status = STATUS_INVALID_ADDR;
        pkt->resolved_base = 0;
    }
    else if (pkt->op_code == OP_QUERY_PHYS) {
        pkt->status = STATUS_INVALID_ADDR;
        pkt->physical_addr = 0;
    }
}

/* KPM_CTL0 handler - ctl_args is kernel pointer from APatch */
static long hfr_control0(const char *ctl_args, char __user *out_msg, int outlen)
{
    struct k_packet *pkt;

    if (!ctl_args || outlen < sizeof(struct k_packet)) {
        kpm_err("control: invalid args, outlen=%d\n", outlen);
        return -EINVAL;
    }

    /* ctl_args is already a kernel pointer - cast directly */
    pkt = (struct k_packet *)ctl_args;

    /* Process the packet */
    process_packet(pkt);

    /* Copy result back to out_msg */
    if (compat_copy_to_user(out_msg, pkt, sizeof(struct k_packet))) {
        kpm_err("control: failed to copy result\n");
        return -EFAULT;
    }

    return 0;
}

static long hfr_memory_init(const char *args, const char *event, void __user *reserved)
{
    p_access_process_vm = (access_process_vm_t)kallsyms_lookup_name("access_process_vm");
    p_get_task_struct = (get_task_struct_t)kallsyms_lookup_name("get_task_struct");
    p_put_task_struct = (put_task_struct_t)kallsyms_lookup_name("put_task_struct");
    p_find_task_by_vpid = (find_task_by_vpid_t)kallsyms_lookup_name("find_task_by_vpid");
    p_kmalloc = (kmalloc_t)kallsyms_lookup_name("__kmalloc");
    p_kfree = (kfree_t)kallsyms_lookup_name("kfree");

    if (!p_access_process_vm || !p_find_task_by_vpid || !p_kmalloc || !p_kfree ||
        !p_get_task_struct || !p_put_task_struct) {
        kpm_err("Symbol resolution failed\n");
        return -EFAULT;
    }

    kpm_info("Loaded! Ready for control calls\n");
    return 0;
}

static long hfr_memory_exit(void __user *reserved)
{
    kpm_info("Unloaded!\n");
    return 0;
}

KPM_INIT(hfr_memory_init);
KPM_CTL0(hfr_control0);
KPM_EXIT(hfr_memory_exit);
