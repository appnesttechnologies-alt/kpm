/* SPDX-License-Identifier: GPL-2.0-or-later */
/* WORKING VERSION - loaded successfully before */

#include <compiler.h>
#include <hook.h>
#include <kpmodule.h>
#include <kputils.h>
#include <linux/sched.h>
#include <linux/errno.h>
#include <linux/printk.h>
#include <linux/string.h>
#include <linux/kernel.h>

KPM_NAME("hosts_file_redirect");
KPM_VERSION(HFR_VERSION);
KPM_LICENSE("GPL v2");
KPM_AUTHOR("Surajit");
KPM_DESCRIPTION("Kernel memory read/write debugger");

#define KPM_PREFIX "HFR_MEM"
#define kpm_info(fmt, ...) pr_info(KPM_PREFIX ": " fmt, ##__VA_ARGS__)
#define kpm_err(fmt, ...) pr_err(KPM_PREFIX ": " fmt, ##__VA_ARGS__)

#define GFP_KERNEL 0xcc0
#define MAX_DATA 256

typedef int (*access_process_vm_t)(void*, unsigned long, void*, int, int);
typedef void* (*find_task_by_vpid_t)(int);
typedef void* (*get_task_struct_t)(void*);
typedef void (*put_task_struct_t)(void*);
typedef void* (*kmalloc_t)(unsigned long, unsigned int);
typedef void (*kfree_t)(const void*);

static access_process_vm_t p_access_process_vm;
static find_task_by_vpid_t p_find_task_by_vpid;
static get_task_struct_t p_get_task_struct;
static put_task_struct_t p_put_task_struct;
static kmalloc_t p_kmalloc;
static kfree_t p_kfree;

static long hfr_control0(const char *ctl_args, char __user *out_msg, int outlen)
{
    char cmd;
    int pid;
    unsigned long addr;
    unsigned int size;
    unsigned int value = 0;
    char resp[512];
    int ret;

    if (!ctl_args || outlen < 1) return -EINVAL;

    if (sscanf(ctl_args, "%c,%d,%lx,%u,%u", &cmd, &pid, &addr, &size, &value) < 4) {
        snprintf(resp, sizeof(resp), "ERR");
        compat_copy_to_user(out_msg, resp, strlen(resp) + 1);
        return -EINVAL;
    }

    if (cmd == 'R' || cmd == 'r') {
        void *kbuf = p_kmalloc(size, GFP_KERNEL);
        if (!kbuf) {
            snprintf(resp, sizeof(resp), "ERR");
            compat_copy_to_user(out_msg, resp, strlen(resp) + 1);
            return -ENOMEM;
        }

        void *task = p_find_task_by_vpid(pid);
        if (!task) {
            p_kfree(kbuf);
            snprintf(resp, sizeof(resp), "ERR");
            compat_copy_to_user(out_msg, resp, strlen(resp) + 1);
            return -ESRCH;
        }

        p_get_task_struct(task);
        ret = p_access_process_vm(task, addr, kbuf, size, 0);
        p_put_task_struct(task);

        if (ret == size) {
            int off = snprintf(resp, sizeof(resp), "OK:");
            unsigned char *data = (unsigned char *)kbuf;
            for (int i = 0; i < size && off < sizeof(resp) - 3; i++)
                off += snprintf(resp + off, sizeof(resp) - off, "%02X", data[i]);
            compat_copy_to_user(out_msg, resp, off + 1);
        } else {
            snprintf(resp, sizeof(resp), "ERR");
            compat_copy_to_user(out_msg, resp, strlen(resp) + 1);
        }
        p_kfree(kbuf);
        return 0;
    }
    else if (cmd == 'W' || cmd == 'w') {
        void *task = p_find_task_by_vpid(pid);
        if (!task) {
            snprintf(resp, sizeof(resp), "ERR");
            compat_copy_to_user(out_msg, resp, strlen(resp) + 1);
            return -ESRCH;
        }

        p_get_task_struct(task);
        ret = p_access_process_vm(task, addr, &value, size, 1);
        p_put_task_struct(task);

        if (ret == size) {
            snprintf(resp, sizeof(resp), "OK");
        } else {
            snprintf(resp, sizeof(resp), "ERR");
        }
        compat_copy_to_user(out_msg, resp, strlen(resp) + 1);
        return 0;
    }

    snprintf(resp, sizeof(resp), "ERR");
    compat_copy_to_user(out_msg, resp, strlen(resp) + 1);
    return -EINVAL;
}

static long hfr_memory_init(const char *args, const char *event, void __user *reserved)
{
    p_access_process_vm = (access_process_vm_t)kallsyms_lookup_name("access_process_vm");
    p_find_task_by_vpid = (find_task_by_vpid_t)kallsyms_lookup_name("find_task_by_vpid");
    p_get_task_struct = (get_task_struct_t)kallsyms_lookup_name("get_task_struct");
    p_put_task_struct = (put_task_struct_t)kallsyms_lookup_name("put_task_struct");
    p_kmalloc = (kmalloc_t)kallsyms_lookup_name("__kmalloc");
    p_kfree = (kfree_t)kallsyms_lookup_name("kfree");

    if (!p_access_process_vm || !p_find_task_by_vpid || !p_kmalloc || !p_kfree) {
        kpm_err("symbol failed\n");
        return -EFAULT;
    }

    kpm_info("Loaded!\n");
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
