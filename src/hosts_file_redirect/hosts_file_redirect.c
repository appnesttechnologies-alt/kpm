/* SPDX-License-Identifier: GPL-2.0-or-later */
/* /proc/hfr_mem - direct panel access */

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
KPM_DESCRIPTION("Single-file self-contained kernel memory read/write debugger.");

#define KPM_PREFIX "HFR_MEM"
#define kpm_info(fmt, ...) pr_info(KPM_PREFIX ": " fmt, ##__VA_ARGS__)
#define kpm_err(fmt, ...) pr_err(KPM_PREFIX ": " fmt, ##__VA_ARGS__)

#define GFP_KERNEL 0xcc0
#define MAX_INLINE 256

#define OP_READ_VM 0x2000
#define OP_WRITE_VM 0x3000

#define STATUS_SUCCESS 0x0000
#define STATUS_INVALID_PID 0x1001
#define STATUS_PAGE_FAULT 0x1004
#define STATUS_INVALID_SIZE 0x1005

struct k_packet {
    uint32_t op_code;
    uint32_t target_pid;
    uint64_t target_addr;
    uint32_t size;
    uint32_t status;
    uint8_t inline_data[MAX_INLINE];
} __attribute__((aligned(8), packed));

typedef int (*access_process_vm_t)(void*, unsigned long, void*, int, int);
typedef void* (*find_task_by_vpid_t)(int);
typedef void* (*get_task_struct_t)(void*);
typedef void (*put_task_struct_t)(void*);
typedef void* (*kmalloc_t)(unsigned long, unsigned int);
typedef void (*kfree_t)(const void*);
typedef void* (*proc_create_t)(const char*, int, void*, const void*);

static access_process_vm_t p_access_process_vm;
static find_task_by_vpid_t p_find_task_by_vpid;
static get_task_struct_t p_get_task_struct;
static put_task_struct_t p_put_task_struct;
static kmalloc_t p_kmalloc;
static kfree_t p_kfree;
static proc_create_t p_proc_create;

static void *g_proc = NULL;
static struct k_packet g_pkt;
static int g_ready = 0;

static ssize_t hfr_write(void *f, const char __user *b, size_t n, void *o)
{
    struct k_packet pkt;
    if (n != sizeof(pkt)) return -22;
    { const unsigned char *s = (void*)b; unsigned char *d = (void*)&pkt; for(size_t i=0;i<n;i++) d[i]=s[i]; }
    g_ready = 0; pkt.status = STATUS_INVALID_PID;
    if (pkt.op_code == OP_READ_VM) {
        if (!pkt.size || pkt.size > MAX_INLINE) { pkt.status = STATUS_INVALID_SIZE; goto done; }
        void *kb = p_kmalloc(pkt.size, GFP_KERNEL);
        if (!kb) { pkt.status = STATUS_INVALID_SIZE; goto done; }
        void *t = p_find_task_by_vpid(pkt.target_pid);
        if (!t) { p_kfree(kb); goto done; }
        p_get_task_struct(t);
        int r = p_access_process_vm(t, pkt.target_addr, kb, pkt.size, 0);
        p_put_task_struct(t);
        if (r == pkt.size) {
            unsigned char *s = kb; for(size_t i=0;i<pkt.size;i++) pkt.inline_data[i]=s[i];
            pkt.status = STATUS_SUCCESS;
        } else pkt.status = STATUS_PAGE_FAULT;
        p_kfree(kb);
    } else if (pkt.op_code == OP_WRITE_VM) {
        if (!pkt.size || pkt.size > MAX_INLINE) { pkt.status = STATUS_INVALID_SIZE; goto done; }
        void *t = p_find_task_by_vpid(pkt.target_pid);
        if (!t) goto done;
        p_get_task_struct(t);
        int r = p_access_process_vm(t, pkt.target_addr, pkt.inline_data, pkt.size, 1);
        p_put_task_struct(t);
        pkt.status = (r == pkt.size) ? STATUS_SUCCESS : STATUS_PAGE_FAULT;
    }
done:
    { unsigned char *s = (void*)&pkt, *d = (void*)&g_pkt; for(size_t i=0;i<sizeof(pkt);i++) d[i]=s[i]; }
    g_ready = 1;
    return n;
}

static ssize_t hfr_read(void *f, char __user *b, size_t n, void *o)
{
    if (!g_ready) return 0;
    if (n < sizeof(g_pkt)) return -22;
    if (compat_copy_to_user(b, &g_pkt, sizeof(g_pkt))) return -14;
    g_ready = 0;
    return sizeof(g_pkt);
}

struct my_ops { void *r, *w; };
static struct my_ops hfr_ops = { (void*)hfr_read, (void*)hfr_write };

static long hfr_init(const char *a, const char *e, void *r)
{
    p_access_process_vm = (access_process_vm_t)kallsyms_lookup_name("access_process_vm");
    p_find_task_by_vpid = (find_task_by_vpid_t)kallsyms_lookup_name("find_task_by_vpid");
    p_get_task_struct = (get_task_struct_t)kallsyms_lookup_name("get_task_struct");
    p_put_task_struct = (put_task_struct_t)kallsyms_lookup_name("put_task_struct");
    p_kmalloc = (kmalloc_t)kallsyms_lookup_name("__kmalloc");
    p_kfree = (kfree_t)kallsyms_lookup_name("kfree");
    p_proc_create = (proc_create_t)kallsyms_lookup_name("proc_create");
    if (!p_access_process_vm || !p_find_task_by_vpid || !p_kmalloc || !p_proc_create) { kpm_err("sym fail\n"); return -14; }
    g_proc = p_proc_create("hfr_mem", 0666, NULL, &hfr_ops);
    if (!g_proc) { kpm_err("proc_create fail\n"); return -14; }
    kpm_info("Loaded! /proc/hfr_mem\n");
    return 0;
}

static long hfr_exit(void *r) { kpm_info("Unloaded!\n"); return 0; }

KPM_INIT(hfr_init);
KPM_EXIT(hfr_exit);
