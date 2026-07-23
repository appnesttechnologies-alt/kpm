/* SPDX-License-Identifier: GPL-2.0-or-later */
/* FINAL: /proc/hfr_mem - NO memcpy, NO external symbols */

#include <compiler.h>
#include <hook.h>
#include <kpmodule.h>
#include <kputils.h>
#include <linux/sched.h>
#include <linux/errno.h>
#include <linux/printk.h>

KPM_NAME("hosts_file_redirect");
KPM_VERSION(HFR_VERSION);
KPM_LICENSE("GPL v2");
KPM_AUTHOR("Surajit");
KPM_DESCRIPTION("Kernel memory r/w - /proc/hfr_mem");

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
#define STATUS_MEM_ALLOC_FAIL 0x1008

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
typedef void *(*proc_create_fn_t)(const char *, int, void *, const void *);

static access_process_vm_t p_vm;
static find_task_by_vpid_t p_find;
static get_task_struct_t p_get;
static put_task_struct_t p_put;
static kmalloc_t p_malloc;
static kfree_t p_free;
static proc_create_fn_t p_proc_create;

static void *g_proc = NULL;
static struct k_packet g_pkt;
static int g_ready = 0;

/* Manual copy - no memcpy */
static void cp(void *d, const void *s, unsigned long n) {
    unsigned char *dd = d; const unsigned char *ss = s;
    for (unsigned long i = 0; i < n; i++) dd[i] = ss[i];
}

/* /proc write handler */
static ssize_t hfr_proc_write(void *f, const char __user *b, size_t n, void *o) {
    struct k_packet pkt;
    if (n != sizeof(pkt)) return -EINVAL;
    
    /* Copy from user buffer byte-by-byte */
    { const unsigned char *s = (void*)b; unsigned char *d = (void*)&pkt; for(size_t i=0;i<n;i++) d[i]=s[i]; }
    
    g_ready = 0;
    pkt.status = STATUS_INVALID_PID;
    
    if (pkt.op_code == OP_READ_VM) {
        if (!pkt.size || pkt.size > MAX_INLINE) { pkt.status = STATUS_INVALID_SIZE; goto done; }
        void *kbuf = p_malloc(pkt.size, GFP_KERNEL);
        if (!kbuf) { pkt.status = STATUS_MEM_ALLOC_FAIL; goto done; }
        void *task = p_find(pkt.target_pid);
        if (!task) { p_free(kbuf); goto done; }
        p_get(task);
        int r = p_vm(task, pkt.target_addr, kbuf, pkt.size, 0);
        p_put(task);
        if (r == pkt.size) { cp(pkt.inline_data, kbuf, pkt.size); pkt.status = STATUS_SUCCESS; }
        else pkt.status = STATUS_PAGE_FAULT;
        p_free(kbuf);
    }
    else if (pkt.op_code == OP_WRITE_VM) {
        if (!pkt.size || pkt.size > MAX_INLINE) { pkt.status = STATUS_INVALID_SIZE; goto done; }
        void *task = p_find(pkt.target_pid);
        if (!task) goto done;
        p_get(task);
        int r = p_vm(task, pkt.target_addr, pkt.inline_data, pkt.size, 1);
        p_put(task);
        pkt.status = (r == pkt.size) ? STATUS_SUCCESS : STATUS_PAGE_FAULT;
    }
    
done:
    cp(&g_pkt, &pkt, sizeof(pkt));
    g_ready = 1;
    return n;
}

/* /proc read handler */
static ssize_t hfr_proc_read(void *f, char __user *b, size_t n, void *o) {
    if (!g_ready) return 0;
    if (n < sizeof(g_pkt)) return -EINVAL;
    if (compat_copy_to_user(b, &g_pkt, sizeof(g_pkt))) return -EFAULT;
    g_ready = 0;
    return sizeof(g_pkt);
}

/* Minimal proc_ops */
struct my_proc_ops { void *read; void *write; };
static struct my_proc_ops ops = { (void*)hfr_proc_read, (void*)hfr_proc_write };

static long hfr_init(const char *a, const char *e, void *r) {
    p_vm = (access_process_vm_t)kallsyms_lookup_name("access_process_vm");
    p_find = (find_task_by_vpid_t)kallsyms_lookup_name("find_task_by_vpid");
    p_get = (get_task_struct_t)kallsyms_lookup_name("get_task_struct");
    p_put = (put_task_struct_t)kallsyms_lookup_name("put_task_struct");
    p_malloc = (kmalloc_t)kallsyms_lookup_name("__kmalloc");
    p_free = (kfree_t)kallsyms_lookup_name("kfree");
    p_proc_create = (proc_create_fn_t)kallsyms_lookup_name("proc_create");
    
    if (!p_vm || !p_find || !p_malloc || !p_proc_create) { kpm_err("sym fail\n"); return -14; }
    
    g_proc = p_proc_create("hfr_mem", 0666, NULL, &ops);
    if (!g_proc) { kpm_err("proc_create fail\n"); return -14; }
    
    kpm_info("READY /proc/hfr_mem\n");
    return 0;
}

static long hfr_exit(void *r) { kpm_info("Unloaded\n"); return 0; }

KPM_INIT(hfr_init);
KPM_EXIT(hfr_exit);
