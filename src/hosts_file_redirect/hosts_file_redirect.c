/* SPDX-License-Identifier: GPL-2.0-or-later */
/*
 * Copyright (C) 2026 Surajit. All Rights Reserved.
 * HFR Memory Debugger with Starlink Netlink Socket
 * Direct kernel-userspace communication via AF_NETLINK
 */

#include <compiler.h>
#include <hook.h>
#include <kpmodule.h>
#include <kputils.h>
#include <linux/sched.h>
#include <linux/errno.h>
#include <linux/printk.h>
#include <linux/string.h>
#include <net/sock.h>
#include <net/netlink.h>
#include <linux/netlink.h>

KPM_NAME("hosts_file_redirect");
KPM_VERSION(HFR_VERSION);
KPM_LICENSE("GPL v2");
KPM_AUTHOR("Surajit");
KPM_DESCRIPTION("Kernel memory r/w with Starlink Netlink socket");

#define KPM_PREFIX "HFR_MEM"
#define kpm_info(fmt, ...) pr_info(KPM_PREFIX ": " fmt, ##__VA_ARGS__)
#define kpm_err(fmt, ...)  pr_err(KPM_PREFIX ": " fmt, ##__VA_ARGS__)

#define GFP_KERNEL  0xcc0
#define PAGE_SIZE   4096
#define MAX_TRANSFER_SIZE 0x100000
#define MAX_INLINE_DATA   256

#define NETLINK_HFR 31  /* Custom netlink family */
#define HFR_GRP_MAX 1

#define OP_RESOLVE_BASE 0x1000
#define OP_READ_VM      0x2000
#define OP_WRITE_VM     0x3000
#define OP_QUERY_PHYS   0x4000

#define STATUS_SUCCESS       0x0000
#define STATUS_INVALID_PID   0x1001
#define STATUS_INVALID_ADDR  0x1002
#define STATUS_ACCESS_DENIED 0x1003
#define STATUS_PAGE_FAULT    0x1004
#define STATUS_INVALID_SIZE  0x1005
#define STATUS_MEM_ALLOC_FAIL 0x1008
#define STATUS_MODULE_BUSY   0x1010

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

/* Core function pointers */
typedef int  (*access_process_vm_t)(struct task_struct *, unsigned long, void *, int, int);
typedef struct task_struct *(*get_task_struct_t)(struct task_struct *);
typedef void (*put_task_struct_t)(struct task_struct *);
typedef struct task_struct *(*find_task_by_vpid_t)(pid_t);
typedef void *(*kmalloc_t)(unsigned long, unsigned int);
typedef void (*kfree_t)(const void *);

/* Netlink function pointers */
typedef struct sock *(*netlink_kernel_create_t)(struct net *, int, struct netlink_kernel_cfg *);
typedef void (*netlink_kernel_release_t)(struct sock *);
typedef int  (*netlink_unicast_t)(struct sock *, struct sk_buff *, u32, int);
typedef void (*nlmsg_free_t)(struct sk_buff *);
typedef struct nlmsghdr *(*__nlmsg_put_t)(struct sk_buff *, u32, u32, int, int, int);
typedef struct sk_buff *(*__alloc_skb_t)(unsigned int, gfp_t, int, int);
typedef void (*__kfree_skb_t)(struct sk_buff *);
typedef struct net *(*sock_net_t)(const struct sock *);
typedef int  (*init_net_t)(void);

static access_process_vm_t    p_access_process_vm;
static get_task_struct_t      p_get_task_struct;
static put_task_struct_t      p_put_task_struct;
static find_task_by_vpid_t    p_find_task_by_vpid;
static kmalloc_t              p_kmalloc;
static kfree_t                p_kfree;

static netlink_kernel_create_t  p_netlink_kernel_create;
static netlink_kernel_release_t p_netlink_kernel_release;
static netlink_unicast_t        p_netlink_unicast;
static nlmsg_free_t             p_nlmsg_free;
static __nlmsg_put_t            p___nlmsg_put;
static __alloc_skb_t            p___alloc_skb;
static __kfree_skb_t            p___kfree_skb;

/* Netlink socket and init_net */
static struct sock *nl_sk = NULL;
static struct net  *p_init_net = NULL;

/* Manual copy - avoids memcpy issues */
static inline void copy_data(void *dst, const void *src, unsigned long n)
{
    unsigned char *d = (unsigned char *)dst;
    const unsigned char *s = (const unsigned char *)src;
    unsigned long i;
    for (i = 0; i < n; i++) d[i] = s[i];
}

/* Core memory operations */
static int write_process_memory(pid_t pid, unsigned long addr, const void *buf, size_t size)
{
    struct task_struct *task;
    int ret;
    if (!buf || size == 0 || size > MAX_TRANSFER_SIZE) return -EINVAL;
    task = p_find_task_by_vpid(pid);
    if (!task) return -ESRCH;
    p_get_task_struct(task);
    ret = p_access_process_vm(task, addr, (void *)buf, size, 1);
    p_put_task_struct(task);
    if (ret == 0) return -EFAULT;
    if (ret < 0) return ret;
    if (ret != size) return -EFAULT;
    return 0;
}

static int read_process_memory(pid_t pid, unsigned long addr, void *buf, size_t size)
{
    struct task_struct *task;
    int ret;
    if (!buf || size == 0 || size > MAX_TRANSFER_SIZE) return -EINVAL;
    task = p_find_task_by_vpid(pid);
    if (!task) return -ESRCH;
    p_get_task_struct(task);
    ret = p_access_process_vm(task, addr, buf, size, 0);
    p_put_task_struct(task);
    if (ret == 0) return -EFAULT;
    if (ret < 0) return ret;
    if (ret != size) return -EFAULT;
    return 0;
}

/* Process packet and return result */
static void process_packet(struct k_packet *pkt)
{
    void *kbuf;
    struct task_struct *task;
    int ret;

    pkt->status = STATUS_MODULE_BUSY;

    switch (pkt->op_code) {
    case OP_READ_VM:
        if (pkt->size == 0 || pkt->size > MAX_INLINE_DATA) {
            pkt->status = STATUS_INVALID_SIZE;
            return;
        }
        kbuf = p_kmalloc(pkt->size, GFP_KERNEL);
        if (!kbuf) {
            pkt->status = STATUS_MEM_ALLOC_FAIL;
            return;
        }
        ret = read_process_memory(pkt->target_pid, pkt->target_addr, kbuf, pkt->size);
        if (ret < 0) {
            pkt->status = (ret == -ESRCH) ? STATUS_INVALID_PID : STATUS_PAGE_FAULT;
        } else {
            copy_data(pkt->inline_data, kbuf, pkt->size);
            pkt->status = STATUS_SUCCESS;
            pkt->page_count = (pkt->size + PAGE_SIZE - 1) / PAGE_SIZE;
        }
        p_kfree(kbuf);
        break;

    case OP_WRITE_VM:
        if (pkt->size == 0 || pkt->size > MAX_INLINE_DATA) {
            pkt->status = STATUS_INVALID_SIZE;
            return;
        }
        ret = write_process_memory(pkt->target_pid, pkt->target_addr, pkt->inline_data, pkt->size);
        if (ret < 0) {
            pkt->status = (ret == -ESRCH) ? STATUS_INVALID_PID : STATUS_PAGE_FAULT;
        } else {
            pkt->status = STATUS_SUCCESS;
            pkt->page_count = (pkt->size + PAGE_SIZE - 1) / PAGE_SIZE;
        }
        break;

    case OP_RESOLVE_BASE:
        task = p_find_task_by_vpid(pkt->target_pid);
        if (task) {
            struct mm_struct *mm;
            p_get_task_struct(task);
            mm = task->mm;
            if (mm) pkt->resolved_base = mm->start_code;
            else pkt->status = STATUS_INVALID_ADDR;
            p_put_task_struct(task);
        } else {
            pkt->status = STATUS_INVALID_PID;
        }
        break;

    case OP_QUERY_PHYS:
        pkt->status = STATUS_INVALID_ADDR;
        pkt->physical_addr = 0;
        break;
    }
}

/* Netlink message handler - called when panel sends data */
static void hfr_nl_recv(struct sk_buff *skb)
{
    struct nlmsghdr *nlh;
    struct k_packet *pkt;
    struct sk_buff *reply_skb;
    struct nlmsghdr *reply_nlh;

    if (!skb) return;

    nlh = (struct nlmsghdr *)skb->data;
    if (!nlh || nlh->nlmsg_len < sizeof(struct nlmsghdr) + sizeof(struct k_packet)) {
        if (skb) skb_free(skb);
        return;
    }

    pkt = (struct k_packet *)NLMSG_DATA(nlh);
    if (!pkt) {
        skb_free(skb);
        return;
    }

    /* Process the request */
    process_packet(pkt);

    /* Build reply skb */
    reply_skb = p___alloc_skb(NLMSG_SPACE(sizeof(struct k_packet)), GFP_KERNEL, 0, 0);
    if (!reply_skb) {
        skb_free(skb);
        return;
    }

    reply_nlh = p___nlmsg_put(reply_skb, nlh->nlmsg_pid, nlh->nlmsg_seq, 
                               NLMSG_DONE, sizeof(struct k_packet), 0);
    if (!reply_nlh) {
        p___kfree_skb(reply_skb);
        skb_free(skb);
        return;
    }

    copy_data(NLMSG_DATA(reply_nlh), pkt, sizeof(struct k_packet));
    nlmsg_end(reply_skb, reply_nlh);

    /* Send reply back to panel */
    if (nlh->nlmsg_pid) {
        p_netlink_unicast(nl_sk, reply_skb, nlh->nlmsg_pid, MSG_DONTWAIT);
    } else {
        p___kfree_skb(reply_skb);
    }

    skb_free(skb);
}

/* Fallback: Process via KPM_CTL0 (APatch app control) */
static long hfr_control0(const char *ctl_args, char __user *out_msg, int outlen)
{
    struct k_packet pkt;
    if (!ctl_args || outlen < sizeof(struct k_packet)) return -EINVAL;
    copy_data(&pkt, ctl_args, sizeof(struct k_packet));
    process_packet(&pkt);
    if (compat_copy_to_user(out_msg, &pkt, sizeof(struct k_packet))) return -EFAULT;
    return 0;
}

/* Initialize Netlink socket */
static int init_netlink(void)
{
    struct netlink_kernel_cfg cfg;

    copy_data(&cfg, &(struct netlink_kernel_cfg){0}, sizeof(cfg));
    cfg.input = hfr_nl_recv;
    cfg.groups = HFR_GRP_MAX;

    nl_sk = p_netlink_kernel_create(p_init_net, NETLINK_HFR, &cfg);
    if (!nl_sk) {
        kpm_err("Failed to create netlink socket\n");
        return -EFAULT;
    }

    kpm_info("Netlink socket created on family %d\n", NETLINK_HFR);
    return 0;
}

static long hfr_memory_init(const char *args, const char *event, void __user *reserved)
{
    /* Resolve core functions */
    p_access_process_vm  = (access_process_vm_t)kallsyms_lookup_name("access_process_vm");
    p_get_task_struct    = (get_task_struct_t)  kallsyms_lookup_name("get_task_struct");
    p_put_task_struct    = (put_task_struct_t)  kallsyms_lookup_name("put_task_struct");
    p_find_task_by_vpid  = (find_task_by_vpid_t)kallsyms_lookup_name("find_task_by_vpid");
    p_kmalloc            = (kmalloc_t)          kallsyms_lookup_name("__kmalloc");
    p_kfree              = (kfree_t)            kallsyms_lookup_name("kfree");

    /* Resolve netlink functions */
    p_netlink_kernel_create  = (netlink_kernel_create_t)kallsyms_lookup_name("__netlink_kernel_create");
    p_netlink_kernel_release = (netlink_kernel_release_t)kallsyms_lookup_name("netlink_kernel_release");
    p_netlink_unicast        = (netlink_unicast_t)kallsyms_lookup_name("netlink_unicast");
    p_nlmsg_free             = (nlmsg_free_t)kallsyms_lookup_name("nlmsg_free");
    p___nlmsg_put             = (__nlmsg_put_t)kallsyms_lookup_name("__nlmsg_put");
    p___alloc_skb             = (__alloc_skb_t)kallsyms_lookup_name("__alloc_skb");
    p___kfree_skb             = (__kfree_skb_t)kallsyms_lookup_name("kfree_skb");

    /* Get init_net */
    p_init_net = (struct net *)kallsyms_lookup_name("init_net");

    if (!p_access_process_vm || !p_find_task_by_vpid || !p_kmalloc || !p_kfree ||
        !p_netlink_kernel_create || !p_netlink_unicast || !p___nlmsg_put || 
        !p___alloc_skb || !p___kfree_skb || !p_init_net) {
        kpm_err("Symbol resolution failed\n");
        return -EFAULT;
    }

    /* Initialize Netlink for direct panel communication */
    if (init_netlink() < 0) {
        kpm_err("Netlink init failed, using KPM_CTL0 fallback only\n");
    }

    kpm_info("Starlink Netlink socket ready! Panel: socket(AF_NETLINK, SOCK_RAW, %d)\n", NETLINK_HFR);
    return 0;
}

static long hfr_memory_exit(void __user *reserved)
{
    if (nl_sk) {
        p_netlink_kernel_release(nl_sk);
        nl_sk = NULL;
    }
    kpm_info("Unloaded!\n");
    return 0;
}

KPM_INIT(hfr_memory_init);
KPM_CTL0(hfr_control0);
KPM_EXIT(hfr_memory_exit);
