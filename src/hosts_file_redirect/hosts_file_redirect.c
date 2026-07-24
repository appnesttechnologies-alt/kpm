/* SPDX-License-Identifier: GPL-2.0-or-later */
/* File socket version - creates actual socket file */

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
KPM_DESCRIPTION("Kernel memory r/w via Unix socket (file socket)");

#define KPM_PREFIX "HFR_MEM"
#define kpm_info(fmt, ...) pr_info(KPM_PREFIX ": " fmt, ##__VA_ARGS__)
#define kpm_err(fmt, ...)  pr_err(KPM_PREFIX ": " fmt, ##__VA_ARGS__)

#define GFP_KERNEL 0xcc0
#define MAX_INLINE 256
#define OP_READ_VM  0x2000
#define OP_WRITE_VM 0x3000
#define STATUS_SUCCESS       0x0000
#define STATUS_INVALID_PID   0x1001
#define STATUS_PAGE_FAULT    0x1004
#define STATUS_INVALID_SIZE  0x1005
#define STATUS_MEM_ALLOC_FAIL 0x1008
#define HFR_SOCKET_PATH "/data/local/tmp/hfr_socket"
#define AF_UNIX 1
#define SOCK_STREAM 1
#define MSG_DONTWAIT 0x40

struct sockaddr_un {
    unsigned short sun_family;
    char sun_path[108];
};

struct iovec {
    void *iov_base;
    unsigned long iov_len;
};

struct msghdr {
    void *msg_name;
    int msg_namelen;
    struct iovec *msg_iov;
    unsigned long msg_iovlen;
    void *msg_control;
    unsigned long msg_controllen;
    unsigned int msg_flags;
};

struct k_packet {
    uint32_t op_code;
    uint32_t target_pid;
    uint64_t target_addr;
    uint32_t size;
    uint32_t status;
    uint8_t inline_data[MAX_INLINE];
} __attribute__((aligned(8), packed));

typedef int  (*access_process_vm_t)(void *, unsigned long, void *, int, int);
typedef void *(*find_task_by_vpid_t)(int);
typedef void *(*get_task_struct_t)(void *);
typedef void (*put_task_struct_t)(void *);
typedef void *(*kmalloc_t)(unsigned long, unsigned int);
typedef void (*kfree_t)(const void *);
typedef int (*sock_create_t)(int, int, int, void **);
typedef int (*sock_release_t)(void *);
typedef int (*kernel_bind_t)(void *, struct sockaddr_un *, int);
typedef int (*kernel_listen_t)(void *, int);
typedef int (*kernel_accept_t)(void *, void **, int);
typedef int (*sock_sendmsg_t)(void *, struct msghdr *);
typedef int (*sock_recvmsg_t)(void *, struct msghdr *, int);

static access_process_vm_t p_vm;
static find_task_by_vpid_t  p_find;
static get_task_struct_t    p_get;
static put_task_struct_t    p_put;
static kmalloc_t            p_malloc;
static kfree_t              p_free;
static sock_create_t   p_sock_create;
static sock_release_t  p_sock_release;
static kernel_bind_t   p_kernel_bind;
static kernel_listen_t p_kernel_listen;
static kernel_accept_t p_kernel_accept;
static sock_sendmsg_t  p_sock_sendmsg;
static sock_recvmsg_t  p_sock_recvmsg;

static void *listen_sock = NULL;
static int server_running = 0;

static void cp(void *d, const void *s, unsigned long n) {
    unsigned char *dd = d; const unsigned char *ss = s;
    for (unsigned long i = 0; i < n; i++) dd[i] = ss[i];
}

static void cz(void *d, unsigned long n) {
    unsigned char *dd = d;
    for (unsigned long i = 0; i < n; i++) dd[i] = 0;
}

static void process_packet(struct k_packet *pkt)
{
    pkt->status = STATUS_INVALID_PID;
    if (pkt->op_code == OP_READ_VM) {
        if (!pkt->size || pkt->size > MAX_INLINE) { pkt->status = STATUS_INVALID_SIZE; return; }
        void *kbuf = p_malloc(pkt->size, GFP_KERNEL);
        if (!kbuf) { pkt->status = STATUS_MEM_ALLOC_FAIL; return; }
        void *task = p_find(pkt->target_pid);
        if (!task) { p_free(kbuf); return; }
        p_get(task);
        int r = p_vm(task, pkt->target_addr, kbuf, pkt->size, 0);
        p_put(task);
        if (r == pkt->size) { cp(pkt->inline_data, kbuf, pkt->size); pkt->status = STATUS_SUCCESS; }
        else pkt->status = STATUS_PAGE_FAULT;
        p_free(kbuf);
    }
    else if (pkt->op_code == OP_WRITE_VM) {
        if (!pkt->size || pkt->size > MAX_INLINE) { pkt->status = STATUS_INVALID_SIZE; return; }
        void *task = p_find(pkt->target_pid);
        if (!task) return;
        p_get(task);
        int r = p_vm(task, pkt->target_addr, pkt->inline_data, pkt->size, 1);
        p_put(task);
        pkt->status = (r == pkt->size) ? STATUS_SUCCESS : STATUS_PAGE_FAULT;
    }
}

static int start_socket_server(void)
{
    struct sockaddr_un addr;
    int ret;
    ret = p_sock_create(AF_UNIX, SOCK_STREAM, 0, &listen_sock);
    if (ret < 0 || !listen_sock) { kpm_err("sock_create failed\n"); return ret; }
    
    cz(&addr, sizeof(addr));
    addr.sun_family = AF_UNIX;
    {
        const char *path = HFR_SOCKET_PATH;
        int i;
        for (i = 0; path[i] && i < 107; i++) addr.sun_path[i] = path[i];
        addr.sun_path[i] = '\0';
    }
    
    ret = p_kernel_bind(listen_sock, &addr, sizeof(addr));
    if (ret < 0) { kpm_err("bind failed\n"); p_sock_release(listen_sock); listen_sock = NULL; return ret; }
    
    ret = p_kernel_listen(listen_sock, 5);
    if (ret < 0) { kpm_err("listen failed\n"); p_sock_release(listen_sock); listen_sock = NULL; return ret; }
    
    kpm_info("Socket ready: %s\n", HFR_SOCKET_PATH);
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
    p_sock_create = (sock_create_t)kallsyms_lookup_name("sock_create");
    p_sock_release = (sock_release_t)kallsyms_lookup_name("sock_release");
    p_kernel_bind = (kernel_bind_t)kallsyms_lookup_name("kernel_bind");
    p_kernel_listen = (kernel_listen_t)kallsyms_lookup_name("kernel_listen");
    p_kernel_accept = (kernel_accept_t)kallsyms_lookup_name("kernel_accept");
    p_sock_sendmsg = (sock_sendmsg_t)kallsyms_lookup_name("sock_sendmsg");
    p_sock_recvmsg = (sock_recvmsg_t)kallsyms_lookup_name("sock_recvmsg");
    
    if (!p_vm || !p_find || !p_malloc || !p_sock_create || !p_kernel_bind || !p_kernel_listen || !p_kernel_accept || !p_sock_recvmsg || !p_sock_sendmsg) {
        kpm_err("Symbol resolution failed\n");
        return -EFAULT;
    }
    
    if (start_socket_server() < 0) { kpm_err("Socket server failed\n"); return -EFAULT; }
    server_running = 1;
    kpm_info("Module loaded - socket: %s\n", HFR_SOCKET_PATH);
    return 0;
}

static long hfr_memory_exit(void __user *reserved)
{
    server_running = 0;
    if (listen_sock) { p_sock_release(listen_sock); listen_sock = NULL; }
    kpm_info("Unloaded!\n");
    return 0;
}

KPM_INIT(hfr_memory_init);
KPM_EXIT(hfr_memory_exit);
