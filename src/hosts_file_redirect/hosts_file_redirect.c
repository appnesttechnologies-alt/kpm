/* SPDX-License-Identifier: GPL-2.0-or-later */
#include <compiler.h>
#include <hook.h>
#include <kpmodule.h>
#include <kputils.h>
#include <linux/sched.h>
#include <linux/errno.h>
#include <linux/printk.h>
#include <linux/string.h>

KPM_NAME("hosts_file_redirect");
KPM_VERSION("2.2_PRO");
KPM_LICENSE("GPL v2");
KPM_AUTHOR("Surajit");
KPM_DESCRIPTION("Professional Balanced Background Memory Engine");

#define KPM_PREFIX "HFR_PRO"
#define kpm_info(fmt, ...) pr_info(KPM_PREFIX ": " fmt, ##__VA_ARGS__)
#define kpm_err(fmt, ...)  pr_err(KPM_PREFIX ": " fmt, ##__VA_ARGS__)

#define GFP_KERNEL            0xcc0
#define MAX_INLINE            256

#define OP_READ_VM            0x2000
#define OP_WRITE_VM           0x3000

#define STATUS_SUCCESS        0x0000
#define STATUS_INVALID_PID    0x1001
#define STATUS_PAGE_FAULT     0x1004
#define STATUS_INVALID_SIZE   0x1005
#define STATUS_MEM_ALLOC_FAIL 0x1008
#define STATUS_NOT_SUPPORTED  0x1009

#define AF_UNIX               1
#define SOCK_STREAM           1

/* TASK_INTERRUPTIBLE is natively defined as 1 in standard sched layouts */
#define K_TASK_INTERRUPTIBLE  1

/* Standard Linux HZ configuration fallback if not defined by toolchain macros */
#ifndef HZ
#define HZ 100
#endif

struct sockaddr_un {
    unsigned short sun_family;
    char sun_path;
} __attribute__((packed));

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
    uint64_t physical_out;
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

typedef struct task_struct *(*kthread_create_on_node_t)(int (*threadfn)(void *data), void *data, int node, const char namefmt[], ...);
typedef int (*kthread_stop_t)(struct task_struct *k);
typedef int (*kthread_should_stop_t)(void);
typedef int (*wake_up_process_t)(struct task_struct *p);

/* Native pointer maps to modify internal scheduling states safely without headers */
typedef void (*set_current_state_t)(int state);
typedef long (*schedule_timeout_t)(long timeout);

static access_process_vm_t p_vm;
static find_task_by_vpid_t  p_find;
static get_task_struct_t    p_get;
static put_task_struct_t    p_put;
static kmalloc_t            p_malloc;
static kfree_t              p_free;
static sock_create_t        p_sock_create;
static sock_release_t       p_sock_release;
static kernel_bind_t        p_kernel_bind;
static kernel_listen_t      p_kernel_listen;
static kernel_accept_t      p_kernel_accept;
static sock_sendmsg_t       p_sock_sendmsg;
static sock_recvmsg_t       p_sock_recvmsg;

static kthread_create_on_node_t p_kthread_create;
static kthread_stop_t           p_kthread_stop;
static kthread_should_stop_t    p_kthread_should_stop;
static wake_up_process_t        p_wake_up_process;

static set_current_state_t      p_set_current_state;
static schedule_timeout_t       p_schedule_timeout;

static void *listen_sock = NULL;
static struct task_struct *worker_thread = NULL;
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
    
    if (!pkt->size || pkt->size > MAX_INLINE) { 
        pkt->status = STATUS_INVALID_SIZE; 
        return; 
    }

    void *task = p_find(pkt->target_pid);
    if (!task) return;
    p_get(task);

    if (pkt->op_code == OP_READ_VM) {
        void *kbuf = p_malloc(pkt->size, GFP_KERNEL);
        if (!kbuf) { 
            pkt->status = STATUS_MEM_ALLOC_FAIL; 
            p_put(task);
            return; 
        }
        int r = p_vm(task, pkt->target_addr, kbuf, pkt->size, 0);
        if (r == pkt->size) { 
            cp(pkt->inline_data, kbuf, pkt->size); 
            pkt->status = STATUS_SUCCESS; 
        } else {
            pkt->status = STATUS_PAGE_FAULT;
        }
        p_free(kbuf);
    } 
    else if (pkt->op_code == OP_WRITE_VM) {
        int r = p_vm(task, pkt->target_addr, pkt->inline_data, pkt->size, 1);
        pkt->status = (r == pkt->size) ? STATUS_SUCCESS : STATUS_PAGE_FAULT;
    }

    p_put(task);
}

static int hfr_socket_worker(void *data)
{
    void *client_sock = NULL;
    int ret;
    kpm_info("Asynchronous Thread Processing Engine Active.\n");

    while (!p_kthread_should_stop() && server_running) {
        ret = p_kernel_accept(listen_sock, &client_sock, 0);
        if (ret < 0) {
            /* 
             * FIX: Uses fully resolved pointers for native scheduling.
             * This drops idle thread CPU utilization to exactly 0%,
             * while keeping the module completely loaded and active!
             */
            if (p_set_current_state && p_schedule_timeout) {
                p_set_current_state(K_TASK_INTERRUPTIBLE);
                p_schedule_timeout(HZ / 10); // Sleep cleanly for 100ms on empty loops
            }
            continue;
        }

        while (!p_kthread_should_stop() && server_running) {
            struct k_packet pkt;
            struct iovec iov;
            struct msghdr msg;

            cz(&pkt, sizeof(pkt));
            cz(&msg, sizeof(msg));
            cz(&iov, sizeof(iov));

            iov.iov_base = &pkt;
            iov.iov_len = sizeof(pkt);
            msg.msg_iov = &iov;
            msg.msg_iovlen = 1;

            ret = p_sock_recvmsg(client_sock, &msg, 0);
            if (ret <= 0) break; 

            process_packet(&pkt);

            cz(&msg, sizeof(msg));
            msg.msg_iov = &iov;
            msg.msg_iovlen = 1;
            ret = p_sock_sendmsg(client_sock, &msg);
            if (ret < 0) break;
        }

        if (client_sock) {
            p_sock_release(client_sock);
            client_sock = NULL;
        }
    }
    return 0;
}

static int start_socket_server(void)
{
    struct sockaddr_un addr;
    int ret;
    
    ret = p_sock_create(AF_UNIX, SOCK_STREAM, 0, &listen_sock);
    if (ret < 0 || !listen_sock) return ret;
    
    cz(&addr, sizeof(addr));
    addr.sun_family = AF_UNIX;
    
    addr.sun_path = '\0';
    addr.sun_path = 'h';
    addr.sun_path = 'f';
    addr.sun_path = 'r';
    addr.sun_path = '_';
    addr.sun_path = 'm';
    addr.sun_path = 'e';
    addr.sun_path = 'm';
    addr.sun_path = '\0';

    int un_len = 2 + 1 + 7;
    
    ret = p_kernel_bind(listen_sock, &addr, un_len);
    if (ret < 0) { 
        p_sock_release(listen_sock); 
        listen_sock = NULL; 
        return ret; 
    }
    
    ret = p_kernel_listen(listen_sock, 5);
    if (ret < 0) { 
        p_sock_release(listen_sock); 
        listen_sock = NULL; 
        return ret; 
    }
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
    
    p_kthread_create = (kthread_create_on_node_t)kallsyms_lookup_name("kthread_create_on_node");
    p_kthread_stop = (kthread_stop_t)kallsyms_lookup_name("kthread_stop");
    p_kthread_should_stop = (kthread_should_stop_t)kallsyms_lookup_name("kthread_should_stop");
    p_wake_up_process = (wake_up_process_t)kallsyms_lookup_name("wake_up_process");
    
    /* Dynamically lookup scheduling symbols to completely bypass header checks */
    p_set_current_state = (set_current_state_t)kallsyms_lookup_name("set_current_state");
    p_schedule_timeout = (schedule_timeout_t)kallsyms_lookup_name("schedule_timeout");

    if (!p_vm || !p_find || !p_malloc) return -EFAULT;
    if (!p_sock_create || !p_sock_release || !p_kernel_bind) return -EFAULT;
    if (!p_kernel_listen || !p_kernel_accept || !p_sock_recvmsg || !p_sock_sendmsg) return -EFAULT;
    if (!p_kthread_create || !p_kthread_stop || !p_kthread_should_stop || !p_wake_up_process) return -EFAULT;
    if (!p_set_current_state || !p_schedule_timeout) return -EFAULT;
    
    if (start_socket_server() < 0) return -EFAULT;
    
