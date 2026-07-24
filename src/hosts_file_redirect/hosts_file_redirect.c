/* SPDX-License-Identifier: GPL-2.0-or-later */
#include <compiler.h>
#include <hook.h>
#include <kpmodule.h>
#include <kputils.h>
#include <linux/sched.h>
#include <linux/errno.h>
#include <linux/printk.h>
#include <linux/string.h>
#include <linux/kthread.h>
#include <linux/delay.h>

KPM_NAME("hosts_file_redirect");
KPM_VERSION("2.0_PRO");
KPM_LICENSE("GPL v2");
KPM_AUTHOR("Surajit");
KPM_DESCRIPTION("Professional High-Performance Cross-Process Physical Memory Engine");

#define KPM_PREFIX "HFR_PRO"
#define kpm_info(fmt, ...) pr_info(KPM_PREFIX ": " fmt, ##__VA_ARGS__)
#define kpm_err(fmt, ...)  pr_err(KPM_PREFIX ": " fmt, ##__VA_ARGS__)

#define GFP_KERNEL            0xcc0
#define MAX_INLINE            256

/* Professional Protocol Command Matrix */
#define OP_READ_VM            0x2000
#define OP_WRITE_VM           0x3000
#define OP_VIRT_TO_PHYS       0x4000
#define OP_FORCE_PHYS_WRITE   0x5000

/* Professional Protocol Status Matrix */
#define STATUS_SUCCESS        0x0000
#define STATUS_INVALID_PID    0x1001
#define STATUS_PAGE_FAULT     0x1004
#define STATUS_INVALID_SIZE   0x1005
#define STATUS_MEM_ALLOC_FAIL 0x1008
#define STATUS_NOT_SUPPORTED  0x1009

#define AF_UNIX               1
#define SOCK_STREAM           1

struct sockaddr_un {
    unsigned short sun_family;
    char sun_path[108];
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

/* Unified Communications Payload with Alignment Boundary Matching */
struct k_packet {
    uint32_t op_code;
    uint32_t target_pid;
    uint64_t target_addr;
    uint64_t physical_out;
    uint32_t size;
    uint32_t status;
    uint8_t inline_data[MAX_INLINE];
} __attribute__((aligned(8), packed));

/* Advanced Core System Dynamic Pointers - Corrected Signatures */
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

/* FIX: Stabilized message routing signatures to prevent kernel register stack corruption */
typedef int (*sock_sendmsg_t)(void *, struct msghdr *);
typedef int (*sock_recvmsg_t)(void *, struct msghdr *, int);

/* External low-level architectural headers hooks provided by your SDK */
extern uint64_t *pgtable_entry_kernel(uint64_t va);
extern phys_addr_t pid_virt_to_phys(pid_t pid, uintptr_t vaddr);

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

/* Professional Dual-Layer Packet Processing Subsystem */
static void process_packet(struct k_packet *pkt)
{
    pkt->status = STATUS_INVALID_PID;
    
    // Safety Bounds Check
    if (!pkt->size || pkt->size > MAX_INLINE) { 
        pkt->status = STATUS_INVALID_SIZE; 
        return; 
    }

    // Resolve target task structural pointer
    void *task = p_find(pkt->target_pid);
    if (!task) {
        pkt->status = STATUS_INVALID_PID;
        return;
    }
    p_get(task);

    switch (pkt->op_code) {
        case OP_READ_VM: {
            void *kbuf = p_malloc(pkt->size, GFP_KERNEL);
            if (!kbuf) { 
                pkt->status = STATUS_MEM_ALLOC_FAIL; 
                break; 
            }
            int r = p_vm(task, pkt->target_addr, kbuf, pkt->size, 0);
            if (r == pkt->size) { 
                cp(pkt->inline_data, kbuf, pkt->size); 
                pkt->status = STATUS_SUCCESS; 
            } else {
                pkt->status = STATUS_PAGE_FAULT;
            }
            p_free(kbuf);
            break;
        }

        case OP_WRITE_VM: {
            int r = p_vm(task, pkt->target_addr, pkt->inline_data, pkt->size, 1);
            pkt->status = (r == pkt->size) ? STATUS_SUCCESS : STATUS_PAGE_FAULT;
            break;
        }

        case OP_VIRT_TO_PHYS: {
            /* 
             * Leverages your SDK's verified pidmem translation architecture 
             * to break through Virtual Address Randomization limits.
             */
            phys_addr_t pa = pid_virt_to_phys(pkt->target_pid, pkt->target_addr);
            if (pa != 0) {
                pkt->physical_out = (uint64_t)pa;
                pkt->status = STATUS_SUCCESS;
            } else {
                pkt->status = STATUS_PAGE_FAULT;
            }
            break;
        }

        case OP_FORCE_PHYS_WRITE: {
            /* 
             * Professional Safety Fix: Keeps the operation safely isolated.
             * Modifying high physical frames inline requires architecture-specific 
             * macros (__va(pa)) which can change across Linux revisions. 
             * Standardizing on OP_WRITE_VM handles caching and page boundaries 
             * safely without triggering hard machine checks.
             */
            pkt->status = STATUS_NOT_SUPPORTED; 
            break;
        }

        default:
            pkt->status = STATUS_NOT_SUPPORTED;
            break;
    }

    p_put(task);
}

/* Asynchronous Background Client Listener Mechanism */
static int hfr_socket_worker(void *data)
{
    void *client_sock = NULL;
    int ret;
    kpm_info("Asynchronous I/O Server Subsystem Engaged.\n");

    while (!kthread_should_stop() && server_running) {
        ret = p_kernel_accept(listen_sock, &client_sock, 0);
        if (ret < 0) {
            msleep(20); // Safeguard against tight loop CPU throttling spikes
            continue;
        }

        // Loop communication mapping matrix until specific client context exits
        while (!kthread_should_stop() && server_running) {
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

            /* FIX: Matches standard Linux internal flags tracking rules safely */
            ret = p_sock_recvmsg(client_sock, &msg, 0);
            if (ret <= 0) break; // Client disconnected gracefully

            // Process payload structures securely through dual layers
            process_packet(&pkt);

            // Respond synchronously with modified status matrices
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
    
    // Explicit, byte-aligned stabilization layout matching client maps
    addr.sun_path[0] = '\0';
    addr.sun_path[1] = 'h';
    addr.sun_path[2] = 'f';
    addr.sun_path[3] = 'r';
    addr.sun_path[4] = '_';
    addr.sun_path[5] = 'm';
    addr.sun_path[6] = 'e';
    addr.sun_path[7] = 'm';
    addr.sun_path[8] = '\0';

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
    
