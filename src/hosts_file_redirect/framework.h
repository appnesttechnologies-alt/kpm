#ifndef _KPM_MEMORY_FRAMEWORK_H
#define _KPM_MEMORY_FRAMEWORK_H

#include <linux/types.h>
#include <linux/mm.h>
#include <linux/sched.h>
#include <linux/pid.h>
#include <linux/uaccess.h>
#include <linux/slab.h>
#include <linux/highmem.h>
#include <linux/pagemap.h>
#include <linux/version.h>
#include <asm/pgtable.h>
#include "kpm_utils.h"

/* Operation Codes for Universal Data Packet */
#define OP_RESOLVE_BASE    0x1000  /* Resolve process base address */
#define OP_READ_VM         0x2000  /* Read virtual memory */
#define OP_WRITE_VM        0x3000  /* Write virtual memory */
#define OP_QUERY_PHYS      0x4000  /* Query physical address mapping */

/* Status Codes */
#define STATUS_SUCCESS          0x0000
#define STATUS_INVALID_PID      0x1001
#define STATUS_INVALID_ADDR     0x1002
#define STATUS_ACCESS_DENIED    0x1003
#define STATUS_PAGE_FAULT       0x1004
#define STATUS_INVALID_SIZE     0x1005
#define STATUS_MMAP_LOCK_FAIL   0x1006
#define STATUS_PAGE_WALK_FAIL   0x1007
#define STATUS_MEM_ALLOC_FAIL   0x1008
#define STATUS_COPY_FAIL        0x1009

/* Architecture-specific Constants for ARM64 */
#define PAGE_LEVELS         4
#define PAGE_SHIFT_4K       12
#define PGD_SHIFT           39
#define PUD_SHIFT           30
#define PMD_SHIFT           21
#define PTRS_PER_PGD        512
#define PTRS_PER_PUD        512
#define PTRS_PER_PMD        512
#define PTRS_PER_PTE        512
#define PAGE_MASK_4K        (~((1UL << PAGE_SHIFT_4K) - 1))
#define MAX_TRANSFER_SIZE   0x100000  /* 1MB max transfer */

/**
 * Universal Data Packet - Shared layout between userspace and kernel
 * Must be 8-byte aligned for ARM64 compatibility
 */
struct k_packet {
    uint32_t op_code;            /* Operation code */
    uint32_t target_pid;         /* Target process PID */
    uint64_t user_buffer;        /* Userspace buffer pointer */
    uint64_t target_addr;        /* Target virtual address */
    uint64_t target_addr_end;    /* End address for range operations */
    uint32_t size;               /* Transfer size */
    uint32_t status;             /* Operation status */
    uint64_t physical_addr;      /* Resolved physical address */
    uint64_t resolved_base;      /* Resolved module base address */
    uint32_t page_count;         /* Number of pages processed */
    uint32_t reserved;           /* Padding for alignment */
} __attribute__((aligned(8)));

/* Internal memory operation context */
struct mem_op_context {
    struct mm_struct *target_mm;
    struct task_struct *target_task;
    struct page **pages;
    void **kva_array;
    unsigned long start_addr;
    unsigned long end_addr;
    int nr_pages;
    int write_mode;
};

/* Function declarations from memory_core.c */
int memory_initialize(void);
void memory_cleanup(void);
int handle_memory_read(struct k_packet *pkt);
int handle_memory_write(struct k_packet *pkt);
int resolve_process_base(struct k_packet *pkt);

/* Function declarations from process_helper.c */
int get_process_mm(pid_t pid, struct mm_struct **mm, struct task_struct **task);
void put_process_mm(struct mm_struct *mm);
unsigned long virtual_to_physical(struct mm_struct *mm, unsigned long vaddr);
int validate_user_address(struct mm_struct *mm, unsigned long vaddr, unsigned long size);
int pin_user_pages_for_transfer(struct mm_struct *mm, unsigned long vaddr,
                                 unsigned long size, int write, struct mem_op_context *ctx);
void unpin_user_pages(struct mem_op_context *ctx);
int copy_data_to_user_pages(struct mem_op_context *ctx, void *src, size_t size);
int copy_data_from_user_pages(struct mem_op_context *ctx, void *dst, size_t size);

/* Module lifecycle functions from main.c */
int kpm_memory_init(void);
void kpm_memory_exit(void);

#endif /* _KPM_MEMORY_FRAMEWORK_H */