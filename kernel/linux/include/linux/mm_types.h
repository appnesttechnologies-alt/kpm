#ifndef _LINUX_MM_TYPES_H
#define _LINUX_MM_TYPES_H

#include <ktypes.h>

struct address_space;
struct mem_cgroup;

typedef size_t pgprot_t;


struct page
{
};


struct mm_struct;


struct vm_area_struct
{
    unsigned long vm_start;
    unsigned long vm_end;

    struct mm_struct *vm_mm;

    pgprot_t vm_page_prot;
    unsigned long vm_flags;
};


struct mm_struct
{
};


struct mm_struct_offset
{
    int16_t mmap_base_offset;
    int16_t task_size_offset;
    int16_t pgd_offset;
    int16_t map_count_offset;
    int16_t total_vm_offset;
    int16_t locked_vm_offset;
    int16_t pinned_vm_offset;
    int16_t data_vm_offset;
    int16_t exec_vm_offset;
    int16_t stack_vm_offset;
    int16_t start_code_offset;
    int16_t end_code_offset;
    int16_t start_data_offset;
    int16_t end_data_offset;
    int16_t start_brk_offset;
    int16_t brk_offset;
    int16_t start_stack_offset;
    int16_t arg_start_offset;
    int16_t arg_end_offset;
    int16_t env_start_offset;
    int16_t env_end_offset;
};


extern struct mm_struct_offset mm_struct_offset;


#endif
