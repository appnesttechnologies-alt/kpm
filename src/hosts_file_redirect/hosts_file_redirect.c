/* SPDX-License-Identifier: GPL-2.0-or-later */
/* 
 * Copyright (C) 2026 Surajit. All Rights Reserved.
 */

#include <linux/printk.h>
#include <linux/string.h>
#include <kpm_utils.h>

// Module details for APatch framework
KPM_NAME("surajit_print_module");
KPM_VERSION("1.0");
KPM_LICENSE("GPL v2");
KPM_AUTHOR("Surajit");
KPM_DESCRIPTION("Simple KPM to print logs safely without crashing.");

// 1. Module load hote hi yeh function execute hoga
static long surajit_module_init(const char *args, const char *event, void *__user reserved)
{
    // Yeh direct kernel ring buffer (dmesg) me high priority print karega
    pr_info("========================================\n");
    pr_info("SURAJIT MODULE LOADED SUCCESSFULLY !!!\n");
    pr_info("========================================\n");
    
    return 0; // 0 matlab successfully initialized without errors
}

// 2. Module unload (disable) hote hi yeh function execute hoga
static long surajit_module_exit(void *__user reserved)
{
    pr_info("SURAJIT MODULE UNLOADED SAFELY WITHOUT FREEZING !\n");
    return 0; // Success
}

// APatch Framework dynamic macros ko register kar rahe hain
KPM_INIT(surajit_module_init);
KPM_EXIT(surajit_module_exit);
