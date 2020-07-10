/* SPDX-License-Identifier: BSD-3-Clause */
/*
 * Copyright 2020, 2022 NXP
 */

#ifndef PLATFORM_CONFIG_H
#define PLATFORM_CONFIG_H

#include <mm/generic_ram_layout.h>

#define CONSOLE_UART_BASE		(0x401C8000)
#define CONSOLE_UART_SIZE		(0x3000)

#define GIC_BASE	(0x50800000)
#define GICD_BASE	(GIC_BASE)

#define DRAM0_NSEC_BASE (CFG_SHMEM_START)
#define DRAM0_NSEC_SIZE (CFG_SHMEM_SIZE)

#endif /* PLATFORM_CONFIG_H */
