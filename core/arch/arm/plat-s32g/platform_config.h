/* SPDX-License-Identifier: BSD-3-Clause */
/*
 * Copyright 2020 NXP
 */

#ifndef PLATFORM_CONFIG_H
#define PLATFORM_CONFIG_H

#include <mm/generic_ram_layout.h>

#define CONSOLE_UART_BASE		(0x401C8000)
#define CONSOLE_UART_SIZE       (0x4000)

#define GIC_BASE    (0x50800000)
#define GICD_OFFSET (0x0)
#define GICR_OFFSET (0x80000)
#define GICD_BASE   (GIC_BASE + GICD_OFFSET)
#define GICR_BASE   (GIC_BASE + GICR_OFFSET)

#define DRAM0_NSEC_BASE (CFG_SHMEM_START)
#define DRAM0_NSEC_SIZE (CFG_SHMEM_SIZE)

#endif /* PLATFORM_CONFIG_H */
