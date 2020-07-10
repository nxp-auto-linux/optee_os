// SPDX-License-Identifier: BSD-3-Clause
/*
 * Copyright 2020-2022 NXP
 */

#include <console.h>
#include <drivers/gic.h>
#include <drivers/s32_uart.h>
#include <kernel/boot.h>
#include <mm/core_mmu.h>
#include <platform_config.h>

static struct gic_data gic_data;
static struct s32_uart_data console_data;

register_phys_mem(MEM_AREA_IO_NSEC, CONSOLE_UART_BASE,
		  CONSOLE_UART_SIZE);

register_phys_mem(MEM_AREA_IO_SEC, GICD_BASE, GIC_DIST_REG_SIZE);

void itr_core_handler(void)
{
	gic_it_handle(&gic_data);
}

void main_init_gic(void)
{
	/* Initialize GIC */
	gic_init_base_addr(&gic_data, 0, GICD_BASE);
	itr_init(&gic_data.chip);
}

void console_init(void)
{
	s32_uart_init(&console_data, CONSOLE_UART_BASE, CONSOLE_UART_SIZE);
	register_serial_console(&console_data.chip);
}
