// SPDX-License-Identifier: BSD-3-Clause
/*
 * Copyright 2020-2022 NXP
 */

#include <console.h>
#include <drivers/gic.h>
#include <drivers/s32_uart.h>
#include <kernel/boot.h>
#include <kernel/panic.h>
#include <mm/core_mmu.h>
#include <platform_config.h>

static struct gic_data gic_data __nex_bss;
static struct s32_uart_data console_data __nex_bss;

register_phys_mem(MEM_AREA_IO_NSEC, CONSOLE_UART_BASE,
		  CONSOLE_UART_SIZE);

register_phys_mem_pgdir(MEM_AREA_IO_SEC, GICD_BASE, CORE_MMU_PGDIR_SIZE);

void itr_core_handler(void)
{
	gic_it_handle(&gic_data);
}

void main_init_gic(void)
{
	vaddr_t gicd_base;

	gicd_base = core_mmu_get_va(GICD_BASE, MEM_AREA_IO_SEC);
	if (!gicd_base)
		panic();

	/* Initialize GIC */
	gic_init_base_addr(&gic_data, 0, gicd_base);
	itr_init(&gic_data.chip);
}

void console_init(void)
{
	s32_uart_init(&console_data, CONSOLE_UART_BASE);
	register_serial_console(&console_data.chip);
}
