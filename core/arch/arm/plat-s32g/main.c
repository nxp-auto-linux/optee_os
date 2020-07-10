// SPDX-License-Identifier: BSD-3-Clause
/*
 * Copyright 2020 NXP
 */

#include <console.h>
#include <drivers/gic.h>
#include <drivers/s32g_uart.h>
#include <kernel/generic_boot.h>
#include <kernel/panic.h>
#include <kernel/pm_stubs.h>
#include <mm/core_mmu.h>
#include <platform_config.h>

static const struct thread_handlers handlers = {
	.cpu_on = cpu_on_handler,
	.cpu_off = pm_do_nothing,
	.cpu_suspend = pm_do_nothing,
	.cpu_resume = pm_do_nothing,
	.system_off = pm_do_nothing,
	.system_reset = pm_do_nothing,
};

static struct gic_data gic_data;
static struct s32g_uart_data console_data;

register_phys_mem(MEM_AREA_IO_NSEC, CONSOLE_UART_BASE,
		  CONSOLE_UART_SIZE);

register_phys_mem_pgdir(MEM_AREA_IO_SEC, GICD_BASE, CORE_MMU_PGDIR_SIZE);

const struct thread_handlers *generic_boot_get_handlers(void)
{
	return &handlers;
}

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
#ifdef CONSOLE_UART_BASE
	s32g_uart_init(&console_data, CONSOLE_UART_BASE);
	register_serial_console(&console_data.chip);
#endif
}
