/* SPDX-License-Identifier: BSD-3-Clause */
/*
 * Copyright 2020 NXP
 */

#ifndef S32G_UART_H
#define S32G_UART_H

#include <types_ext.h>
#include <drivers/serial.h>

struct s32g_uart_data {
	struct io_pa_va base;
	struct serial_chip chip;
};

void s32g_uart_init(struct s32g_uart_data *pd, paddr_t pbase);

#endif /* S32G_UART_H */
