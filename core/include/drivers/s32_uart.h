/* SPDX-License-Identifier: BSD-3-Clause */
/*
 * Copyright 2020,2022 NXP
 */

#ifndef S32_UART_H
#define S32_UART_H

#include <types_ext.h>
#include <drivers/serial.h>

struct s32_uart_data {
	struct io_pa_va base;
	size_t len;
	struct serial_chip chip;
};

void s32_uart_init(struct s32_uart_data *pd, paddr_t pbase, size_t len);

#endif /* S32_UART_H */
