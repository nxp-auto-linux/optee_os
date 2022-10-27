/* SPDX-License-Identifier: BSD-3-Clause */
/*
 * Copyright 2022 NXP
 */

#ifndef HSE_DT_H
#define HSE_DT_H

#include <types_ext.h>

int hse_dt_get_regs(paddr_t *regs_base, size_t *regs_size,
		    paddr_t *desc_base, size_t *desc_size);
int hse_dt_get_irq(int *rx_irq);
#endif /* HSE_DT_H */
