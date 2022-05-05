/* SPDX-License-Identifier: BSD-3-Clause */
/*
 * Copyright 2022 NXP
 */

#ifndef HSE_DT_H
#define HSE_DT_H

#include <types_ext.h>

int hse_dt_get_regs(paddr_t *regs_base, size_t *regs_size,
		    paddr_t *desc_base, size_t *desc_size);
#endif /* HSE_DT_H */
