/* SPDX-License-Identifier: BSD-3-Clause */
/*
 * Copyright 2022 NXP
 */

#ifndef HSE_ABI_H
#define HSE_ABI_H

#include <util.h>

#define HSE_SRV_DESC_MAX_SIZE    256u /* maximum service descriptor size */

/**
 * enum hse_status - HSE status
 * @HSE_STATUS_RNG_INIT_OK: RNG initialization successfully completed
 * @HSE_STATUS_INIT_OK: HSE initialization successfully completed
 * @HSE_STATUS_INSTALL_OK: HSE installation phase successfully completed,
 *                         key stores have been formatted and can be used
 * @HSE_STATUS_PUBLISH_SYS_IMAGE: volatile HSE configuration detected
 */
enum hse_status {
	HSE_STATUS_RNG_INIT_OK = BIT(5),
	HSE_STATUS_INIT_OK = BIT(8),
	HSE_STATUS_INSTALL_OK = BIT(9),
	HSE_STATUS_PUBLISH_SYS_IMAGE = BIT(13),
};

#endif /* HSE_ABI_H */
