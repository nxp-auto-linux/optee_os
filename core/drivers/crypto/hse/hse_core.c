// SPDX-License-Identifier: BSD-3-Clause
/*
 * Copyright 2022 NXP
 */

#include <hse_mu.h>
#include <initcall.h>
#include <kernel/interrupt.h>
#include <tee_api_types.h>
#include <trace.h>

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

static TEE_Result crypto_driver_init(void)
{
	void *mu = NULL;
	uint16_t status;

	mu = hse_mu_init();
	if (!mu) {
		EMSG("Could not get MU Instance");
		return TEE_ERROR_BAD_STATE;
	}

	status = hse_mu_check_status(mu);
	if (!(status & HSE_STATUS_INIT_OK)) {
		EMSG("Firmware not found");

		hse_mu_free(drv->mu);
		return TEE_ERROR_BAD_STATE;
	}

	IMSG("HSE is successfully initialized");

	return TEE_SUCCESS;
}

early_init(crypto_driver_init);
