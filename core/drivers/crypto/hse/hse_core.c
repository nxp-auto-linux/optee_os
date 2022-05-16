// SPDX-License-Identifier: BSD-3-Clause
/*
 * Copyright 2022 NXP
 */

#include <hse_abi.h>
#include <hse_core.h>
#include <hse_mu.h>
#include <initcall.h>
#include <kernel/interrupt.h>
#include <malloc.h>
#include <tee_api_types.h>
#include <trace.h>

/**
 * struct hse_drvdata - HSE driver private data
 * @srv_desc[n].ptr: service descriptor virtual address for channel n
 * @srv_desc[n].dma: service descriptor DMA address for channel n
 * @srv_desc[n].id: current service request ID for channel n
 * @mu: MU instance handle returned by lower abstraction layer
 * @type[n]: designated type of service channel n
 */
struct hse_drvdata {
	struct {
		void  *ptr;
		paddr_t dma;
		uint32_t id;
	} srv_desc[HSE_NUM_CHANNELS];
	void *mu;
	enum hse_ch_type type[HSE_NUM_CHANNELS];
};

static struct hse_drvdata *drv;

/**
 * hse_config_channels - configure channels and manage descriptor space
 *
 * HSE firmware restricts channel zero to administrative services, all the rest
 * are usable for crypto operations. Driver reserves the last HSE_STREAM_COUNT
 * channels for streaming mode use and marks the remaining as shared channels.
 */
static inline void hse_config_channels(void)
{
	unsigned int offset;
	uint8_t channel;
	vaddr_t ch_addr;

	drv->type[0] = HSE_CH_TYPE_ADMIN;
	drv->srv_desc[0].ptr = hse_mu_desc_base_ptr(drv->mu);
	drv->srv_desc[0].dma = hse_mu_desc_base_dma(drv->mu);

	for (channel = 1; channel < HSE_NUM_CHANNELS; channel++) {
		if (channel >= HSE_NUM_CHANNELS - HSE_STREAM_COUNT)
			drv->type[channel] = HSE_CH_TYPE_STREAM;
		else
			drv->type[channel] = HSE_CH_TYPE_SHARED;

		offset = channel * HSE_SRV_DESC_MAX_SIZE;
		ch_addr = (vaddr_t)drv->srv_desc[0].ptr + offset;

		drv->srv_desc[channel].ptr = (void *)ch_addr;
		drv->srv_desc[channel].dma = drv->srv_desc[0].dma + offset;
	}
}

static TEE_Result crypto_driver_init(void)
{
	TEE_Result ret = TEE_ERROR_GENERIC;
	uint16_t status;

	drv = malloc(sizeof(*drv));
	if (!drv) {
		EMSG("Could not malloc drv instance");
		return TEE_ERROR_OUT_OF_MEMORY;
	}

	drv->mu = hse_mu_init();
	if (!drv->mu) {
		EMSG("Could not get MU Instance");
		return TEE_ERROR_GENERIC;
	}

	status = hse_mu_check_status(drv->mu);
	if (!(status & HSE_STATUS_INIT_OK)) {
		EMSG("Firmware not found");
		return TEE_ERROR_BAD_STATE;
	}

	hse_config_channels();

	IMSG("HSE is successfully initialized");

	return TEE_SUCCESS;
}

early_init(crypto_driver_init);
