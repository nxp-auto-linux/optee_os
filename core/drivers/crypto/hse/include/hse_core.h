/* SPDX-License-Identifier: BSD-3-Clause */
/*
 * Copyright 2022 NXP
 */

#ifndef HSE_CORE_H
#define HSE_CORE_H

#include <tee_api_types.h>

#define HSE_CHANNEL_ANY    0xACu /* use any channel, no request ordering */
#define HSE_CHANNEL_ADM    0u /* channel reserved for administrative services */

/**
 * enum hse_ch_type - channel type
 * @HSE_CHANNEL_ADMIN: restricted to administrative services
 * @HSE_CHANNEL_SHARED: shared channel, available for crypto
 * @HSE_CHANNEL_STREAM: reserved for streaming mode use
 */
enum hse_ch_type {
	HSE_CH_TYPE_ADMIN = 0u,
	HSE_CH_TYPE_SHARED = 1u,
	HSE_CH_TYPE_STREAM = 2u,
};

TEE_Result hse_srv_req_sync(uint8_t channel, const void *srv_desc);

#endif /* HSE_CORE_H */