/* SPDX-License-Identifier: BSD-3-Clause */
/*
 * Copyright 2022 NXP
 */

#ifndef HSE_CORE_H
#define HSE_CORE_H

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

#endif /* HSE_CORE_H */
