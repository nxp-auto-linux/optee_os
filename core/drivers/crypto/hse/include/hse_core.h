/* SPDX-License-Identifier: BSD-3-Clause */
/*
 * Copyright 2022-2023 NXP
 */

#ifndef HSE_CORE_H
#define HSE_CORE_H

#include <hse_keymgmt_common_types.h>
#include <tee_api_types.h>
#include <types_ext.h>

#define HSE_CHANNEL_ANY    0xACu /* use any channel, no request ordering */
#define HSE_CHANNEL_ADM    0u /* channel reserved for administrative services */

#define HSE_SRV_INIT(stype, sname)  \
	typeof(stype) ((sname)) = {0}

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

/**
 * struct hse_buf - HSE buffer management struct
 * @data: data buffer
 * @paddr: physical address of the buffer
 * @size: number of bytes in the data buffer
 */
struct hse_buf {
	uint8_t *data; /* Data buffer */
	paddr_t paddr; /* Physical address of the buffer */
	size_t size;   /* Number of bytes in the data buffer */
};

TEE_Result hse_buf_alloc(struct hse_buf *buf, size_t size);
void hse_buf_free(struct hse_buf *buf);

TEE_Result hse_srv_req_sync(uint8_t channel, const void *srv_desc);
TEE_Result hse_srv_req_async(uint8_t channel, const void *srv_desc,
			     void *ctx,
			     void (*rx_cbk)(TEE_Result err, void *ctx));

hseKeyHandle_t hse_keyslot_acquire(hseKeyType_t type);
void hse_keyslot_release(hseKeyHandle_t handle);
bool hse_keyslot_is_used(hseKeyHandle_t handle);

#endif /* HSE_CORE_H */
