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

/* Opaque data type */
struct hse_buf;

struct hse_buf *hse_buf_alloc(size_t size);
void hse_buf_free(struct hse_buf *buf);
struct hse_buf *hse_buf_init(const void *data, size_t size);

TEE_Result hse_buf_put_data(struct hse_buf *buf, const void *data, size_t size,
			    size_t offset);
TEE_Result hse_buf_get_data(struct hse_buf *buf, void *data, size_t size,
			    size_t offset);

uint32_t hse_buf_get_size(struct hse_buf *buf);
paddr_t hse_buf_get_paddr(struct hse_buf *buf);

bool is_hse_status_ok(void);

TEE_Result hse_srv_req_sync(uint8_t channel, const void *srv_desc);
TEE_Result hse_srv_req_async(uint8_t channel, const void *srv_desc,
			     void *ctx,
			     void (*rx_cbk)(TEE_Result err, void *ctx));

hseKeyHandle_t hse_keyslot_acquire(hseKeyType_t type);
void hse_keyslot_release(hseKeyHandle_t handle);
bool hse_keyslot_is_used(hseKeyHandle_t handle);

TEE_Result hse_import_key(hseKeyHandle_t handle, hseKeyInfo_t *key_info,
			  struct hse_buf *key0, struct hse_buf *key1,
			  struct hse_buf *key2);
TEE_Result hse_acquire_and_import_key(hseKeyHandle_t *handle,
				      hseKeyInfo_t *key_info,
				      struct hse_buf *key0,
				      struct hse_buf *key1,
				      struct hse_buf *key2);
void hse_erase_key(hseKeyHandle_t handle);
void hse_release_and_erase_key(hseKeyHandle_t handle);

TEE_Result hse_stream_channel_acquire(uint8_t *channel, uint8_t *stream_id);
void hse_stream_channel_release(uint8_t stream_id);
TEE_Result hse_stream_ctx_copy(uint8_t src_stream, uint8_t dst_stream);

#endif /* HSE_CORE_H */
