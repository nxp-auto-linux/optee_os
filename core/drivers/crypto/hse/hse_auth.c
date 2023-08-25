// SPDX-License-Identifier: BSD-3-Clause
/*
 * Copyright 2023 NXP
 */

#include <drvcrypt.h>
#include <drvcrypt_authenc.h>
#include <hse_core.h>
#include <hse_interface.h>
#include <hse_services.h>
#include <malloc.h>
#include <string.h>
#include <utee_defines.h>

#define MAX_AAD_LEN 65280
#define MAX_CCM_INPUT_SIZE 5096
#define ENUM_AES_CCM 0
#define ENUM_AES_GCM 1

struct hse_auth_tpl {
	const char *algo_name;
	unsigned int blocksize;
	hseAuthCipherMode_t cipher_type;
};

struct hse_authenc_ctx {
	struct hse_auth_tpl *alg_tpl;
	uint8_t iv[TEE_AES_MAX_KEY_SIZE];
	uint32_t iv_len;
	uint8_t key[TEE_AES_MAX_KEY_SIZE];
	size_t key_len;
	struct hse_buf *aad;
	size_t aad_len;
	size_t saved_aad_len;
	hseKeyHandle_t key_handle;
	hseCipherDir_t direction;
	bool stream_started;
	uint8_t stream_id;
	uint8_t channel;
	uint8_t cached_buf[MAX_CCM_INPUT_SIZE];
	size_t cached_size;
	size_t tag_len;
};

static struct hse_auth_tpl hse_auth_algs_tpl[] = {
	[ENUM_AES_CCM] = {
		.algo_name = "ccm(aes)",
		.blocksize = TEE_AES_BLOCK_SIZE,
		.cipher_type = HSE_AUTH_CIPHER_MODE_CCM,
	},
	[ENUM_AES_GCM] = {
		.algo_name = "gcm(aes)",
		.blocksize = TEE_AES_BLOCK_SIZE,
		.cipher_type = HSE_AUTH_CIPHER_MODE_GCM,
	},
};

static struct hse_auth_tpl *get_authalgo(uint32_t algo)
{
	if (algo == TEE_ALG_AES_CCM)
		return &hse_auth_algs_tpl[ENUM_AES_CCM];
	else if (algo == TEE_ALG_AES_GCM)
		return &hse_auth_algs_tpl[ENUM_AES_GCM];
	return NULL;
}

static TEE_Result hse_import_authkey(struct drvcrypt_buf key,
				     hseKeyType_t key_type,
				     hseCipherDir_t direction,
				     hseKeyHandle_t *handle)
{
	TEE_Result ret;
	hseKeyInfo_t key_info = {0};
	struct hse_buf *key_buf = NULL;
	size_t key_bitlen = HSE_BYTES_TO_BITS(key.length);

	if (!key.data || !key.length)
		return TEE_ERROR_BAD_PARAMETERS;

	/* The bit length is stored in an uint16_t field of key_info */
	if (key_bitlen > UINT16_MAX)
		return TEE_ERROR_BAD_PARAMETERS;

	key_buf = hse_buf_init(key.data, key.length);
	if (!key_buf)
		return TEE_ERROR_OUT_OF_MEMORY;

	key_info.keyFlags = (direction == HSE_CIPHER_DIR_ENCRYPT) ?
				HSE_KF_USAGE_ENCRYPT : HSE_KF_USAGE_DECRYPT;
	key_info.keyBitLen = key_bitlen;
	key_info.keyType = key_type;

	ret = hse_acquire_and_import_key(handle, &key_info, NULL, NULL,
					 key_buf);

	hse_buf_free(key_buf);

	return ret;
}

static void hse_authenc_free_ctx(void *ctx)
{
	struct hse_authenc_ctx *hse_ctx = ctx;

	if (!hse_ctx)
		return;

	hse_buf_free(hse_ctx->aad);

	free(hse_ctx);
}

static TEE_Result hse_authenc_alloc_ctx(void **ctx, uint32_t algo)
{
	TEE_Result res;
	struct hse_authenc_ctx *hse_ctx;
	struct hse_auth_tpl *alg_tpl;

	hse_ctx = calloc(1, sizeof(*hse_ctx));
	if (!hse_ctx) {
		res = TEE_ERROR_OUT_OF_MEMORY;
		goto out_err;
	}
	alg_tpl = get_authalgo(algo);
	if (!alg_tpl) {
		DMSG("HSE does not implement alg type 0x%x", algo);
		res = TEE_ERROR_NOT_IMPLEMENTED;
		goto out_free_ctx;
	}
	hse_ctx->alg_tpl = alg_tpl;
	hse_ctx->key_handle = HSE_INVALID_KEY_HANDLE;
	hse_ctx->stream_id = HSE_STREAM_COUNT;
	hse_ctx->aad = NULL;
	*ctx = hse_ctx;

	DMSG("Allocated context for algo %s", alg_tpl->algo_name);
	return TEE_SUCCESS;

out_free_ctx:
	free(hse_ctx);
out_err:
	return res;
}

static void hse_authenc_reset(struct hse_authenc_ctx *hse_ctx)
{
	if (hse_ctx->key_handle != HSE_INVALID_KEY_HANDLE)
		hse_release_and_erase_key(hse_ctx->key_handle);

	hse_buf_free(hse_ctx->aad);
	hse_ctx->aad = NULL;
	hse_stream_channel_release(hse_ctx->stream_id);
	hse_ctx->stream_id = HSE_STREAM_COUNT;
	hse_ctx->channel = 0;
	hse_ctx->saved_aad_len = 0;
	hse_ctx->stream_started = false;
	hse_ctx->cached_size = 0;
}

static TEE_Result
hse_check_init_params(struct drvcrypt_authenc_init *dinit)
{
	struct hse_authenc_ctx *hse_ctx = dinit->ctx;

	if (!dinit->key.data || !dinit->key.length)
		return TEE_ERROR_BAD_PARAMETERS;
	if (!dinit->nonce.data || !dinit->nonce.length)
		return TEE_ERROR_BAD_PARAMETERS;
	if (dinit->key.length != 16 && dinit->key.length != 24 &&
	    dinit->key.length != 32)
		return TEE_ERROR_BAD_PARAMETERS;
	switch (hse_ctx->alg_tpl->cipher_type) {
	case HSE_AUTH_CIPHER_MODE_CCM:
		if (dinit->nonce.length < 7 || dinit->nonce.length > 13)
			return TEE_ERROR_BAD_PARAMETERS;

		if (dinit->aad_len > MAX_AAD_LEN)
			return TEE_ERROR_BAD_PARAMETERS;

		if ((dinit->tag_len % 2) || dinit->tag_len > 16 ||
		    dinit->tag_len < 4)
			return TEE_ERROR_BAD_PARAMETERS;
		break;
	case HSE_AUTH_CIPHER_MODE_GCM:
		if (dinit->nonce.length >= UINT32_MAX)
			return TEE_ERROR_BAD_PARAMETERS;
		if (dinit->tag_len != 4 && dinit->tag_len != 8 &&
		    dinit->tag_len < 12 && dinit->tag_len > 16)
			return TEE_ERROR_BAD_PARAMETERS;
		break;
	default:
		return TEE_ERROR_BAD_PARAMETERS;
	}
	return TEE_SUCCESS;
}

static TEE_Result hse_authenc_init(struct drvcrypt_authenc_init *dinit)
{
	TEE_Result res;
	struct hse_authenc_ctx *hse_ctx = dinit->ctx;
	hseAuthDir_t direction;

	direction = dinit->encrypt ? HSE_CIPHER_DIR_ENCRYPT :
				HSE_CIPHER_DIR_DECRYPT;

	res = hse_check_init_params(dinit);
	if (res != TEE_SUCCESS)
		goto out;

	hse_authenc_reset(hse_ctx);
	res = hse_stream_channel_acquire(&hse_ctx->channel,
					 &hse_ctx->stream_id);
	if (res != TEE_SUCCESS)
		goto out;

	hse_ctx->key_len = dinit->key.length;
	memcpy(hse_ctx->key, dinit->key.data, hse_ctx->key_len);
	hse_ctx->aad_len = dinit->aad_len;
	if (hse_ctx->aad_len) {
		hse_ctx->aad = hse_buf_alloc(hse_ctx->aad_len);
		if (!hse_ctx->aad) {
			res = TEE_ERROR_OUT_OF_MEMORY;
			goto out_free_stream;
		}
	}
	hse_ctx->direction = direction;
	hse_ctx->tag_len = dinit->tag_len;
	res = hse_import_authkey(dinit->key, HSE_KEY_TYPE_AES,
				 direction, &hse_ctx->key_handle);
	if (res != TEE_SUCCESS)
		goto out_free_aad;

	memcpy(hse_ctx->iv, dinit->nonce.data, dinit->nonce.length);
	hse_ctx->iv_len = dinit->nonce.length;
	return TEE_SUCCESS;

out_free_aad:
	hse_buf_free(hse_ctx->aad);
out_free_stream:
	hse_stream_channel_release(hse_ctx->stream_id);
out:
	return res;
}

static TEE_Result
hse_authenc_update_aad(struct drvcrypt_authenc_update_aad *update)
{
	struct hse_authenc_ctx *hse_ctx = update->ctx;
	TEE_Result res;

	if (update->aad.length + hse_ctx->saved_aad_len > hse_ctx->aad_len)
		return TEE_ERROR_BAD_PARAMETERS;

	res = hse_buf_put_data(hse_ctx->aad, update->aad.data,
			       update->aad.length, hse_ctx->saved_aad_len);
	if (res != TEE_SUCCESS)
		return res;

	hse_ctx->saved_aad_len += update->aad.length;
	return TEE_SUCCESS;
}

static TEE_Result
hse_authenc_start_stream(struct drvcrypt_authenc_update_payload *d)
{
	TEE_Result res;
	struct hse_authenc_ctx *hse_ctx = d->ctx;
	struct hse_buf *iv = NULL;
	hseAuthDir_t direction;

	HSE_SRV_INIT(hseSrvDescriptor_t, srv_desc);

	iv = hse_buf_init(hse_ctx->iv, hse_ctx->iv_len);
	if (!iv)
		return TEE_ERROR_OUT_OF_MEMORY;

	direction = d->encrypt ? HSE_CIPHER_DIR_ENCRYPT :
				HSE_CIPHER_DIR_DECRYPT;
	srv_desc.srvId = HSE_SRV_ID_AEAD;
	srv_desc.hseSrv.aeadReq.accessMode = HSE_ACCESS_MODE_START;
	srv_desc.hseSrv.aeadReq.sgtOption = HSE_SGT_OPTION_NONE;
	srv_desc.hseSrv.aeadReq.streamId = hse_ctx->stream_id;
	srv_desc.hseSrv.aeadReq.authCipherMode = hse_ctx->alg_tpl->cipher_type;
	srv_desc.hseSrv.aeadReq.cipherDir = direction;
	srv_desc.hseSrv.aeadReq.keyHandle = hse_ctx->key_handle;
	srv_desc.hseSrv.aeadReq.ivLength = hse_buf_get_size(iv);
	srv_desc.hseSrv.aeadReq.pIV = hse_buf_get_paddr(iv);
	srv_desc.hseSrv.aeadReq.aadLength = hse_buf_get_size(hse_ctx->aad);
	srv_desc.hseSrv.aeadReq.pAAD = hse_buf_get_paddr(hse_ctx->aad);
	res = hse_srv_req_sync(hse_ctx->channel, &srv_desc);
	hse_buf_free(iv);

	if (res != TEE_SUCCESS) {
		EMSG("hse_srv_req_sync returned with err 0x%x", res);
		return res;
	}
	return TEE_SUCCESS;
}

static TEE_Result
hse_authenc_update_payload(struct drvcrypt_authenc_update_payload *d)
{
	TEE_Result res;
	struct hse_authenc_ctx *hse_ctx = d->ctx;
	hseCipherDir_t direction;
	struct hse_buf *input = NULL, *output = NULL;
	size_t input_len, blks, rem;

	HSE_SRV_INIT(hseSrvDescriptor_t, srv_desc);

	direction = d->encrypt ? HSE_CIPHER_DIR_ENCRYPT :
				HSE_CIPHER_DIR_DECRYPT;

	if (!d->src.length) {
		d->dst.length = 0;
		return TEE_SUCCESS;
	}
	if (!d->src.data || !d->dst.data || !d->dst.length)
		return TEE_ERROR_BAD_PARAMETERS;

	/* Streaming mode is exclusive to GCM */
	if (hse_ctx->alg_tpl->cipher_type == HSE_AUTH_CIPHER_MODE_CCM) {
		memcpy(hse_ctx->cached_buf + hse_ctx->cached_size,
		       d->src.data, d->src.length);
		hse_ctx->cached_size += d->src.length;
		d->dst.length = 0;
		return TEE_SUCCESS;
	}
	if (!hse_ctx->stream_started) {
		res = hse_authenc_start_stream(d);
		if (res != TEE_SUCCESS)
			return res;
		hse_ctx->stream_started = true;
	}
	input_len = d->src.length + hse_ctx->cached_size;
	rem = input_len % hse_ctx->alg_tpl->blocksize;
	blks = input_len / hse_ctx->alg_tpl->blocksize;
	input_len -= rem;
	if (!input_len) {
		memcpy(hse_ctx->cached_buf + hse_ctx->cached_size,
		       d->src.data, d->src.length);
		hse_ctx->cached_size += d->src.length;
		d->dst.length = 0;
		return TEE_SUCCESS;
	}
	input = hse_buf_alloc(input_len);
	if (!input)
		return TEE_ERROR_OUT_OF_MEMORY;
	res = hse_buf_put_data(input, hse_ctx->cached_buf,
			       hse_ctx->cached_size, 0);
	if (res != TEE_SUCCESS)
		goto out;

	res = hse_buf_put_data(input, d->src.data,
			       input_len - hse_ctx->cached_size,
			       hse_ctx->cached_size);
	if (res != TEE_SUCCESS)
		goto out;

	hse_ctx->cached_size = 0;
	output = hse_buf_alloc(input_len);
	if (!output)
		goto out;

	srv_desc.srvId = HSE_SRV_ID_AEAD;
	srv_desc.hseSrv.aeadReq.accessMode = HSE_ACCESS_MODE_UPDATE;
	srv_desc.hseSrv.aeadReq.sgtOption = HSE_SGT_OPTION_NONE;
	srv_desc.hseSrv.aeadReq.streamId = hse_ctx->stream_id;
	srv_desc.hseSrv.aeadReq.inputLength = hse_buf_get_size(input);
	srv_desc.hseSrv.aeadReq.pInput = hse_buf_get_paddr(input);
	srv_desc.hseSrv.aeadReq.pOutput = hse_buf_get_paddr(output);
	srv_desc.hseSrv.aeadReq.cipherDir = direction;
	res = hse_srv_req_sync(hse_ctx->channel, &srv_desc);
	if (res != TEE_SUCCESS) {
		EMSG("hse_srv_req_sync returned with err 0x%x", res);
		goto out;
	}
	hse_ctr_inc(hse_ctx->iv, blks, hse_ctx->alg_tpl->blocksize);
	hse_buf_get_data(output, d->dst.data, input_len, 0);
	d->dst.length = input_len;
	if (rem) {
		memcpy(hse_ctx->cached_buf,
		       d->src.data + d->src.length - rem, rem);
		hse_ctx->cached_size = rem;
	}

out:
	hse_buf_free(output);
	hse_buf_free(input);
	return res;
}

static TEE_Result hse_authenc_crypt_final(struct drvcrypt_authenc_final *dfinal,
					  hseCipherDir_t direction)
{
	TEE_Result res = TEE_ERROR_OUT_OF_MEMORY;
	struct hse_authenc_ctx *hse_ctx = dfinal->ctx;
	struct hse_buf *input = NULL, *output = NULL, *tag = NULL, *iv = NULL;
	uint32_t input_len;

	HSE_SRV_INIT(hseSrvDescriptor_t, srv_desc);

	if (dfinal->tag.length != hse_ctx->tag_len)
		return TEE_ERROR_BAD_PARAMETERS;
	iv = hse_buf_init(hse_ctx->iv, hse_ctx->iv_len);
	if (!iv)
		goto out;

	if (direction == HSE_CIPHER_DIR_DECRYPT)
		tag = hse_buf_init(dfinal->tag.data, dfinal->tag.length);
	else
		tag = hse_buf_alloc(dfinal->tag.length);

	if (!tag)
		goto out_free_iv;

	if (ADD_OVERFLOW(dfinal->src.length, hse_ctx->cached_size,
			 &input_len)) {
		res = TEE_ERROR_OVERFLOW;
		goto out_free_iv;
	}
	if (input_len != 0) {
		input = hse_buf_alloc(input_len);
		if (!input)
			goto out_free_tag;
		res = hse_buf_put_data(input, hse_ctx->cached_buf,
				       hse_ctx->cached_size, 0);
		if (res != TEE_SUCCESS)
			goto out_free_input;
		res = hse_buf_put_data(input, dfinal->src.data,
				       dfinal->src.length,
					   hse_ctx->cached_size);
		if (res != TEE_SUCCESS)
			goto out_free_input;
		output = hse_buf_alloc(input_len);
		if (!output) {
			res = TEE_ERROR_OUT_OF_MEMORY;
			goto out_free_input;
		}
	}
	srv_desc.srvId = HSE_SRV_ID_AEAD;
	srv_desc.hseSrv.aeadReq.inputLength = hse_buf_get_size(input);
	srv_desc.hseSrv.aeadReq.sgtOption = HSE_SGT_OPTION_NONE;
	srv_desc.hseSrv.aeadReq.streamId = hse_ctx->stream_id;
	srv_desc.hseSrv.aeadReq.tagLength = hse_buf_get_size(tag);
	srv_desc.hseSrv.aeadReq.pTag = hse_buf_get_paddr(tag);
	srv_desc.hseSrv.aeadReq.pInput = hse_buf_get_paddr(input);
	srv_desc.hseSrv.aeadReq.pOutput = hse_buf_get_paddr(output);
	srv_desc.hseSrv.aeadReq.authCipherMode = hse_ctx->alg_tpl->cipher_type;
	srv_desc.hseSrv.aeadReq.cipherDir = direction;
	srv_desc.hseSrv.aeadReq.keyHandle = hse_ctx->key_handle;
	srv_desc.hseSrv.aeadReq.ivLength = hse_buf_get_size(iv);
	srv_desc.hseSrv.aeadReq.pIV = hse_buf_get_paddr(iv);
	srv_desc.hseSrv.aeadReq.aadLength = hse_buf_get_size(hse_ctx->aad);
	srv_desc.hseSrv.aeadReq.pAAD = hse_buf_get_paddr(hse_ctx->aad);
	if (!hse_ctx->stream_started)
		srv_desc.hseSrv.aeadReq.accessMode = HSE_ACCESS_MODE_ONE_PASS;
	else
		srv_desc.hseSrv.aeadReq.accessMode = HSE_ACCESS_MODE_FINISH;

	res = hse_srv_req_sync(hse_ctx->channel, &srv_desc);
	if (res != TEE_SUCCESS)
		goto out_free_output;
	if (input_len > 0)
		hse_buf_get_data(output, dfinal->dst.data, input_len, 0);
	if (direction == HSE_CIPHER_DIR_ENCRYPT)
		hse_buf_get_data(tag, dfinal->tag.data, dfinal->tag.length, 0);
	dfinal->dst.length = input_len;
out_free_output:
	hse_buf_free(output);
out_free_input:
	hse_buf_free(input);
out_free_tag:
	hse_buf_free(tag);
out_free_iv:
	hse_buf_free(iv);
out:
	return res;
}

static TEE_Result hse_authenc_enc_final(struct drvcrypt_authenc_final *dfinal)
{
	return hse_authenc_crypt_final(dfinal, HSE_CIPHER_DIR_ENCRYPT);
}

static TEE_Result hse_authenc_dec_final(struct drvcrypt_authenc_final *dfinal)
{
	return hse_authenc_crypt_final(dfinal, HSE_CIPHER_DIR_DECRYPT);
}

static void hse_authenc_final(void *ctx)
{
	struct hse_authenc_ctx *hse_ctx = ctx;

	hse_authenc_reset(hse_ctx);
}

static void hse_authenc_copy_state(void *dst_ctx, void *src_ctx)
{
	struct hse_authenc_ctx *dst;
	struct hse_authenc_ctx *src;
	uint32_t size;

	dst = dst_ctx;
	src = src_ctx;
	if (src && dst) {
		struct drvcrypt_authenc_init init_params = {
			.aad_len = src->aad_len,
			.ctx = dst,
			.encrypt = src->direction,
			.key = {
				.data = src->key,
				.length = src->key_len,
			},
			.nonce = {
				.data = src->iv,
				.length = src->iv_len,
			},
			.payload_len = MAX_CCM_INPUT_SIZE,
			.tag_len = src->tag_len,
		};
		hse_authenc_init(&init_params);
	} else {
		return;
	}
	dst->stream_started = src->stream_started;
	if (src->aad) {
		size = hse_buf_get_size(src->aad);
		hse_buf_copy(src->aad, dst->aad, size);
		dst->aad_len = src->aad_len;
		dst->saved_aad_len = src->saved_aad_len;
	}
	dst->cached_size = src->cached_size;
	memcpy(dst->cached_buf, src->cached_buf, src->cached_size);
	if (src->stream_started)
		hse_stream_ctx_copy(src->stream_id, dst->stream_id);
}

static struct drvcrypt_authenc driver_authenc = {
	.alloc_ctx = hse_authenc_alloc_ctx,
	.free_ctx = hse_authenc_free_ctx,
	.init = hse_authenc_init,
	.update_aad = hse_authenc_update_aad,
	.update_payload = hse_authenc_update_payload,
	.enc_final = hse_authenc_enc_final,
	.dec_final = hse_authenc_dec_final,
	.final = hse_authenc_final,
	.copy_state = hse_authenc_copy_state,
};

TEE_Result hse_authenc_register(void)
{
	return drvcrypt_register_authenc(&driver_authenc);
}
