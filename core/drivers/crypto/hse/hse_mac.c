// SPDX-License-Identifier: BSD-3-Clause
/*
 * Copyright 2023 NXP
 */

#include <assert.h>
#include <drvcrypt_mac.h>
#include <hse_core.h>
#include <hse_interface.h>
#include <hse_services.h>
#include <malloc.h>
#include <string.h>
#include <tee/cache.h>
#include <utee_defines.h>
#include <util.h>

struct hse_mac_tpl {
	uint32_t algo_id;
	uint32_t algo_mode;
	hseMacScheme_t mac_scheme;
	size_t blocksize;
	size_t tagsize;
};

struct hse_mac_ctx {
	struct crypto_mac_ctx drv_ctx;
	bool initialized;
	const struct hse_mac_tpl *mac_tpl;
	struct drvcrypt_buf key;
	hseKeyHandle_t key_handle;
	struct drvcrypt_buf cached_blks;
	struct drvcrypt_buf left_bytes;
	uint8_t stream_id;
	uint8_t channel;
	bool stream_started;
};

static const struct hse_mac_tpl hse_mac_algs_tpl[] = {
#ifdef HSE_HASH_ALGO_MD5
	{
		.algo_id = TEE_MAIN_ALGO_MD5,
		.mac_scheme = {
			.macAlgo = HSE_MAC_ALGO_HMAC,
			.sch.hmac.hashAlgo = HSE_HASH_ALGO_MD5,
		},
		.blocksize = 64,
		.tagsize = 16,
	},
#endif
	{
		.algo_id = TEE_MAIN_ALGO_SHA1,
		.mac_scheme = {
			.macAlgo = HSE_MAC_ALGO_HMAC,
			.sch.hmac.hashAlgo = HSE_HASH_ALGO_SHA_1,
		},
		.blocksize = 64,
		.tagsize = 20,
	},
	{
		.algo_id = TEE_MAIN_ALGO_SHA224,
		.mac_scheme = {
			.macAlgo = HSE_MAC_ALGO_HMAC,
			.sch.hmac.hashAlgo = HSE_HASH_ALGO_SHA2_224,
		},
		.blocksize = 64,
		.tagsize = 28,
	},
	{
		.algo_id = TEE_MAIN_ALGO_SHA256,
		.mac_scheme = {
			.macAlgo = HSE_MAC_ALGO_HMAC,
			.sch.hmac.hashAlgo = HSE_HASH_ALGO_SHA2_256,
		},
		.blocksize = 64,
		.tagsize = 32,
	},
	{
		.algo_id = TEE_MAIN_ALGO_SHA384,
		.mac_scheme = {
			.macAlgo = HSE_MAC_ALGO_HMAC,
			.sch.hmac.hashAlgo = HSE_HASH_ALGO_SHA2_384,
		},
		.blocksize = 128,
		.tagsize = 48,
	},
	{
		.algo_id = TEE_MAIN_ALGO_SHA512,
		.mac_scheme = {
			.macAlgo = HSE_MAC_ALGO_HMAC,
			.sch.hmac.hashAlgo = HSE_HASH_ALGO_SHA2_512,
		},
		.blocksize = 128,
		.tagsize = 64,
	},
	{
		.algo_id = TEE_MAIN_ALGO_AES,
		.algo_mode = TEE_CHAIN_MODE_CMAC,
		.mac_scheme = {
			.macAlgo = HSE_MAC_ALGO_CMAC,
			.sch.cmac.cipherAlgo = HSE_CIPHER_ALGO_AES,
		},
		.blocksize = 16,
		.tagsize = 16,
	},

};

static const struct crypto_mac_ops hse_mac_ops;

static struct hse_mac_ctx *to_hse_mac_ctx(struct crypto_mac_ctx *ctx)
{
	assert(ctx && ctx->ops == &hse_mac_ops);
	return container_of(ctx, struct hse_mac_ctx, drv_ctx);
}

static const struct hse_mac_tpl *get_mac_tpl(uint32_t algo)
{
	uint32_t algo_id = TEE_ALG_GET_MAIN_ALG(algo);
	uint32_t algo_mode = TEE_ALG_GET_CHAIN_MODE(algo);
	const struct hse_mac_tpl *mac_tpl = NULL;
	size_t i;

	if (!algo_id)
		return NULL;

	for (i = 0; i < ARRAY_SIZE(hse_mac_algs_tpl); i++)
		if (hse_mac_algs_tpl[i].algo_id == algo_id &&
		    hse_mac_algs_tpl[i].algo_mode == algo_mode) {
			mac_tpl = &hse_mac_algs_tpl[i];
			break;
		}

	return mac_tpl;
}

static TEE_Result hse_mac_alloc(struct crypto_mac_ctx **ctx, uint32_t algo)
{
	TEE_Result ret;
	struct hse_mac_ctx *priv = NULL;
	size_t blocksize;

	if (!ctx || !algo)
		return TEE_ERROR_BAD_PARAMETERS;

	priv = calloc(1, sizeof(*priv));
	if (!priv)
		return TEE_ERROR_OUT_OF_MEMORY;

	priv->drv_ctx.ops = &hse_mac_ops;

	priv->mac_tpl = get_mac_tpl(algo);
	if (!priv->mac_tpl) {
		ret = TEE_ERROR_NOT_IMPLEMENTED;
		goto out_free_priv;
	}

	blocksize = priv->mac_tpl->blocksize;

	priv->left_bytes.data = calloc(1, blocksize);
	if (!priv->left_bytes.data) {
		ret = TEE_ERROR_OUT_OF_MEMORY;
		goto out_free_priv;
	}

	priv->key_handle = HSE_INVALID_KEY_HANDLE;
	priv->stream_id = HSE_STREAM_COUNT;

	*ctx = &priv->drv_ctx;

	return TEE_SUCCESS;

out_free_priv:
	EMSG("HSE MAC Allocation Operation failed with err 0x%x", ret);
	free(priv);
	return ret;
}

static void drvcrypt_buf_free(struct drvcrypt_buf *buf)
{
	if (!buf)
		return;

	buf->length = 0;

	if (buf->data) {
		free(buf->data);
		buf->data = NULL;
	}
}

static void hse_mac_reset(struct hse_mac_ctx *hse_ctx)
{
	if (!hse_ctx || !hse_ctx->initialized)
		return;

	hse_stream_channel_release(hse_ctx->stream_id);
	hse_ctx->stream_id = HSE_STREAM_COUNT;
	hse_ctx->channel = 0;
	hse_ctx->stream_started = false;

	hse_release_and_erase_key(hse_ctx->key_handle);
	hse_ctx->key_handle = HSE_INVALID_KEY_HANDLE;

	drvcrypt_buf_free(&hse_ctx->key);
	drvcrypt_buf_free(&hse_ctx->cached_blks);

	/* 'left_bytes' is allocated during hse_mac_alloc() operation
	 * and should be freed in the corresponding hse_mac_free().
	 * Its size is known at allocation time and stays the same throughout
	 * the operation's lifetime
	 */
	hse_ctx->left_bytes.length = 0;

	hse_ctx->initialized = false;
}

static void hse_mac_free(struct crypto_mac_ctx *ctx)
{
	struct hse_mac_ctx *hse_ctx = to_hse_mac_ctx(ctx);

	hse_mac_reset(hse_ctx);

	if (hse_ctx->left_bytes.data)
		free(hse_ctx->left_bytes.data);

	free(hse_ctx);
}

static TEE_Result hse_import_mackey(struct crypto_mac_ctx *ctx,
				    const uint8_t *key, size_t len)
{
	TEE_Result ret;
	struct hse_mac_ctx *hse_ctx = to_hse_mac_ctx(ctx);
	struct hse_buf key_buf;
	hseMacAlgo_t mac_algo = hse_ctx->mac_tpl->mac_scheme.macAlgo;
	hseKeyHandle_t *key_handle = &hse_ctx->key_handle;
	hseKeyInfo_t key_info = {0};
	size_t key_buf_len;

	if (!key || !len)
		return TEE_ERROR_BAD_PARAMETERS;

	/* In case of HMAC algos, pad the provided key with zeros, up to
	 * HSE_BITS_TO_BYTES(HSE_MIN_HMAC_KEY_BITS_LEN) if its length is smaller
	 * than this size
	 */
	if (mac_algo == HSE_MAC_ALGO_HMAC)
		key_buf_len = MAX(len,
				  HSE_BITS_TO_BYTES(HSE_MIN_HMAC_KEY_BITS_LEN));
	else
		key_buf_len = len;

	/* Check if the shift would wrap, resulting in lost data when assigning
	 * the value to key_info.keyBitLen
	 */
	if (HSE_BYTES_TO_BITS(key_buf_len) > UINT16_MAX)
		return TEE_ERROR_BAD_PARAMETERS;

	ret = hse_buf_alloc(&key_buf, key_buf_len);
	if (ret != TEE_SUCCESS)
		goto out;
	memset(key_buf.data, 0, key_buf_len);
	memcpy(key_buf.data, key, len);

	key_info.keyFlags = HSE_KF_USAGE_SIGN;
	key_info.keyBitLen = HSE_BYTES_TO_BITS(key_buf_len);
	key_info.keyType = (mac_algo == HSE_MAC_ALGO_HMAC) ? HSE_KEY_TYPE_HMAC :
							     HSE_KEY_TYPE_AES;

	ret = hse_acquire_and_import_key(key_handle, &key_info, NULL, NULL,
					 &key_buf);
	hse_buf_free(&key_buf);

out:
	if (ret != TEE_SUCCESS)
		EMSG("HSE Import of MAC Key failed with err 0x%x", ret);

	return ret;
}

static TEE_Result hse_mac_init(struct crypto_mac_ctx *ctx, const uint8_t *key,
			       size_t len)
{
	TEE_Result ret;
	struct hse_mac_ctx *hse_ctx = to_hse_mac_ctx(ctx);
	struct drvcrypt_buf *ctx_key = &hse_ctx->key;

	if (!key || !len)
		return TEE_ERROR_BAD_PARAMETERS;

	/* If the context was previously initialized, it must be reset
	 * on a subsequent initialization
	 */
	if (hse_ctx->initialized)
		hse_mac_reset(hse_ctx);

	ret = hse_stream_channel_acquire(&hse_ctx->channel,
					 &hse_ctx->stream_id);
	if (ret != TEE_SUCCESS)
		goto out;

	ret = hse_import_mackey(ctx, key, len);
	if (ret != TEE_SUCCESS)
		goto out_release_stream;

	ctx_key->data = malloc(len);
	if (!ctx_key->data) {
		ret = TEE_ERROR_OUT_OF_MEMORY;
		goto out_erase_key;
	}
	ctx_key->length = len;
	memcpy(ctx_key->data, key, len);

	hse_ctx->initialized = true;

	return TEE_SUCCESS;

out_erase_key:
	hse_release_and_erase_key(hse_ctx->key_handle);
out_release_stream:
	hse_stream_channel_release(hse_ctx->stream_id);
out:
	if (ret != TEE_SUCCESS)
		EMSG("HSE MAC Initializaion failed with err 0x%x", ret);

	return ret;
}

static inline uint8_t get_hse_access_mode(bool stream_started, bool is_final_op)
{
	if (!stream_started && !is_final_op)
		return HSE_ACCESS_MODE_START;

	else if (!stream_started && is_final_op)
		return HSE_ACCESS_MODE_ONE_PASS;

	else if (stream_started && !is_final_op)
		return HSE_ACCESS_MODE_UPDATE;

	else
		return HSE_ACCESS_MODE_FINISH;
}

static TEE_Result hse_mac_srv_req(struct hse_mac_ctx *hse_ctx,
				  bool is_final_op,
				  struct drvcrypt_buf *input,
				  struct drvcrypt_buf *digest)
{
	HSE_SRV_INIT(hseSrvDescriptor_t, srv_desc);
	TEE_Result ret;
	hseAccessMode_t mode;
	struct hse_buf in_buf = {0}, out_buf = {0}, len_buf = {0};

	if (!hse_ctx)
		return TEE_ERROR_BAD_PARAMETERS;

	if (is_final_op && (!digest || !digest->length || !digest->data))
		return TEE_ERROR_BAD_PARAMETERS;

	mode = get_hse_access_mode(hse_ctx->stream_started, is_final_op);
	if (mode == HSE_ACCESS_MODE_START)
		hse_ctx->stream_started = true;

	if (input->length) {
		ret = hse_buf_alloc(&in_buf, input->length);
		if (ret != TEE_SUCCESS)
			goto out;
		memcpy(in_buf.data, input->data, input->length);
		cache_operation(TEE_CACHEFLUSH, in_buf.data, in_buf.size);
	}

	srv_desc.srvId = HSE_SRV_ID_MAC;
	srv_desc.hseSrv.macReq.accessMode = mode;
	srv_desc.hseSrv.macReq.streamId = hse_ctx->stream_id;
	srv_desc.hseSrv.macReq.authDir = HSE_AUTH_DIR_GENERATE;
	srv_desc.hseSrv.macReq.sgtOption = HSE_SGT_OPTION_NONE;
	srv_desc.hseSrv.macReq.macScheme = hse_ctx->mac_tpl->mac_scheme;
	srv_desc.hseSrv.macReq.keyHandle = hse_ctx->key_handle;
	srv_desc.hseSrv.macReq.inputLength = in_buf.size;
	srv_desc.hseSrv.macReq.pInput = in_buf.paddr;

	if (is_final_op) {
		ret = hse_buf_alloc(&out_buf, digest->length);
		if (ret != TEE_SUCCESS)
			goto out_free_input;
		cache_operation(TEE_CACHEINVALIDATE, out_buf.data,
				out_buf.size);

		ret = hse_buf_alloc(&len_buf, sizeof(uint32_t));
		if (ret != TEE_SUCCESS)
			goto out_free_output;
		memcpy(len_buf.data, &digest->length, len_buf.size);
		cache_operation(TEE_CACHEFLUSH, len_buf.data, len_buf.size);

		srv_desc.hseSrv.macReq.pTagLength = len_buf.paddr;
		srv_desc.hseSrv.macReq.pTag = out_buf.paddr;
	}

	ret = hse_srv_req_sync(hse_ctx->channel, &srv_desc);
	if (ret != TEE_SUCCESS) {
		EMSG("Service request for MAC opeartion 0x%x failed: 0x%x",
		     mode, ret);
		goto out_free_len;
	}

	if (is_final_op) {
		memcpy(&digest->length, len_buf.data, len_buf.size);
		memcpy(digest->data, out_buf.data, digest->length);
	}

out_free_len:
	hse_buf_free(&len_buf);
out_free_output:
	hse_buf_free(&out_buf);
out_free_input:
	hse_buf_free(&in_buf);
out:
	return ret;
}

static TEE_Result hse_mac_update(struct crypto_mac_ctx *ctx,
				 const uint8_t *data,
				 size_t len)
{
	TEE_Result ret = TEE_SUCCESS;
	struct hse_mac_ctx *hse_ctx = to_hse_mac_ctx(ctx);
	struct drvcrypt_buf *cached_blks = &hse_ctx->cached_blks;
	struct drvcrypt_buf *left_bytes = &hse_ctx->left_bytes;
	size_t alg_blocksize = hse_ctx->mac_tpl->blocksize;
	size_t total_len, rem, blocks_len;

	if (!data || !len)
		return TEE_ERROR_BAD_PARAMETERS;

	/* Check if there's data available to be processed by HSE from a
	 * previous update
	 */
	if (cached_blks->length) {
		ret = hse_mac_srv_req(hse_ctx, false, cached_blks, NULL);

		drvcrypt_buf_free(cached_blks);

		if (ret != TEE_SUCCESS)
			goto out;
	}

	if (ADD_OVERFLOW(left_bytes->length, len, &total_len))
		return TEE_ERROR_OVERFLOW;

	if (total_len < alg_blocksize) {
		memcpy(left_bytes->data + left_bytes->length, data, len);
		left_bytes->length += len;
		return TEE_SUCCESS;
	}

	rem = total_len % alg_blocksize;
	blocks_len = total_len - rem;

	/* Check if the length would fit in an uint32_t and would not result in
	 * lost data when assigning the value to
	 * srv_desc.hseSrv.macReq.inputLength (uint32_t)
	 */
	if (blocks_len > UINT32_MAX)
		return TEE_ERROR_BAD_PARAMETERS;

	if (cached_blks->data || cached_blks->length)
		return TEE_ERROR_BAD_STATE;

	cached_blks->data = malloc(blocks_len);
	if (!cached_blks->data) {
		ret = TEE_ERROR_OUT_OF_MEMORY;
		goto out;
	}
	cached_blks->length = blocks_len;

	memcpy(cached_blks->data, left_bytes->data, left_bytes->length);
	memcpy(cached_blks->data + left_bytes->length, data,
	       blocks_len - left_bytes->length);

	memcpy(left_bytes->data, data + blocks_len - left_bytes->length, rem);
	left_bytes->length = rem;

out:
	if (ret != TEE_SUCCESS)
		EMSG("HSE Mac Update failed with err 0x%x", ret);
	return ret;
}

static TEE_Result hse_mac_final(struct crypto_mac_ctx *ctx, uint8_t *digest,
				size_t len)
{
	TEE_Result ret;
	struct hse_mac_ctx *hse_ctx = to_hse_mac_ctx(ctx);
	struct drvcrypt_buf final_bytes;
	struct drvcrypt_buf *cached_blks = &hse_ctx->cached_blks;
	struct drvcrypt_buf *left_bytes = &hse_ctx->left_bytes;
	size_t total_len;
	struct drvcrypt_buf digest_buf = {
		.data = digest,
		.length = len,
	};

	if (!digest || !len)
		return TEE_ERROR_BAD_PARAMETERS;

	if (len < hse_ctx->mac_tpl->tagsize)
		return TEE_ERROR_BAD_PARAMETERS;

	if (ADD_OVERFLOW(cached_blks->length, left_bytes->length, &total_len))
		return TEE_ERROR_OVERFLOW;

	final_bytes.data = malloc(total_len);
	if (!final_bytes.data)
		return TEE_ERROR_OUT_OF_MEMORY;
	final_bytes.length = total_len;

	memcpy(final_bytes.data, cached_blks->data, cached_blks->length);
	memcpy(final_bytes.data + cached_blks->length, left_bytes->data,
	       left_bytes->length);

	ret = hse_mac_srv_req(hse_ctx, true, &final_bytes, &digest_buf);
	if (ret != TEE_SUCCESS)
		EMSG("HSE MAC Final failed with err 0x%x", ret);

	free(final_bytes.data);

	return ret;
}

static void hse_mac_copy_state(struct crypto_mac_ctx *dst_ctx,
			       struct crypto_mac_ctx *src_ctx)
{
	TEE_Result ret;
	struct hse_mac_ctx *hse_src_ctx = to_hse_mac_ctx(src_ctx);
	struct hse_mac_ctx *hse_dst_ctx = to_hse_mac_ctx(dst_ctx);
	struct drvcrypt_buf *src_key = &hse_src_ctx->key;
	struct drvcrypt_buf *src_cached_blks = &hse_src_ctx->cached_blks,
		*dst_cached_blks = &hse_dst_ctx->cached_blks;
	struct drvcrypt_buf *src_left_bytes = &hse_src_ctx->left_bytes,
		*dst_left_bytes = &hse_dst_ctx->left_bytes;

	if (!hse_src_ctx->initialized)
		return;

	ret = hse_mac_init(dst_ctx, src_key->data, src_key->length);
	if (ret != TEE_SUCCESS)
		goto out;

	if (hse_src_ctx->stream_started) {
		ret = hse_stream_ctx_copy(hse_src_ctx->stream_id,
					  hse_dst_ctx->stream_id);
		if (ret != TEE_SUCCESS)
			goto out;

		hse_dst_ctx->stream_started = true;
	}

	if (src_cached_blks->length) {
		dst_cached_blks->data = malloc(src_cached_blks->length);
		if (!dst_cached_blks->data) {
			ret = TEE_ERROR_OUT_OF_MEMORY;
			goto out;
		}
	}

	memcpy(dst_cached_blks->data, src_cached_blks->data,
	       src_cached_blks->length);
	dst_cached_blks->length = src_cached_blks->length;

	memcpy(dst_left_bytes->data, src_left_bytes->data,
	       src_left_bytes->length);
	dst_left_bytes->length = src_left_bytes->length;

out:
	if (ret != TEE_SUCCESS)
		EMSG("HSE MAC Copy Operation failed with err 0x%x", ret);
}

static const struct crypto_mac_ops hse_mac_ops = {
	.init = hse_mac_init,
	.update = hse_mac_update,
	.final = hse_mac_final,
	.free_ctx = hse_mac_free,
	.copy_state = hse_mac_copy_state,
};

TEE_Result hse_mac_register(void)
{
	TEE_Result ret;

	ret = drvcrypt_register_cmac(&hse_mac_alloc);
	if (ret != TEE_SUCCESS)
		return ret;

	ret = drvcrypt_register_hmac(&hse_mac_alloc);

	return ret;
}
