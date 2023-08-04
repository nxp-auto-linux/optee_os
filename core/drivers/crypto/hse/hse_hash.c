// SPDX-License-Identifier: BSD-3-Clause
/*
 * Copyright 2023 NXP
 */

#include <drvcrypt.h>
#include <drvcrypt_hash.h>
#include <hse_core.h>
#include <hse_interface.h>
#include <hse_services.h>
#include <tee/cache.h>
#include <string.h>
#include <utee_defines.h>
#include <malloc.h>

#define HASH_MAX_BLK_SIZE 128
#define MAX_INPUT_BUF_SIZE (HASH_MAX_BLK_SIZE * 20)

struct hse_hash_tpl {
	char hash_name[128];
	hseHashAlgo_t algo_type;
};

struct hse_hash_context {
	struct crypto_hash_ctx hash_ctx;
	const struct hse_hash_tpl *algo;
	uint8_t *cached_block;
	size_t cached_size;
	bool init;
	uint8_t stream_id;
	uint8_t channel;
};

static const struct hse_hash_tpl hse_hash_algs[] = {
#ifdef HSE_HASH_ALGO_MD5
	[TEE_MAIN_ALGO_MD5] = {
		.hash_name = "MD5",
		.algo_type = HSE_HASH_ALGO_MD5,
	},
#endif
	[TEE_MAIN_ALGO_SHA1] = {
		.hash_name = "SHA1",
		.algo_type = HSE_HASH_ALGO_SHA_1,
	},
	[TEE_MAIN_ALGO_SHA224] = {
		.hash_name = "SHA2-224",
		.algo_type = HSE_HASH_ALGO_SHA2_224,
	},
	[TEE_MAIN_ALGO_SHA256] = {
		.hash_name = "SHA2-256",
		.algo_type = HSE_HASH_ALGO_SHA2_256,
	},
	[TEE_MAIN_ALGO_SHA384] = {
		.hash_name = "SHA2-384",
		.algo_type = HSE_HASH_ALGO_SHA2_384,
	},
	[TEE_MAIN_ALGO_SHA512] = {
		.hash_name = "SHA2-512",
		.algo_type = HSE_HASH_ALGO_SHA2_512,
	}
};

static const struct hse_hash_tpl *get_algo(uint32_t algo)
{
	uint32_t alg;

	alg = TEE_ALG_GET_MAIN_ALG(algo);
#ifdef HSE_HASH_ALGO_MD5
	if (alg >= TEE_MAIN_ALGO_MD5 && alg <= TEE_MAIN_ALGO_SHA512)
		return &hse_hash_algs[alg];
#else
	if (alg >= TEE_MAIN_ALGO_SHA1 && alg <= TEE_MAIN_ALGO_SHA512)
		return &hse_hash_algs[alg];
#endif
	return NULL;
}

static void hse_free_stream(struct hse_hash_context *hse_ctx)
{
	hse_stream_channel_release(hse_ctx->stream_id);
	hse_ctx->stream_id = HSE_STREAM_COUNT;
	hse_ctx->channel = 0;
}

static void hse_hash_reset(struct hse_hash_context *hse_ctx)
{
	hse_free_stream(hse_ctx);
	hse_ctx->cached_size = 0;
	hse_ctx->init = false;
	if (hse_ctx->cached_block)
		free(hse_ctx->cached_block);
}

static TEE_Result hse_start_stream(struct hse_hash_context *hse_ctx)
{
	TEE_Result res;

	HSE_SRV_INIT(hseSrvDescriptor_t, srv_desc);

	srv_desc.srvId = HSE_SRV_ID_HASH;
	srv_desc.hseSrv.hashReq.hashAlgo = hse_ctx->algo->algo_type;
	srv_desc.hseSrv.hashReq.accessMode = HSE_ACCESS_MODE_START;
	srv_desc.hseSrv.hashReq.sgtOption = HSE_SGT_OPTION_NONE;
	srv_desc.hseSrv.hashReq.streamId = hse_ctx->stream_id;
	srv_desc.hseSrv.hashReq.inputLength = 0;

	res = hse_srv_req_sync(hse_ctx->channel, &srv_desc);
	if (res != TEE_SUCCESS)
		EMSG("Stream start operation failed with error code0x%x", res);

	hse_ctx->init = true;
	return res;
}

static TEE_Result hse_hash_init(struct crypto_hash_ctx *ctx)
{
	struct hse_hash_context *hse_ctx;
	TEE_Result res;

	hse_ctx = container_of(ctx, struct hse_hash_context, hash_ctx);

	hse_hash_reset(hse_ctx);

	hse_ctx->cached_block = calloc(MAX_INPUT_BUF_SIZE,
				       sizeof(uint8_t));
	if (!hse_ctx->cached_block)
		return TEE_ERROR_OUT_OF_MEMORY;

	res = hse_stream_channel_acquire(&hse_ctx->channel,
					 &hse_ctx->stream_id);
	if (res != TEE_SUCCESS)
		return res;

	return hse_start_stream(hse_ctx);
}

static TEE_Result update_operation(struct hse_hash_context *hse_ctx,
				   struct hse_buf *in_buf)
{
	TEE_Result res;

	HSE_SRV_INIT(hseSrvDescriptor_t, srv_desc);

	srv_desc.srvId = HSE_SRV_ID_HASH;
	srv_desc.hseSrv.hashReq.hashAlgo = hse_ctx->algo->algo_type;
	srv_desc.hseSrv.hashReq.accessMode = HSE_ACCESS_MODE_UPDATE;

	if (in_buf->size > UINT32_MAX)
		return TEE_ERROR_OVERFLOW;

	srv_desc.hseSrv.hashReq.inputLength = in_buf->size;
	srv_desc.hseSrv.hashReq.streamId = hse_ctx->stream_id;
	srv_desc.hseSrv.hashReq.pInput = in_buf->paddr;
	srv_desc.hseSrv.hashReq.sgtOption = HSE_SGT_OPTION_NONE;
	cache_operation(TEE_CACHEFLUSH, in_buf->data, in_buf->size);

	res = hse_srv_req_sync(hse_ctx->channel, &srv_desc);
	if (res != TEE_SUCCESS)
		EMSG("Hash update operation failed with error code0x%x", res);

	return res;
}

static TEE_Result hse_hash_update(struct crypto_hash_ctx *ctx,
				  const uint8_t *data, size_t len)
{
	TEE_Result res;
	struct hse_hash_context *hse_ctx;
	struct hse_buf in_buf = {0};
	size_t rem, idx = 0, actual_len = 0;

	hse_ctx = container_of(ctx, struct hse_hash_context, hash_ctx);
	if (!data || !len)
		return TEE_ERROR_BAD_PARAMETERS;

	if (ADD_OVERFLOW(len, hse_ctx->cached_size, &actual_len))
		return TEE_ERROR_OVERFLOW;

	if (actual_len < MAX_INPUT_BUF_SIZE) {
		memcpy(hse_ctx->cached_block + hse_ctx->cached_size, data, len);
		hse_ctx->cached_size += len;
		return TEE_SUCCESS;
	}

	res = hse_buf_alloc(&in_buf, MAX_INPUT_BUF_SIZE);
	if (res != TEE_SUCCESS)
		goto out;
	memcpy(in_buf.data, hse_ctx->cached_block, hse_ctx->cached_size);
	memcpy(in_buf.data + hse_ctx->cached_size, data,
	       MAX_INPUT_BUF_SIZE - hse_ctx->cached_size);
	res = update_operation(hse_ctx, &in_buf);

	if (res != TEE_SUCCESS)
		goto out_free_buf;

	idx = MAX_INPUT_BUF_SIZE - hse_ctx->cached_size;
	while (len - idx > MAX_INPUT_BUF_SIZE) {
		memcpy(in_buf.data, data + idx, MAX_INPUT_BUF_SIZE);
		res = update_operation(hse_ctx, &in_buf);

		if (res != TEE_SUCCESS)
			goto out_free_buf;

		if (ADD_OVERFLOW(idx, MAX_INPUT_BUF_SIZE, &idx)) {
			res = TEE_ERROR_OVERFLOW;
			goto out_free_buf;
		}
	}

	if (SUB_OVERFLOW(len, idx, &rem)) {
		res = TEE_ERROR_OVERFLOW;
		goto out_free_buf;
	}
	memcpy(hse_ctx->cached_block, data + idx, rem);
	hse_ctx->cached_size = rem;
	res = TEE_SUCCESS;

out_free_buf:
	hse_buf_free(&in_buf);
out:
	return res;
}

static TEE_Result hse_hash_final(struct crypto_hash_ctx *ctx,
				 uint8_t *digest, size_t len)
{
	struct hse_hash_context *hse_ctx;
	TEE_Result res;
	struct hse_buf in_buf = {0}, len_buf = {0}, out_buf = {0};

	HSE_SRV_INIT(hseSrvDescriptor_t, srv_desc);

	hse_ctx = container_of(ctx, struct hse_hash_context, hash_ctx);

	if (!len || !digest)
		return TEE_ERROR_BAD_PARAMETERS;

	if (hse_ctx->cached_size) {
		res = hse_buf_alloc(&in_buf, hse_ctx->cached_size);
		if (res != TEE_SUCCESS)
			goto out;
		memcpy(in_buf.data, hse_ctx->cached_block,
		       hse_ctx->cached_size);
		cache_operation(TEE_CACHEFLUSH, in_buf.data,
				hse_ctx->cached_size);
	}

	res = hse_buf_alloc(&len_buf, sizeof(size_t));
	if (res != TEE_SUCCESS)
		goto out_free_in_buf;
	memcpy(len_buf.data, &len, sizeof(size_t));
	cache_operation(TEE_CACHEFLUSH, len_buf.data, len_buf.size);

	res = hse_buf_alloc(&out_buf, len);
	if (res != TEE_SUCCESS)
		goto out_free_len_buf;
	cache_operation(TEE_CACHEINVALIDATE, out_buf.data, out_buf.size);

	srv_desc.srvId = HSE_SRV_ID_HASH;
	srv_desc.hseSrv.hashReq.accessMode = HSE_ACCESS_MODE_FINISH;
	srv_desc.hseSrv.hashReq.sgtOption = HSE_SGT_OPTION_NONE;
	srv_desc.hseSrv.hashReq.streamId = hse_ctx->stream_id;
	srv_desc.hseSrv.hashReq.hashAlgo = hse_ctx->algo->algo_type;
	srv_desc.hseSrv.hashReq.inputLength = hse_ctx->cached_size;
	srv_desc.hseSrv.hashReq.pInput = in_buf.paddr;
	srv_desc.hseSrv.hashReq.pHashLength = len_buf.paddr;
	srv_desc.hseSrv.hashReq.pHash = out_buf.paddr;

	res = hse_srv_req_sync(hse_ctx->channel, &srv_desc);
	if (res != TEE_SUCCESS) {
		EMSG("hse_srv_req_sync failed with err 0x%x", res);
		goto out_free_out_buf;
	}
	memcpy(digest, out_buf.data, len);
out_free_out_buf:
	hse_buf_free(&out_buf);
out_free_len_buf:
	hse_buf_free(&len_buf);
out_free_in_buf:
	hse_buf_free(&in_buf);
out:
	return res;
}

static void hse_hash_free_ctx(struct crypto_hash_ctx *ctx)
{
	struct hse_hash_context *hse_ctx = NULL;

	hse_ctx = container_of(ctx, struct hse_hash_context, hash_ctx);

	hse_free_stream(hse_ctx);
	free(hse_ctx->cached_block);
	free(hse_ctx);
}

static void hse_hash_copy_state(struct crypto_hash_ctx *dst_ctx,
				struct crypto_hash_ctx *src_ctx)
{
	TEE_Result res = TEE_SUCCESS;
	struct hse_hash_context *dst_hse_ctx;
	struct hse_hash_context *src_hse_ctx;

	if (!src_ctx || !dst_ctx)
		return;

	src_hse_ctx = container_of(src_ctx, struct hse_hash_context, hash_ctx);
	dst_hse_ctx = container_of(dst_ctx, struct hse_hash_context, hash_ctx);
	if (src_hse_ctx->init) {
		res = hse_stream_ctx_copy(src_hse_ctx->stream_id,
					  dst_hse_ctx->stream_id);
		if (res != TEE_SUCCESS)
			goto out;
	}
	dst_hse_ctx->cached_size = src_hse_ctx->cached_size;
	memcpy(dst_hse_ctx->cached_block,
	       src_hse_ctx->cached_block, src_hse_ctx->cached_size);
	dst_hse_ctx->init = src_hse_ctx->init;

out:
	if (res != TEE_SUCCESS)
		EMSG("Hash copy state failed with err 0x%x", res);
}

static const struct crypto_hash_ops driver_hash = {
	.init = hse_hash_init,
	.update = hse_hash_update,
	.final = hse_hash_final,
	.free_ctx = hse_hash_free_ctx,
	.copy_state = hse_hash_copy_state,
};

static TEE_Result hse_hash_alloc_ctx(struct crypto_hash_ctx **ctx,
				     uint32_t algo)
{
	struct hse_hash_context *hse_ctx;
	const struct hse_hash_tpl *alg_tpl;
	TEE_Result res = TEE_SUCCESS;

	*ctx = NULL;
	hse_ctx = calloc(1, sizeof(*hse_ctx));
	if (!hse_ctx) {
		res = TEE_ERROR_OUT_OF_MEMORY;
		goto out_err;
	}

	alg_tpl = get_algo(algo);
	if (!alg_tpl) {
		res = TEE_ERROR_NOT_IMPLEMENTED;
		goto out_free_ctx;
	}

	hse_ctx->algo = alg_tpl;
	hse_ctx->hash_ctx.ops = &driver_hash;
	hse_ctx->stream_id = HSE_STREAM_COUNT;
	*ctx = &hse_ctx->hash_ctx;
	DMSG("Allocated context for algo %s", hse_ctx->algo->hash_name);
	return TEE_SUCCESS;

out_free_ctx:
	free(hse_ctx);
out_err:
	EMSG("Hash initialisation failed with error 0x%x", res);
	return res;
}

TEE_Result hse_hash_register(void)
{
	return drvcrypt_register_hash(&hse_hash_alloc_ctx);
}
