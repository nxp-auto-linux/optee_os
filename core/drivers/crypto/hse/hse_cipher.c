// SPDX-License-Identifier: BSD-3-Clause
/*
 * Copyright 2022-2023 NXP
 */

#include <drvcrypt.h>
#include <drvcrypt_cipher.h>
#include <hse_core.h>
#include <hse_interface.h>
#include <hse_services.h>
#include <mm/core_memprot.h>
#include <string.h>
#include <tee/cache.h>
#include <utee_defines.h>
#include <malloc.h>

enum aes_key_size {
	AES_KEY_SIZE_128 = 16,
	AES_KEY_SIZE_192 = 24,
	AES_KEY_SIZE_256 = 32,
};

/**
 * struct hse_cipher_tpl - algorithm template
 * @cipher_name: cipher algorithm name
 * @blocksize: block size
 * @ivsize: initialization vector size
 * @cipher_type: cipher algorithm/type
 * @block_mode: cipher block mode
 * @key_type: type of key used
 */
struct hse_cipher_tpl {
	char cipher_name[128];
	unsigned int blocksize;
	unsigned int ivsize;
	hseCipherAlgo_t cipher_type;
	hseCipherBlockMode_t block_mode;
	hseKeyType_t key_type;
};

/**
 * struct hse_cipher_ctx - container for all the other contexts
 * @alg_tpl: algorithm template pointer
 * @initialized: the operation has been initialized
 * @iv: initialization vector buffer
 * @key_handle: key handle in the AES Key Group
 * @direction: encrypt or decrypt direction
 */
struct hse_cipher_ctx {
	const struct hse_cipher_tpl *alg_tpl;
	bool initialized;
	uint8_t iv[TEE_AES_BLOCK_SIZE];
	uint8_t key[AES_KEY_SIZE_256];
	size_t key_len;
	hseKeyHandle_t key_handle;
	hseCipherDir_t direction;
	uint8_t prev_data[TEE_AES_BLOCK_SIZE];
	size_t prev_size;
};

/* Constant array of templates for cipher algorithms */
static const struct hse_cipher_tpl hse_cipher_algs_tpl[] = {
	[TEE_CHAIN_MODE_ECB_NOPAD] = {
		.cipher_name = "ecb(aes)",
		.blocksize = TEE_AES_BLOCK_SIZE,
		.ivsize = 0u,
		.cipher_type = HSE_CIPHER_ALGO_AES,
		.block_mode = HSE_CIPHER_BLOCK_MODE_ECB,
		.key_type = HSE_KEY_TYPE_AES,
	},
	[TEE_CHAIN_MODE_CBC_NOPAD] = {
		.cipher_name = "cbc(aes)",
		.blocksize =  TEE_AES_BLOCK_SIZE,
		.ivsize = TEE_AES_BLOCK_SIZE,
		.cipher_type = HSE_CIPHER_ALGO_AES,
		.block_mode = HSE_CIPHER_BLOCK_MODE_CBC,
		.key_type = HSE_KEY_TYPE_AES,
	},
	[TEE_CHAIN_MODE_CTR] = {
		.cipher_name = "ctr(aes)",
		.blocksize =  TEE_AES_BLOCK_SIZE,
		.ivsize = TEE_AES_BLOCK_SIZE,
		.cipher_type = HSE_CIPHER_ALGO_AES,
		.block_mode = HSE_CIPHER_BLOCK_MODE_CTR,
		.key_type = HSE_KEY_TYPE_AES,
	},
};

/**
 * aes_check_key_size - checks if the key_size parameter
 *			has a supported size for AES
 *
 * @key_size: cipher key size
 */
static inline TEE_Result aes_check_key_size(size_t key_size)
{
	switch (key_size) {
	case AES_KEY_SIZE_128:
	case AES_KEY_SIZE_192:
	case AES_KEY_SIZE_256:
		return TEE_SUCCESS;
	default:
		return TEE_ERROR_BAD_PARAMETERS;
	}
}

/**
 * get_cipheralgo - matches the algo parameter with a template entry
 * @algo: algorithm ID
 *
 * Checks if the algorithm @algo is supported and returns the
 * local algorithm entry in the corresponding template array
 */
static const struct hse_cipher_tpl *get_cipheralgo(uint32_t algo)
{
	unsigned int algo_id = TEE_ALG_GET_MAIN_ALG(algo);
	unsigned int algo_md = TEE_ALG_GET_CHAIN_MODE(algo);

	if (algo_id == TEE_MAIN_ALGO_AES &&
	    algo_md < ARRAY_SIZE(hse_cipher_algs_tpl))
		return &hse_cipher_algs_tpl[algo_md];

	return NULL;
}

static TEE_Result hse_import_symkey(struct drvcrypt_buf key,
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

static void hse_cipher_reset(struct hse_cipher_ctx *ctx)
{
	if (!ctx || !ctx->initialized)
		return;

	hse_release_and_erase_key(ctx->key_handle);
	ctx->key_handle = HSE_INVALID_KEY_HANDLE;
	ctx->prev_size = 0;
	ctx->initialized = false;
}

/**
 * hse_cipher_free_ctx - free all allocated objects of
 *			 the current context
 * @ctx: cipher context
 *
 */
static void hse_cipher_free_ctx(void *ctx)
{
	struct hse_cipher_ctx *hse_ctx = ctx;

	if (!hse_ctx)
		return;

	hse_release_and_erase_key(hse_ctx->key_handle);

	free(hse_ctx);
}

/**
 * hse_cipher_alloc_ctx - allocates objects for the current
 *			  cipher context
 * @ctx: pointer to the context, returned to the caller
 * @algo: algorithm ID
 *
 * Return: TEE_SUCCESS on success, error code on error
 */
static TEE_Result hse_cipher_alloc_ctx(void **ctx, uint32_t algo)
{
	TEE_Result ret = TEE_SUCCESS;
	struct hse_cipher_ctx *hse_ctx;
	const struct hse_cipher_tpl *alg_tpl;

	hse_ctx = calloc(1, sizeof(*hse_ctx));
	if (!hse_ctx) {
		ret = TEE_ERROR_OUT_OF_MEMORY;
		goto out_err;
	}

	alg_tpl = get_cipheralgo(algo);
	if (!alg_tpl) {
		DMSG("HSE does not implement alg type 0x%x", algo);
		ret = TEE_ERROR_NOT_IMPLEMENTED;
		goto out_free_ctx;
	}
	hse_ctx->alg_tpl = alg_tpl;

	hse_ctx->key_handle = HSE_INVALID_KEY_HANDLE;

	*ctx = hse_ctx;

	DMSG("Allocated context for algo %s", alg_tpl->cipher_name);
	return ret;

out_free_ctx:
	free(hse_ctx);
out_err:
	DMSG("Cipher context allocation failed with err: 0x%x", ret);
	return ret;
}

/**
 * hse_cipher_init - imports the key into HSE and initializes the IV
 *
 * @dinit: variable containing key and IV data
 *
 * Return: TEE_SUCCESS on success, error code on error
 */
static TEE_Result hse_cipher_init(struct drvcrypt_cipher_init *dinit)
{
	TEE_Result ret = TEE_SUCCESS;
	struct hse_cipher_ctx *ctx = dinit->ctx;
	const struct hse_cipher_tpl *alg = ctx->alg_tpl;
	hseKeyHandle_t *key_handle = &ctx->key_handle;

	if (ctx->initialized)
		hse_cipher_reset(ctx);

	if (!dinit->key1.data || !dinit->key1.length) {
		ret = TEE_ERROR_BAD_PARAMETERS;
		goto out;
	}

	ret = aes_check_key_size(dinit->key1.length);
	if (ret != TEE_SUCCESS)
		goto out;

	ctx->key_len = dinit->key1.length;
	memcpy(ctx->key, dinit->key1.data, dinit->key1.length);

	ctx->direction = dinit->encrypt ? HSE_CIPHER_DIR_ENCRYPT :
					  HSE_CIPHER_DIR_DECRYPT;

	ret = hse_import_symkey(dinit->key1, alg->key_type, ctx->direction,
				key_handle);
	if (ret != TEE_SUCCESS)
		goto out;

	if (dinit->iv.data && dinit->iv.length == alg->ivsize)
		memcpy(ctx->iv, dinit->iv.data, dinit->iv.length);

	ctx->initialized = true;

out:
	if (ret != TEE_SUCCESS) {
		DMSG("Cipher initialization failed with err 0x%x", ret);
		hse_cipher_free_ctx(ctx);
	}

	return ret;
}

/**
 * hse_cipher_update - performs an encrypt/decrypt transformation
 *		       on the given data
 *
 * @dupdate: variable containing source data and destination buffer
 *
 * Return: TEE_SUCCESS on success, error code on error
 */
static TEE_Result hse_cipher_update(struct drvcrypt_cipher_update *dupdate)
{
	TEE_Result ret = TEE_SUCCESS;
	struct hse_cipher_ctx *ctx = dupdate->ctx;
	const struct hse_cipher_tpl *alg = ctx->alg_tpl;
	struct hse_buf *buf = NULL, *iv_buf = NULL;
	size_t src_len, dst_len = dupdate->dst.length,
	       blocksize = alg->blocksize, blks;
	size_t prev_size = ctx->prev_size, rem_size;
	uint8_t *src_data, *dst_data = dupdate->dst.data, *last_block,
		*prev_data = ctx->prev_data;
	HSE_SRV_INIT(hseSrvDescriptor_t, srv_desc);

	switch (alg->block_mode) {
	case HSE_CIPHER_BLOCK_MODE_ECB:
	case HSE_CIPHER_BLOCK_MODE_CBC:
		if (dupdate->src.length < blocksize ||
		    dupdate->src.length % blocksize ||
		    dupdate->src.length > UINT32_MAX ||
		    prev_size != 0) {
			ret = TEE_ERROR_BAD_PARAMETERS;
			goto out;
		}

		break;

	case HSE_CIPHER_BLOCK_MODE_CTR:
		if (prev_size >= blocksize ||
		    dupdate->src.length + prev_size > UINT32_MAX) {
			ret = TEE_ERROR_BAD_PARAMETERS;
			goto out;
		}

		break;

	default:
		goto out;
	}

	/* For NOPAD modes prev_size will always be 0 */
	src_len = dupdate->src.length + prev_size;

	src_data = malloc(src_len);
	if (!src_data) {
		ret = TEE_ERROR_OUT_OF_MEMORY;
		goto out;
	}

	memcpy(src_data, prev_data, prev_size);
	memcpy(src_data + prev_size, dupdate->src.data, dupdate->src.length);

	buf = hse_buf_init(src_data, src_len);
	if (!buf) {
		ret = TEE_ERROR_OUT_OF_MEMORY;
		goto out_free_src;
	}

	if (ctx->alg_tpl->ivsize) {
		iv_buf = hse_buf_init(ctx->iv, ctx->alg_tpl->ivsize);
		if (!iv_buf) {
			ret = TEE_ERROR_OUT_OF_MEMORY;
			goto out_free_buf;
		}
	}

	srv_desc.srvId = HSE_SRV_ID_SYM_CIPHER;
	srv_desc.hseSrv.symCipherReq.accessMode = HSE_ACCESS_MODE_ONE_PASS;
	srv_desc.hseSrv.symCipherReq.cipherAlgo = alg->cipher_type;
	srv_desc.hseSrv.symCipherReq.cipherBlockMode = alg->block_mode;
	srv_desc.hseSrv.symCipherReq.cipherDir = ctx->direction;
	srv_desc.hseSrv.symCipherReq.keyHandle = ctx->key_handle;
	srv_desc.hseSrv.symCipherReq.pIV = hse_buf_get_paddr(iv_buf);
	srv_desc.hseSrv.symCipherReq.sgtOption = HSE_SGT_OPTION_NONE;
	srv_desc.hseSrv.symCipherReq.inputLength = hse_buf_get_size(buf);
	srv_desc.hseSrv.symCipherReq.pInput = hse_buf_get_paddr(buf);
	srv_desc.hseSrv.symCipherReq.pOutput = hse_buf_get_paddr(buf);

	ret = hse_srv_req_sync(HSE_CHANNEL_ANY, &srv_desc);
	if (ret != TEE_SUCCESS) {
		DMSG("HSE Cipher Request failed");
		goto out_free_buf;
	}

	hse_buf_get_data(buf, dst_data, dst_len, prev_size);

	switch (alg->block_mode) {
	case HSE_CIPHER_BLOCK_MODE_CBC:
		if (ctx->direction == HSE_CIPHER_DIR_ENCRYPT)
			last_block = dst_data  + dst_len - alg->ivsize;
		else
			last_block = src_data + src_len - alg->ivsize;

		memcpy(ctx->iv, last_block, alg->ivsize);
		break;

	case HSE_CIPHER_BLOCK_MODE_CTR:
		blks = src_len / blocksize;
		rem_size = src_len % blocksize;

		hse_ctr_inc(ctx->iv, blks, blocksize);

		memcpy(prev_data, src_data + blks, rem_size);
		ctx->prev_size = rem_size;

		break;

	default:
		break;
	}

out_free_buf:
	hse_buf_free(buf);
	hse_buf_free(iv_buf);

out_free_src:
	free(src_data);

out:
	if (ret != TEE_SUCCESS) {
		DMSG("Cipher update operation failed with err: 0x%x", ret);
		hse_cipher_free_ctx(ctx);
	}

	return ret;
}

static void hse_cipher_final(void *ctx __unused)
{
}

static void hse_cipher_copy_state(void *dst_ctx, void *src_ctx)
{
	TEE_Result ret;
	struct hse_cipher_ctx *src, *dst;
	const struct hse_cipher_tpl *alg;
	struct drvcrypt_buf key;

	if (!src_ctx || !dst_ctx)
		return;

	src = src_ctx;
	dst = dst_ctx;
	alg = src->alg_tpl;

	if (!src->initialized)
		return;

	dst->direction = src->direction;

	key.data = src->key;
	key.length = src->key_len;

	ret = hse_import_symkey(key, alg->key_type, dst->direction,
				&dst->key_handle);
	if (ret != TEE_SUCCESS)
		return;

	memcpy(dst->key, src->key, src->key_len);
	dst->key_len = src->key_len;

	memcpy(dst->prev_data, src->prev_data, src->prev_size);
	dst->prev_size = src->prev_size;

	if (!alg->ivsize)
		return;

	memcpy(dst->iv, src->iv, alg->ivsize);
}

static struct drvcrypt_cipher driver_cipher = {
	.alloc_ctx = hse_cipher_alloc_ctx,
	.free_ctx = hse_cipher_free_ctx,
	.init = hse_cipher_init,
	.update = hse_cipher_update,
	.final = hse_cipher_final,
	.copy_state = hse_cipher_copy_state,
};

TEE_Result hse_cipher_register(void)
{
	return drvcrypt_register_cipher(&driver_cipher);
}
