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
 * @iv: initialization vector buffer
 * @key_handle: key handle in the AES Key Group
 * @direction: encrypt or decrypt direction
 */
struct hse_cipher_ctx {
	const struct hse_cipher_tpl *alg_tpl;
	struct hse_buf iv;
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

static TEE_Result hse_import_key(struct drvcrypt_buf key, hseKeyType_t key_type,
				 hseKeyHandle_t key_handle)
{
	TEE_Result ret = TEE_SUCCESS;
	struct hse_buf keybuf, keyinf;
	hseKeyInfo_t *key_inf_buf;
	HSE_SRV_INIT(hseSrvDescriptor_t, srv_desc);
	HSE_SRV_INIT(hseImportKeySrv_t, import_key_req);

	ret = hse_buf_alloc(&keybuf, key.length);
	if (ret != TEE_SUCCESS)
		goto out;

	memcpy(keybuf.data, key.data, key.length);

	ret = hse_buf_alloc(&keyinf, sizeof(hseKeyInfo_t));
	if (ret != TEE_SUCCESS)
		goto out_free_keybuf;
	memset(keyinf.data, 0, keyinf.size);

	key_inf_buf = (hseKeyInfo_t *)((void *)keyinf.data);
	key_inf_buf->keyFlags = HSE_KF_USAGE_ENCRYPT | HSE_KF_USAGE_DECRYPT;
	key_inf_buf->keyBitLen = keybuf.size * 8;
	key_inf_buf->keyType = key_type;
	key_inf_buf->smrFlags = 0;

	srv_desc.srvId = HSE_SRV_ID_IMPORT_KEY;
	import_key_req.targetKeyHandle = key_handle;
	import_key_req.pKeyInfo = keyinf.paddr;
	import_key_req.pKey[2] = keybuf.paddr;
	import_key_req.keyLen[2] = keybuf.size;
	import_key_req.cipher.cipherKeyHandle = HSE_INVALID_KEY_HANDLE;
	import_key_req.keyContainer.authKeyHandle = HSE_INVALID_KEY_HANDLE;

	srv_desc.hseSrv.importKeyReq = import_key_req;

	cache_operation(TEE_CACHEFLUSH, keybuf.data, keybuf.size);
	cache_operation(TEE_CACHEFLUSH, keyinf.data, keyinf.size);

	ret = hse_srv_req_sync(HSE_CHANNEL_ANY, &srv_desc);

	hse_buf_free(&keyinf);

out_free_keybuf:
	hse_buf_free(&keybuf);
out:
	if (ret != TEE_SUCCESS)
		DMSG("HSE Import Key request failed with err 0x%x", ret);
	return ret;
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

	hse_buf_free(&hse_ctx->iv);
	hse_keyslot_release(hse_ctx->key_handle);

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

	if (alg_tpl->ivsize) {
		ret = hse_buf_alloc(&hse_ctx->iv, alg_tpl->ivsize);
		if (ret != TEE_SUCCESS)
			goto out_free_ctx;
	}

	hse_ctx->key_handle = hse_keyslot_acquire(alg_tpl->key_type);
	if (!hse_ctx->key_handle) {
		ret = TEE_ERROR_BUSY;
		goto out_free_iv;
	}

	*ctx = hse_ctx;

	DMSG("Allocated context for algo %s", alg_tpl->cipher_name);
	return ret;

out_free_iv:
	hse_buf_free(&hse_ctx->iv);
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
	hseKeyHandle_t key_handle = ctx->key_handle;

	if (!dinit->key1.data || !dinit->key1.length) {
		ret = TEE_ERROR_BAD_PARAMETERS;
		goto out;
	}

	ret = aes_check_key_size(dinit->key1.length);
	if (ret != TEE_SUCCESS)
		goto out;

	ctx->key_len = dinit->key1.length;
	memcpy(ctx->key, dinit->key1.data, dinit->key1.length);

	ret = hse_import_key(dinit->key1, alg->key_type, key_handle);
	if (ret != TEE_SUCCESS)
		goto out;

	ctx->direction = dinit->encrypt ? HSE_CIPHER_DIR_ENCRYPT :
					  HSE_CIPHER_DIR_DECRYPT;

	if (dinit->iv.data && dinit->iv.length == alg->ivsize)
		memcpy(ctx->iv.data, dinit->iv.data, dinit->iv.length);

out:
	if (ret != TEE_SUCCESS) {
		DMSG("Cipher initialization failed with err 0x%x", ret);
		hse_cipher_free_ctx(ctx);
	}

	return ret;
}

/**
 * hse_ctr_inc - in counter mode, each time a block is encrypted/decrypted,
 *               the iv is incremented by 1
 * @iv: iv
 * @blks: number of blocks that have been encrypted/decrypted during the
 *        update operation
 * @blocksize: size of the block -- 16 for AES-CTR. The iv has the size
 *             of the block size.
 */
static inline void hse_ctr_inc(uint8_t *iv, size_t blks, size_t blocksize)
{
	for (; blks > 0; blks--)
		for (int64_t i = blocksize - 1; i >= 0; i--) {
			iv[i] = (iv[i] + 1) & 0xff;
			if (iv[i])
				break;
		}
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
	struct hse_buf buf;
	size_t  src_len, blocksize = alg->blocksize, blks;
	size_t prev_size = ctx->prev_size, rem_size;
	uint8_t *src_data, *last_block, *prev_data = ctx->prev_data;
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

	ret = hse_buf_alloc(&buf, src_len);
	if (ret != TEE_SUCCESS)
		goto out_free_src;

	memcpy(buf.data, src_data, buf.size);

	srv_desc.srvId = HSE_SRV_ID_SYM_CIPHER;
	srv_desc.hseSrv.symCipherReq.accessMode = HSE_ACCESS_MODE_ONE_PASS;
	srv_desc.hseSrv.symCipherReq.cipherAlgo = alg->cipher_type;
	srv_desc.hseSrv.symCipherReq.cipherBlockMode = alg->block_mode;
	srv_desc.hseSrv.symCipherReq.cipherDir = ctx->direction;
	srv_desc.hseSrv.symCipherReq.keyHandle = ctx->key_handle;
	srv_desc.hseSrv.symCipherReq.pIV = ctx->iv.paddr;
	srv_desc.hseSrv.symCipherReq.sgtOption = HSE_SGT_OPTION_NONE;
	srv_desc.hseSrv.symCipherReq.inputLength = buf.size;
	srv_desc.hseSrv.symCipherReq.pInput = buf.paddr;
	srv_desc.hseSrv.symCipherReq.pOutput = buf.paddr;

	cache_operation(TEE_CACHEFLUSH, buf.data, buf.size);
	cache_operation(TEE_CACHEFLUSH, ctx->iv.data, alg->ivsize);

	ret = hse_srv_req_sync(HSE_CHANNEL_ANY, &srv_desc);
	if (ret != TEE_SUCCESS) {
		DMSG("HSE Cipher Request failed");
		goto out_free_buf;
	}

	cache_operation(TEE_CACHEINVALIDATE, buf.data, buf.size);
	memcpy(dupdate->dst.data, buf.data + prev_size, dupdate->dst.length);

	switch (alg->block_mode) {
	case HSE_CIPHER_BLOCK_MODE_CBC:
		if (ctx->direction == HSE_CIPHER_DIR_ENCRYPT)
			last_block = buf.data  + buf.size - alg->ivsize;
		else
			last_block = src_data + src_len - alg->ivsize;

		memcpy(ctx->iv.data, last_block, alg->ivsize);
		break;

	case HSE_CIPHER_BLOCK_MODE_CTR:
		blks = src_len / blocksize;
		rem_size = src_len % blocksize;

		hse_ctr_inc(ctx->iv.data, blks, blocksize);

		memcpy(prev_data, src_data + blks, rem_size);
		ctx->prev_size = rem_size;

		break;

	default:
		break;
	}

out_free_buf:
	hse_buf_free(&buf);

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

	if (!src_ctx || !dst_ctx)
		return;

	src = src_ctx;
	dst = dst_ctx;
	alg = src->alg_tpl;

	dst->direction = src->direction;

	if (src->key_len) {
		struct drvcrypt_buf key = {
			.data = src->key,
			.length = src->key_len,
		};

		ret = hse_import_key(key, alg->key_type, dst->key_handle);
		if (ret != TEE_SUCCESS)
			return;

		memcpy(dst->key, src->key, src->key_len);
		dst->key_len = src->key_len;
	}

	memcpy(dst->prev_data, src->prev_data, src->prev_size);
	dst->prev_size = src->prev_size;

	if (!alg->ivsize)
		return;

	memcpy(dst->iv.data, src->iv.data, alg->ivsize);
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
