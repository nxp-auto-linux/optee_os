// SPDX-License-Identifier: BSD-3-Clause
/*
 * Copyright 2022 NXP
 */

#include <drvcrypt.h>
#include <drvcrypt_cipher.h>
#include <hse_abi.h>
#include <hse_cipher.h>
#include <hse_core.h>
#include <hse_util.h>
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
	enum hse_cipher_algorithm cipher_type;
	enum hse_block_mode block_mode;
	enum hse_key_type key_type;
};

/**
 * struct hse_cipher_ctx - container for all the other contexts
 * @alg_tpl: algorithm template pointer
 * @iv: initialization vector buffer
 * @key_slot: current key entry in cipher key ring
 * @direction: encrypt or decrypt direction
 */
struct hse_cipher_ctx {
	const struct hse_cipher_tpl *alg_tpl;
	struct hse_buf iv;
	struct hse_key *key_slot;
	enum hse_cipher_dir direction;
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

/**
 * hse_cipher_free_ctx - free all allocated objects of
 *			 the current context
 * @ctx: cipher context
 *
 */
static void hse_cipher_free_ctx(void *ctx)
{
	struct hse_cipher_ctx *hse_ctx = ctx;

	if (hse_ctx) {
		hse_buf_free(&hse_ctx->iv);
		hse_key_slot_release(hse_ctx->key_slot);

		free(hse_ctx);
	}
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
		if (ret)
			goto out_free_ctx;
	}

	hse_ctx->key_slot = hse_key_slot_acquire(alg_tpl->key_type);
	if (!hse_ctx->key_slot) {
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
	struct hse_buf keybuf, keyinf;
	struct hse_key_info *key_inf_buf;
	struct hse_srv_desc srv_desc;

	if (!dinit->key1.data || !dinit->key1.length) {
		ret = TEE_ERROR_BAD_PARAMETERS;
		goto out;
	}

	ret = aes_check_key_size(dinit->key1.length);
	if (ret)
		goto out;

	ret = hse_buf_alloc(&keybuf, dinit->key1.length);
	if (ret)
		goto out;

	memcpy(keybuf.data, dinit->key1.data, keybuf.size);

	ret = hse_buf_alloc(&keyinf, sizeof(struct hse_key_info));
	if (ret)
		goto out_free_keybuf;

	key_inf_buf = (struct hse_key_info *)keyinf.data;
	key_inf_buf->key_flags = HSE_KF_USAGE_ENCRYPT | HSE_KF_USAGE_DECRYPT;
	key_inf_buf->key_bit_len = keybuf.size * 8;
	key_inf_buf->key_type = alg->key_type;

	srv_desc.srv_id = HSE_SRV_ID_IMPORT_KEY;
	srv_desc.import_key_req.key_handle = ctx->key_slot->handle;
	srv_desc.import_key_req.key_info = keyinf.paddr;
	srv_desc.import_key_req.sym.key = keybuf.paddr;
	srv_desc.import_key_req.sym.keylen = keybuf.size;
	srv_desc.import_key_req.cipher_key = HSE_INVALID_KEY_HANDLE;
	srv_desc.import_key_req.auth_key = HSE_INVALID_KEY_HANDLE;

	cache_operation(TEE_CACHEFLUSH, keybuf.data, keybuf.size);
	cache_operation(TEE_CACHEFLUSH, keyinf.data, keyinf.size);

	ret = hse_srv_req_sync(HSE_CHANNEL_ANY, &srv_desc);
	if (ret) {
		DMSG("HSE Import Key request failed");
		goto out_free_keyinf;
	}

	ctx->direction = dinit->encrypt ? HSE_CIPHER_DIR_ENCRYPT :
					  HSE_CIPHER_DIR_DECRYPT;

	if (dinit->iv.data && dinit->iv.length == alg->ivsize)
		memcpy(ctx->iv.data, dinit->iv.data, dinit->iv.length);

out_free_keyinf:
	hse_buf_free(&keyinf);

out_free_keybuf:
	hse_buf_free(&keybuf);

out:
	if (ret) {
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
	struct hse_buf buf;
	size_t  src_len, blocksize = alg->blocksize;
	uint8_t *src_data, *last_block;
	struct hse_srv_desc srv_desc;

	if (dupdate->src.length < blocksize ||
	    dupdate->src.length % blocksize) {
		ret = TEE_ERROR_BAD_PARAMETERS;
		goto out;
	}

	src_data = dupdate->src.data;
	src_len = dupdate->src.length;

	ret = hse_buf_alloc(&buf, src_len);
	if (ret)
		goto out;

	memcpy(buf.data, src_data, buf.size);

	srv_desc.srv_id = HSE_SRV_ID_SYM_CIPHER;
	srv_desc.cipher_req.access_mode = HSE_ACCESS_MODE_ONE_PASS;
	srv_desc.cipher_req.cipher_algo = alg->cipher_type;
	srv_desc.cipher_req.block_mode = alg->block_mode;
	srv_desc.cipher_req.cipher_dir = ctx->direction;
	srv_desc.cipher_req.key_handle = ctx->key_slot->handle;
	srv_desc.cipher_req.iv = ctx->iv.paddr;
	srv_desc.cipher_req.sgt_opt = HSE_SGT_OPT_NONE;
	srv_desc.cipher_req.input_len = buf.size;
	srv_desc.cipher_req.input = buf.paddr;
	srv_desc.cipher_req.output = buf.paddr;

	cache_operation(TEE_CACHEFLUSH, buf.data, buf.size);
	cache_operation(TEE_CACHEFLUSH, ctx->iv.data, alg->ivsize);

	ret = hse_srv_req_sync(HSE_CHANNEL_ANY, &srv_desc);
	if (ret) {
		DMSG("HSE Cipher Request failed");
		goto out_free_buf;
	}

	cache_operation(TEE_CACHEINVALIDATE, buf.data, buf.size);
	memcpy(dupdate->dst.data, buf.data, dupdate->dst.length);

	switch (alg->block_mode) {
	case HSE_CIPHER_BLOCK_MODE_CBC:
		if (ctx->direction == HSE_CIPHER_DIR_ENCRYPT)
			last_block = buf.data  + buf.size - alg->ivsize;
		else
			last_block = src_data + src_len - alg->ivsize;

		memcpy(ctx->iv.data, last_block, alg->ivsize);
		break;
	default:
		break;
	}

out_free_buf:
	hse_buf_free(&buf);

out:
	if (ret) {
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
	struct hse_cipher_ctx *src = src_ctx, *dst = dst_ctx;
	const struct hse_cipher_tpl *alg = src->alg_tpl;

	if (!src_ctx || !dst_ctx)
		return;

	dst->alg_tpl = alg;
	dst->direction = src->direction;
	dst->key_slot = src->key_slot;

	if (!alg->ivsize)
		return;

	if (!dst->iv.data) {
		ret = hse_buf_alloc(&dst->iv,
				    alg->ivsize);
		if (ret)
			return;
	}
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
