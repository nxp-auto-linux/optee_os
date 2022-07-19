// SPDX-License-Identifier: BSD-3-Clause
/*
 * Copyright 2022 NXP
 */

#include <assert.h>
#include <hse_abi.h>
#include <hse_core.h>
#include <hse_huk.h>
#include <hse_util.h>
#include <kernel/tee_common_otp.h>
#include <tee/cache.h>
#include <trace.h>

#define HSE_HUK_LENGTH	32

static uint8_t stored_key[HSE_HUK_LENGTH];
static bool key_retrieved;

static TEE_Result hse_extract_step(struct hse_key *key_slot)
{
	TEE_Result ret = TEE_SUCCESS;
	struct hse_srv_desc srv_desc;
	struct hse_key_derive_srv derive_req;

	if (!key_slot)
		return TEE_ERROR_BAD_PARAMETERS;

	derive_req.kdf_algo = HSE_KDF_ALGO_EXTRACT_STEP;
	derive_req.extract_step.secret_key_handle = HSE_ROM_KEY_AES256_KEY1;
	derive_req.extract_step.target_key_handle = key_slot->handle;
	derive_req.extract_step.kdf_prf = HSE_KDF_PRF_HMAC;
	derive_req.extract_step.hmac_hash = HSE_HASH_ALGO_SHA2_256;
	derive_req.extract_step.salt_key_handle = HSE_INVALID_KEY_HANDLE;
	derive_req.extract_step.salt = 0;

	/* Reserved field is not used, but using an uninitialized value
	 * triggers a coverity error
	 */
	memset(derive_req.reserved, 0x0, sizeof(derive_req.reserved));

	srv_desc.srv_id = HSE_SRV_ID_KEY_DERIVE;
	srv_desc.key_derive_req = derive_req;

	ret = hse_srv_req_sync(HSE_CHANNEL_ANY, &srv_desc);
	if (ret != TEE_SUCCESS)
		DMSG("HSE Derive Key service request failed");

	return ret;
}

static TEE_Result hse_expand_step(struct hse_key *key_slot)
{
	TEE_Result ret = TEE_SUCCESS;
	struct hse_srv_desc srv_desc;
	struct hse_kdf_common_params kdf_common;

	if (!key_slot)
		return TEE_ERROR_BAD_PARAMETERS;

	kdf_common.src_key_handle = key_slot->handle;
	kdf_common.target_key_handle = key_slot->handle;
	kdf_common.key_mat_len = HSE_HUK_LENGTH;
	kdf_common.kdf_prf = HSE_KDF_PRF_HMAC;
	kdf_common.hmac_hash = HSE_HASH_ALGO_SHA2_256;
	kdf_common.p_info = 0;
	kdf_common.info_len = 0;

	srv_desc.srv_id = HSE_SRV_ID_KEY_DERIVE;
	srv_desc.key_derive_req.kdf_algo = HSE_KDF_ALGO_HKDF_EXPAND;
	srv_desc.key_derive_req.hkdf_expand.kdf_common = kdf_common;

	ret = hse_srv_req_sync(HSE_CHANNEL_ANY, &srv_desc);
	if (ret != TEE_SUCCESS)
		DMSG("HSE Derive Key service request failed");

	return ret;
}

static TEE_Result hse_copy_and_extract(struct hse_key *src_slot,
				       struct hse_key *dst_slot,
				       uint8_t *data)
{
	TEE_Result ret = TEE_SUCCESS;
	struct hse_srv_desc srv_desc;
	uint16_t flags, bit_len;
	struct hse_buf keyinf, keybuf, keysize;
	struct hse_sym_cipher_scheme sym_cipher;

	if (!src_slot || !dst_slot || !data)
		return TEE_ERROR_BAD_PARAMETERS;

	flags = HSE_KF_ACCESS_EXPORTABLE | HSE_KF_USAGE_SIGN;
	bit_len = HSE_HUK_LENGTH * 8;

	srv_desc.srv_id = HSE_SRV_ID_KEY_DERIVE_COPY;
	srv_desc.key_derive_copy_key_req.key_handle = src_slot->handle;
	srv_desc.key_derive_copy_key_req.start_offset = 0;
	srv_desc.key_derive_copy_key_req.target_key_handle = dst_slot->handle;
	srv_desc.key_derive_copy_key_req.key_info.key_flags = flags;
	srv_desc.key_derive_copy_key_req.key_info.key_bit_len = bit_len;
	srv_desc.key_derive_copy_key_req.key_info.key_type = HSE_KEY_TYPE_HMAC;

	ret = hse_srv_req_sync(HSE_CHANNEL_ANY, &srv_desc);
	if (ret != TEE_SUCCESS) {
		DMSG("HSE Derive Copy Key service request failed");
		return ret;
	}

	ret = hse_buf_alloc(&keyinf, sizeof(struct hse_key_info));
	if (ret != TEE_SUCCESS)
		return ret;

	ret = hse_buf_alloc(&keybuf, HSE_HUK_LENGTH);
	if (ret != TEE_SUCCESS)
		goto out_free_keyinf;

	ret = hse_buf_alloc(&keysize, sizeof(uint16_t));
	if (ret != TEE_SUCCESS)
		goto out_free_keybuf;
	keysize.data[0] = HSE_HUK_LENGTH;

	cache_operation(TEE_CACHEFLUSH, keysize.data, keysize.size);

	sym_cipher.algo = HSE_CIPHER_ALGO_AES;
	sym_cipher.block_mode = HSE_CIPHER_BLOCK_MODE_ECB;
	sym_cipher.iv_len = 0;

	srv_desc.srv_id = HSE_SRV_ID_EXPORT_KEY;
	srv_desc.export_key_req.key_handle = dst_slot->handle;
	srv_desc.export_key_req.key_info = keyinf.paddr;
	srv_desc.export_key_req.sym.key = keybuf.paddr;
	srv_desc.export_key_req.sym.keylen = keysize.paddr;
	srv_desc.export_key_req.cipher.cipher_key_handle =
		HSE_ROM_KEY_AES256_KEY1;
	srv_desc.export_key_req.cipher.sym_cipher = sym_cipher;
	srv_desc.export_key_req.auth_key = HSE_INVALID_KEY_HANDLE;

	ret = hse_srv_req_sync(HSE_CHANNEL_ANY, &srv_desc);
	if (ret != TEE_SUCCESS) {
		DMSG("HSE Export Key service request failed");
		goto out_free_keysize;
	}

	cache_operation(TEE_CACHEINVALIDATE, keybuf.data, keybuf.size);

	memcpy(data, keybuf.data, HSE_HUK_LENGTH);

out_free_keysize:
	hse_buf_free(&keysize);

out_free_keybuf:
	hse_buf_free(&keybuf);

out_free_keyinf:
	hse_buf_free(&keyinf);

	return ret;
}

TEE_Result hse_retrieve_huk(void)
{
	TEE_Result ret = TEE_SUCCESS;
	struct hse_key *sh_secret_slot, *hmac_slot;

	assert(!key_retrieved);

	sh_secret_slot = hse_key_slot_acquire(HSE_KEY_TYPE_SHARED_SECRET);
	if (!sh_secret_slot) {
		ret = TEE_ERROR_BUSY;
		goto out;
	}

	ret = hse_extract_step(sh_secret_slot);
	if (ret != TEE_SUCCESS) {
		DMSG("Extract Step failed");
		goto release_sh_secret;
	}

	ret = hse_expand_step(sh_secret_slot);
	if (ret != TEE_SUCCESS) {
		DMSG("Expand Step failed");
		goto release_sh_secret;
	}

	hmac_slot = hse_key_slot_acquire(HSE_KEY_TYPE_HMAC);
	if (!hmac_slot)
		goto release_sh_secret;

	ret = hse_copy_and_extract(sh_secret_slot, hmac_slot, stored_key);
	if (ret != TEE_SUCCESS) {
		DMSG("Copy and Export Step failed");
		goto release_hmac;
	}

	key_retrieved = true;

release_hmac:
	hse_key_slot_release(hmac_slot);

release_sh_secret:
	hse_key_slot_release(sh_secret_slot);

out:
	if (ret != TEE_SUCCESS)
		DMSG("HW Unique Key request failed with err 0x%x", ret);
	return ret;
}

TEE_Result tee_otp_get_hw_unique_key(struct tee_hw_unique_key *hwkey)
{
	COMPILE_TIME_ASSERT(sizeof(stored_key) >= sizeof(hwkey->data));

	if (!key_retrieved)
		return TEE_ERROR_SECURITY;

	memcpy(&hwkey->data[0], &stored_key[0], sizeof(hwkey->data));

	return TEE_SUCCESS;
}
