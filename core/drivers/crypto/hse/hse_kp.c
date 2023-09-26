// SPDX-License-Identifier: BSD-3-Clause
/*
 * Copyright 2023 NXP
 */

#include <crypto/crypto_hse.h>
#include <hse_core.h>
#include <hse_interface.h>
#include <hse_kp.h>
#include <stdlib.h>
#include <string.h>
#include <trace.h>
#include <tee/cache.h>
#include <utee_defines.h>
#include <util.h>

static TEE_Result verify_key_info(hseKeyType_t key_type, uint32_t bits_size,
				  hseKeyHandle_t key_handle)
{
	TEE_Result ret = TEE_ERROR_BAD_PARAMETERS;
	uint32_t key_bits_sizes[] = HSE_AES_KEY_BITS_LENS;
	hseKeyHandle_t sym_keys_handles[] = HSE_NVM_SYM_KEYS;
	bool valid_handle = false;
	size_t i;

	for (i = 0; i < ARRAY_SIZE(sym_keys_handles); i++)
		if (key_handle == sym_keys_handles[i]) {
			valid_handle = true;
			break;
		}

	if (!valid_handle)
		return TEE_ERROR_BAD_PARAMETERS;

	switch (key_type) {
	case HSE_KEY_TYPE_AES:
		for (i = 0; i < ARRAY_SIZE(key_bits_sizes); i++)
			if (bits_size == key_bits_sizes[i]) {
				ret = TEE_SUCCESS;
				break;
			}
		break;
	case HSE_KEY_TYPE_HMAC:
		if (bits_size >= HSE_MIN_HMAC_KEY_BITS_LEN &&
		    bits_size <= HSE_MAX_HMAC_KEY_BITS_LEN)
			ret = TEE_SUCCESS;
		break;
	default:
		ret = TEE_ERROR_BAD_PARAMETERS;
	}

	return ret;
}

TEE_Result hse_provision_sym_key(void *payload,
				 uint8_t key_group,
				 uint8_t key_slot)
{
	HSE_SRV_INIT(hseCipherScheme_t, cipher_scheme);
	HSE_SRV_INIT(hseSrvDescriptor_t, srv_desc);
	HSE_SRV_INIT(hseImportKeySrv_t, import_key_req);
	TEE_Result ret = TEE_SUCCESS;
	struct hse_buf *keyinfo_buff, *tag, *iv, *enckey;
	hseKeyHandle_t key_handle;
	hseKeyInfo_t key_info;
	struct hse_kp_payload *kp_buff = (struct hse_kp_payload *)payload;
	uint32_t enckey_size;

	key_info = kp_buff->key_info;
	key_handle = GET_KEY_HANDLE(HSE_KEY_CATALOG_ID_NVM, key_group,
				    key_slot);

	if (MUL_OVERFLOW(kp_buff->enckey_size, 8, &enckey_size) ||
	    enckey_size > UINT16_MAX)
		return TEE_ERROR_BAD_PARAMETERS;

	/* Check if size has been altered in the payload */
	if (key_info.keyBitLen != enckey_size)
		return TEE_ERROR_BAD_PARAMETERS;

	ret = verify_key_info(key_info.keyType, key_info.keyBitLen,
			      key_handle);
	if (ret != TEE_SUCCESS)
		return ret;

	keyinfo_buff = hse_buf_init((uint8_t *)&key_info, sizeof(key_info));
	if (!keyinfo_buff) {
		ret = TEE_ERROR_OUT_OF_MEMORY;
		goto out;
	}

	tag = hse_buf_init(kp_buff->tag, HSE_GCM_TAG_SIZE);
	if (!tag) {
		ret = TEE_ERROR_OUT_OF_MEMORY;
		goto out_free_info;
	}

	iv = hse_buf_init(kp_buff->iv, HSE_GCM_IV_SIZE);
	if (!iv) {
		ret = TEE_ERROR_OUT_OF_MEMORY;
		goto out_free_tag;
	}

	enckey = hse_buf_init(kp_buff->enckey, kp_buff->enckey_size);
	if (!enckey) {
		ret = TEE_ERROR_OUT_OF_MEMORY;
		goto out_free_iv;
	}

	cipher_scheme.aeadCipher.authCipherMode = HSE_AUTH_CIPHER_MODE_GCM;
	cipher_scheme.aeadCipher.tagLength = HSE_GCM_TAG_SIZE;
	cipher_scheme.aeadCipher.pTag = hse_buf_get_paddr(tag);
	cipher_scheme.aeadCipher.ivLength = HSE_GCM_IV_SIZE;
	cipher_scheme.aeadCipher.pIV = hse_buf_get_paddr(iv);
	cipher_scheme.aeadCipher.aadLength = hse_buf_get_size(keyinfo_buff);
	cipher_scheme.aeadCipher.pAAD = hse_buf_get_paddr(keyinfo_buff);

	import_key_req.targetKeyHandle = key_handle;
	import_key_req.pKeyInfo = hse_buf_get_paddr(keyinfo_buff);
	import_key_req.pKey[2] = hse_buf_get_paddr(enckey);
	import_key_req.keyLen[2] = hse_buf_get_size(enckey);
	import_key_req.cipher.cipherKeyHandle = HSE_NVM_KEK_HANDLE;
	import_key_req.cipher.cipherScheme = cipher_scheme;
	import_key_req.keyContainer.authKeyHandle = HSE_INVALID_KEY_HANDLE;

	srv_desc.srvId = HSE_SRV_ID_IMPORT_KEY;
	srv_desc.hseSrv.importKeyReq = import_key_req;

	ret = hse_srv_req_sync(HSE_CHANNEL_ANY, &srv_desc);
	if (ret != TEE_SUCCESS)
		DMSG("Key provision service request failed with err 0x%x", ret);

	hse_buf_free(enckey);
out_free_iv:
	hse_buf_free(iv);
out_free_tag:
	hse_buf_free(tag);
out_free_info:
	hse_buf_free(keyinfo_buff);
out:
	return ret;
}
