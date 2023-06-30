// SPDX-License-Identifier: BSD-3-Clause
/*
 * Copyright 2023 NXP
 */

#include <drvcrypt.h>
#include <drvcrypt_acipher.h>
#include <hse_core.h>
#include <hse_interface.h>
#include <hse_services.h>
#include <string.h>
#include <tee/cache.h>

#define HSE_HASH_ALGO_ERR	0xFF
#define HSE_SIGN_ALGO_ERR	0xFF
#define HSE_RSA_ALGO_ERR	0xFF

static void hse_free_publickey(struct rsa_public_key *key)
{
	crypto_bignum_free(key->e);
	crypto_bignum_free(key->n);
}

static void hse_free_keypair(struct rsa_keypair *key)
{
	crypto_bignum_free(key->e);
	crypto_bignum_free(key->d);
	crypto_bignum_free(key->n);
	crypto_bignum_free(key->p);
	crypto_bignum_free(key->q);
	crypto_bignum_free(key->qp);
	crypto_bignum_free(key->dp);
	crypto_bignum_free(key->dq);
}

static TEE_Result hse_allocate_keypair(struct rsa_keypair *key,
				       size_t size_bits)
{
	memset(key, 0, sizeof(*key));

	key->e = crypto_bignum_allocate(size_bits);
	if (!key->e)
		goto free_keypair;

	key->d = crypto_bignum_allocate(size_bits);
	if (!key->d)
		goto free_keypair;

	key->n = crypto_bignum_allocate(size_bits);
	if (!key->n)
		goto free_keypair;

	key->p = crypto_bignum_allocate(size_bits / 2);
	if (!key->p)
		goto free_keypair;

	key->q = crypto_bignum_allocate(size_bits / 2);
	if (!key->q)
		goto free_keypair;

	key->dp = crypto_bignum_allocate(size_bits / 2);
	if (!key->dp)
		goto free_keypair;

	key->dq = crypto_bignum_allocate(size_bits / 2);
	if (!key->dq)
		goto free_keypair;

	key->qp = crypto_bignum_allocate(size_bits / 2);
	if (!key->qp)
		goto free_keypair;

	return TEE_SUCCESS;

free_keypair:
	hse_free_keypair(key);

	return TEE_ERROR_OUT_OF_MEMORY;
}

static TEE_Result hse_allocate_publickey(struct rsa_public_key *key,
					 size_t size_bits)
{
	memset(key, 0, sizeof(*key));

	key->e = crypto_bignum_allocate(size_bits);
	if (!key->e)
		goto free_publickey;

	key->n = crypto_bignum_allocate(size_bits);
	if (!key->n)
		goto free_publickey;

	return TEE_SUCCESS;

free_publickey:
	hse_free_publickey(key);

	return TEE_ERROR_OUT_OF_MEMORY;
}

static TEE_Result hse_import_rsakey(struct hse_buf e, struct hse_buf n,
				    struct hse_buf d,
				    hseKeyHandle_t key_handle,
				    hseKeyFlags_t key_flags,
				    hseKeyType_t key_type)
{
	HSE_SRV_INIT(hseImportKeySrv_t, import_key_req);
	HSE_SRV_INIT(hseSrvDescriptor_t, srv_desc);
	TEE_Result ret = TEE_SUCCESS;
	struct hse_buf keyinf;
	hseKeyInfo_t *key_inf_buf;

	ret = hse_buf_alloc(&keyinf, sizeof(hseKeyInfo_t));
	if (ret != TEE_SUCCESS)
		goto out;
	memset(keyinf.data, 0, keyinf.size);

	key_inf_buf = (hseKeyInfo_t *)((void *)keyinf.data);
	key_inf_buf->keyFlags = key_flags;
	key_inf_buf->keyBitLen = n.size * 8;
	key_inf_buf->keyType = key_type;
	key_inf_buf->smrFlags = 0;
	key_inf_buf->specific.pubExponentSize = e.size;

	srv_desc.srvId = HSE_SRV_ID_IMPORT_KEY;
	import_key_req.targetKeyHandle = key_handle;
	import_key_req.pKeyInfo = keyinf.paddr;
	import_key_req.pKey[0] = n.paddr;
	import_key_req.pKey[1] = e.paddr;
	import_key_req.pKey[2] = d.paddr;
	import_key_req.keyLen[0] = n.size;
	import_key_req.keyLen[1] = e.size;
	import_key_req.keyLen[2] = d.size;
	import_key_req.cipher.cipherKeyHandle = HSE_INVALID_KEY_HANDLE;
	import_key_req.keyContainer.authKeyHandle = HSE_INVALID_KEY_HANDLE;

	srv_desc.hseSrv.importKeyReq = import_key_req;

	cache_operation(TEE_CACHEFLUSH, e.data, e.size);
	cache_operation(TEE_CACHEFLUSH, n.data, n.size);
	cache_operation(TEE_CACHEFLUSH, d.data, d.size);
	cache_operation(TEE_CACHEFLUSH, keyinf.data, keyinf.size);

	ret = hse_srv_req_sync(HSE_CHANNEL_ANY, &srv_desc);

	hse_buf_free(&keyinf);
out:
	return ret;
}

static TEE_Result hse_import_keypair(struct rsa_keypair *key,
				     hseKeyHandle_t key_handle,
				     hseKeyFlags_t flag)
{
	TEE_Result ret = TEE_SUCCESS;
	struct hse_buf e, n, d;
	size_t e_len, n_len, d_len;
	size_t min_keylen = HSE_BITS_TO_BYTES(HSE_MIN_RSA_KEY_BITS_LEN);
	size_t max_keylen = HSE_BITS_TO_BYTES(HSE_MAX_RSA_KEY_BITS_LEN);

	if (flag != HSE_KF_USAGE_SIGN &&
	    flag != HSE_KF_USAGE_DECRYPT)
		return TEE_ERROR_BAD_PARAMETERS;

	e_len = crypto_bignum_num_bytes(key->e);
	if (e_len > HSE_MAX_RSA_PUB_EXP_SIZE) {
		ret = TEE_ERROR_BAD_PARAMETERS;
		goto out;
	}

	ret = hse_buf_alloc(&e, e_len);
	if (ret != TEE_SUCCESS)
		goto out;
	crypto_bignum_bn2bin(key->e, e.data);

	n_len = crypto_bignum_num_bytes(key->n);
	if (n_len < min_keylen || n_len > max_keylen) {
		ret = TEE_ERROR_BAD_PARAMETERS;
		goto out_free_e;
	}

	ret = hse_buf_alloc(&n, n_len);
	if (ret != TEE_SUCCESS)
		goto out_free_e;
	crypto_bignum_bn2bin(key->n, n.data);

	d_len = crypto_bignum_num_bytes(key->d);
	if (d_len < min_keylen || d_len > max_keylen) {
		ret = TEE_ERROR_BAD_PARAMETERS;
		goto out_free_n;
	}

	ret = hse_buf_alloc(&d, d_len);
	if (ret != TEE_SUCCESS)
		goto out_free_n;
	crypto_bignum_bn2bin(key->d, d.data);

	ret = hse_import_rsakey(e, n, d, key_handle, flag,
				HSE_KEY_TYPE_RSA_PAIR);

	hse_buf_free(&d);
out_free_n:
	hse_buf_free(&n);
out_free_e:
	hse_buf_free(&e);
out:
	if (ret != TEE_SUCCESS)
		DMSG("HSE RSA Keypair request failed with err 0x%x", ret);
	return ret;
}

static TEE_Result hse_import_pubkey(struct rsa_public_key *key,
				    hseKeyHandle_t key_handle,
				    hseKeyFlags_t flag)
{
	TEE_Result ret = TEE_SUCCESS;
	struct hse_buf e, n, d;
	size_t e_len, n_len;
	size_t min_keylen = HSE_BITS_TO_BYTES(HSE_MIN_RSA_KEY_BITS_LEN);
	size_t max_keylen = HSE_BITS_TO_BYTES(HSE_MAX_RSA_KEY_BITS_LEN);

	if (flag != HSE_KF_USAGE_VERIFY &&
	    flag != HSE_KF_USAGE_ENCRYPT)
		return TEE_ERROR_BAD_PARAMETERS;

	e_len = crypto_bignum_num_bytes(key->e);
	if (e_len > HSE_MAX_RSA_PUB_EXP_SIZE) {
		ret = TEE_ERROR_BAD_PARAMETERS;
		goto out;
	}

	ret = hse_buf_alloc(&e, e_len);
	if (ret != TEE_SUCCESS)
		goto out;
	crypto_bignum_bn2bin(key->e, e.data);

	n_len = crypto_bignum_num_bytes(key->n);
	if (n_len < min_keylen || n_len > max_keylen) {
		ret = TEE_ERROR_BAD_PARAMETERS;
		goto out_free_e;
	}

	ret = hse_buf_alloc(&n, n_len);
	if (ret != TEE_SUCCESS)
		goto out_free_e;
	crypto_bignum_bn2bin(key->n, n.data);

	memset(&d, 0, sizeof(d));

	ret = hse_import_rsakey(e, n, d, key_handle, flag,
				HSE_KEY_TYPE_RSA_PUB);

	hse_buf_free(&d);
	hse_buf_free(&n);
out_free_e:
	hse_buf_free(&e);
out:
	if (ret != TEE_SUCCESS)
		DMSG("HSE RSA Public Key request failed with err 0x%x", ret);
	return ret;
}

static void hse_erase_rsakey(hseKeyHandle_t key_handle)
{
	HSE_SRV_INIT(hseSrvDescriptor_t, srv_desc);
	TEE_Result res;

	srv_desc.srvId = HSE_SRV_ID_ERASE_KEY;
	srv_desc.hseSrv.eraseKeyReq.keyHandle = key_handle;
	srv_desc.hseSrv.eraseKeyReq.eraseKeyOptions = HSE_ERASE_NOT_USED;

	res = hse_srv_req_sync(HSE_CHANNEL_ANY, &srv_desc);
	if (res != TEE_SUCCESS)
		DMSG("HSE Erase Key request failed with err 0x%x", res);
}

static uint8_t get_hse_hash_algo(uint32_t hash_algo)
{
	switch (hash_algo) {
	case TEE_ALG_SHA1:
		return HSE_HASH_ALGO_SHA_1;
	case TEE_ALG_SHA224:
		return HSE_HASH_ALGO_SHA2_224;
	case TEE_ALG_SHA256:
		return HSE_HASH_ALGO_SHA2_256;
	case TEE_ALG_SHA384:
		return HSE_HASH_ALGO_SHA2_384;
	case TEE_ALG_SHA512:
		return HSE_HASH_ALGO_SHA2_512;
	case 0x0:
		return HSE_HASH_ALGO_NULL;

	/* The remaining MD5 is not supported in HSE */
	default:
		return HSE_HASH_ALGO_ERR;
	}
}

static hseRsaAlgo_t get_hse_rsa_algo(uint32_t rsa_algo)
{
	switch (rsa_algo) {
	case DRVCRYPT_RSA_NOPAD:
		return HSE_RSA_ALGO_NO_PADDING;

	case DRVCRYPT_RSA_OAEP:
		return HSE_RSA_ALGO_RSAES_OAEP;

	case DRVCRYPT_RSA_PKCS_V1_5:
		return HSE_RSA_ALGO_RSAES_PKCS1_V15;

	default:
		return HSE_RSA_ALGO_ERR;
	}
}

static TEE_Result fill_cipher_sch(struct drvcrypt_rsa_ed *rsa_data,
				  struct hse_buf *label_buf,
				  hseRsaCipherScheme_t *cipher_sch)
{
	TEE_Result res;
	hseHashAlgo_t hash_algo = HSE_HASH_ALGO_NULL;
	hseRsaAlgo_t rsa_algo;
	struct drvcrypt_buf label = rsa_data->label;

	hash_algo = get_hse_hash_algo(rsa_data->hash_algo);
	rsa_algo = get_hse_rsa_algo(rsa_data->rsa_id);

	if (hash_algo == HSE_HASH_ALGO_ERR || rsa_algo == HSE_RSA_ALGO_ERR)
		return TEE_ERROR_BAD_PARAMETERS;

	cipher_sch->rsaAlgo = rsa_algo;

	memset(label_buf, 0, sizeof(*label_buf));

	if (rsa_algo != HSE_RSA_ALGO_RSAES_OAEP)
		return TEE_SUCCESS;

	if (label.length && label.length < 128) {
		res = hse_buf_alloc(label_buf, label.length);
		if (res != TEE_SUCCESS)
			return res;

		memcpy(label_buf->data, label.data, label.length);

		cache_operation(TEE_CACHEFLUSH, label_buf->data,
				label_buf->size);
	}

	cipher_sch->sch.rsaOAEP.hashAlgo = hash_algo;
	cipher_sch->sch.rsaOAEP.labelLength = label_buf->size;
	cipher_sch->sch.rsaOAEP.pLabel = label_buf->paddr;

	return TEE_SUCCESS;
}

static TEE_Result hse_rsa_enc_req(struct drvcrypt_rsa_ed *rsa_data,
				  hseCipherDir_t direction)
{
	HSE_SRV_INIT(hseSrvDescriptor_t, srv_desc);
	HSE_SRV_INIT(hseRsaCipherScheme_t, cipher_sch);
	TEE_Result res;
	struct hse_buf label, hse_in, hse_out, hse_out_len;
	hseKeyType_t key_type;
	hseKeyHandle_t key_handle;
	size_t n_len;
	struct drvcrypt_buf *in_buf, *out_buf;
	uint32_t off = 0, out_len;

	res = fill_cipher_sch(rsa_data, &label, &cipher_sch);
	if (res != TEE_SUCCESS)
		goto out;

	key_type = (direction == HSE_CIPHER_DIR_ENCRYPT) ?
		   HSE_KEY_TYPE_RSA_PUB : HSE_KEY_TYPE_RSA_PAIR;

	key_handle = hse_keyslot_acquire(key_type);
	if (key_handle == HSE_INVALID_KEY_HANDLE) {
		res = TEE_ERROR_BUSY;
		goto out_free_label;
	}

	res = (direction == HSE_CIPHER_DIR_ENCRYPT) ?
	hse_import_pubkey(rsa_data->key.key, key_handle,
			  HSE_KF_USAGE_ENCRYPT) :
	hse_import_keypair(rsa_data->key.key, key_handle,
			   HSE_KF_USAGE_DECRYPT);

	if (res != TEE_SUCCESS)
		goto out_free_keyslot;

	if (direction == HSE_CIPHER_DIR_ENCRYPT) {
		in_buf = &rsa_data->message;
		out_buf = &rsa_data->cipher;

	} else {
		in_buf = &rsa_data->cipher;
		out_buf = &rsa_data->message;

		/*
		 * In case of decryption, the cipher text should be the length
		 * of the modulus. Some buffers may be over-allocated.
		 */
		n_len = crypto_bignum_num_bytes(((struct rsa_keypair *)
						 (rsa_data->key.key))->n);

		if (in_buf->length != n_len)
			in_buf->length = n_len;
	}

	res = hse_buf_alloc(&hse_in, in_buf->length);
	if (res != TEE_SUCCESS)
		goto out_free_keyslot;

	memcpy(hse_in.data, in_buf->data, in_buf->length);
	cache_operation(TEE_CACHEFLUSH, hse_in.data, hse_in.size);

	res = hse_buf_alloc(&hse_out, out_buf->length);
	if (res != TEE_SUCCESS)
		goto out_free_input;

	memset(hse_out.data, 0, hse_out.size);
	cache_operation(TEE_CACHEFLUSH, hse_out.data, hse_out.size);

	res = hse_buf_alloc(&hse_out_len, sizeof(uint32_t));
	if (res != TEE_SUCCESS)
		goto out_free_output;

	memcpy(hse_out_len.data, &out_buf->length, sizeof(uint32_t));
	cache_operation(TEE_CACHEFLUSH, hse_out_len.data, hse_out_len.size);

	srv_desc.srvId = HSE_SRV_ID_RSA_CIPHER;
	srv_desc.hseSrv.rsaCipherReq.rsaScheme = cipher_sch;
	srv_desc.hseSrv.rsaCipherReq.cipherDir = direction;
	srv_desc.hseSrv.rsaCipherReq.keyHandle = key_handle;
	srv_desc.hseSrv.rsaCipherReq.inputLength = hse_in.size;
	srv_desc.hseSrv.rsaCipherReq.pInput = hse_in.paddr;
	srv_desc.hseSrv.rsaCipherReq.pOutputLength = hse_out_len.paddr;
	srv_desc.hseSrv.rsaCipherReq.pOutput = hse_out.paddr;

	res = hse_srv_req_sync(HSE_CHANNEL_ANY, &srv_desc);
	if (res != TEE_SUCCESS) {
		DMSG("HSE RSA Cipher Request failed with ret=0x%x", res);
		goto out_free_len;
	}

	cache_operation(TEE_CACHEINVALIDATE, hse_out.data, hse_out.size);
	cache_operation(TEE_CACHEINVALIDATE, hse_out_len.data,
			hse_out_len.size);

	memcpy(&out_len, hse_out_len.data, sizeof(uint32_t));

	/* Remove the trailing zeros. Leave one zero if output is only zeros */
	if (rsa_data->rsa_id == DRVCRYPT_RSA_NOPAD)
		while ((off < out_len - 1) && (hse_out.data[off] == 0))
			off++;

	out_buf->length = out_len - off;
	memcpy(out_buf->data, hse_out.data + off, out_buf->length);

out_free_len:
	hse_buf_free(&hse_out_len);
out_free_output:
	hse_buf_free(&hse_out);
out_free_input:
	hse_buf_free(&hse_in);
out_free_keyslot:
	hse_erase_rsakey(key_handle);
	hse_keyslot_release(key_handle);
out_free_label:
	hse_buf_free(&label);
out:
	if (res != TEE_SUCCESS)
		DMSG("HSE RSA Encrypt operation failed with err 0x%x", res);

	return res;
}

static hseSignSchemeEnum_t get_hse_sign_algo(uint32_t sign_algo)
{
	switch (sign_algo) {
	case TEE_ALG_RSASSA_PKCS1_V1_5_SHA1:
	case TEE_ALG_RSASSA_PKCS1_V1_5_SHA224:
	case TEE_ALG_RSASSA_PKCS1_V1_5_SHA256:
	case TEE_ALG_RSASSA_PKCS1_V1_5_SHA384:
	case TEE_ALG_RSASSA_PKCS1_V1_5_SHA512:
		return HSE_SIGN_RSASSA_PKCS1_V15;

	case TEE_ALG_RSASSA_PKCS1_PSS_MGF1_SHA1:
	case TEE_ALG_RSASSA_PKCS1_PSS_MGF1_SHA224:
	case TEE_ALG_RSASSA_PKCS1_PSS_MGF1_SHA256:
	case TEE_ALG_RSASSA_PKCS1_PSS_MGF1_SHA384:
	case TEE_ALG_RSASSA_PKCS1_PSS_MGF1_SHA512:
		return HSE_SIGN_RSASSA_PSS;

	default:
		return HSE_SIGN_ALGO_ERR;
	}
}

static TEE_Result check_salt_len(struct drvcrypt_rsa_ssa *ssa_data)
{
	size_t n_size = ssa_data->key.n_size;
	uint32_t hash_algo = ssa_data->hash_algo;
	size_t digest_size = ssa_data->digest_size;
	size_t salt_len = ssa_data->salt_len;

	/* HSE restrictions on salt length */
	if (hash_algo == HSE_HASH_ALGO_SHA2_512 && n_size == 128) {
		if (salt_len > 62)
			return TEE_ERROR_BAD_PARAMETERS;

	} else if (salt_len > digest_size) {
		return  TEE_ERROR_BAD_PARAMETERS;
	}

	return TEE_SUCCESS;
}

static TEE_Result fill_sign_sch(struct drvcrypt_rsa_ssa *ssa_data,
				hseSignScheme_t *sign_scheme)
{
	TEE_Result res;
	hseHashAlgo_t hash_algo;
	hseSignSchemeEnum_t sign_algo;

	hash_algo = get_hse_hash_algo(ssa_data->hash_algo);
	sign_algo = get_hse_sign_algo(ssa_data->algo);

	if (hash_algo == HSE_HASH_ALGO_ERR || sign_algo == HSE_SIGN_ALGO_ERR)
		return TEE_ERROR_BAD_PARAMETERS;

	sign_scheme->signSch = sign_algo;

	if (sign_algo == HSE_SIGN_RSASSA_PKCS1_V15) {
		sign_scheme->sch.rsaPkcs1v15.hashAlgo = hash_algo;
	} else {
		res = check_salt_len(ssa_data);
		if (res != TEE_SUCCESS)
			return TEE_ERROR_BAD_PARAMETERS;

		sign_scheme->sch.rsaPss.hashAlgo = hash_algo;
		sign_scheme->sch.rsaPss.saltLength = ssa_data->salt_len;
	}

	return TEE_SUCCESS;
}

static TEE_Result hse_rsa_sign_req(struct drvcrypt_rsa_ssa *ssa_data,
				   hseAuthDir_t direction)
{
	HSE_SRV_INIT(hseSrvDescriptor_t, srv_desc);
	HSE_SRV_INIT(hseSignScheme_t, sign_scheme);
	TEE_Result res = TEE_SUCCESS;
	hseKeyType_t key_type;
	hseKeyHandle_t key_handle;
	struct hse_buf message, sign_len, signature;

	res = fill_sign_sch(ssa_data, &sign_scheme);
	if (res != TEE_SUCCESS)
		goto out;

	key_type = (direction == HSE_AUTH_DIR_GENERATE) ?
		   HSE_KEY_TYPE_RSA_PAIR : HSE_KEY_TYPE_RSA_PUB;

	key_handle = hse_keyslot_acquire(key_type);
	if (key_handle == HSE_INVALID_KEY_HANDLE) {
		res = TEE_ERROR_BUSY;
		goto out;
	}

	res = (direction == HSE_AUTH_DIR_GENERATE) ?
	hse_import_keypair(ssa_data->key.key, key_handle,
			   HSE_KF_USAGE_SIGN) :
	hse_import_pubkey(ssa_data->key.key, key_handle,
			  HSE_KF_USAGE_VERIFY);

	if (res != TEE_SUCCESS)
		goto out_free_keyslot;

	if (ssa_data->signature.length > UINT32_MAX ||
	    ssa_data->message.length > UINT32_MAX) {
		res = TEE_ERROR_BAD_PARAMETERS;
		goto out_erase_key;
	}

	res = hse_buf_alloc(&message, ssa_data->message.length);
	if (res != TEE_SUCCESS)
		goto out_erase_key;

	memcpy(message.data, ssa_data->message.data, ssa_data->message.length);
	cache_operation(TEE_CACHEFLUSH, message.data, message.size);

	res = hse_buf_alloc(&signature, ssa_data->signature.length);
	if (res != TEE_SUCCESS)
		goto out_free_message;

	if (direction == HSE_AUTH_DIR_VERIFY) {
		memcpy(signature.data, ssa_data->signature.data,
		       ssa_data->signature.length);
		cache_operation(TEE_CACHEFLUSH, signature.data,
				signature.size);
	}

	res = hse_buf_alloc(&sign_len, sizeof(uint32_t));
	if (res != TEE_SUCCESS)
		goto out_free_sign;

	memcpy(sign_len.data, &ssa_data->signature.length, sizeof(uint32_t));
	cache_operation(TEE_CACHEFLUSH, sign_len.data, sign_len.size);

	srv_desc.srvId = HSE_SRV_ID_SIGN;
	srv_desc.hseSrv.signReq.accessMode = HSE_ACCESS_MODE_ONE_PASS;
	srv_desc.hseSrv.signReq.streamId = 0u;
	srv_desc.hseSrv.signReq.authDir = direction;
	srv_desc.hseSrv.signReq.bInputIsHashed = true;
	srv_desc.hseSrv.signReq.signScheme = sign_scheme;
	srv_desc.hseSrv.signReq.keyHandle = key_handle;
	srv_desc.hseSrv.signReq.sgtOption = HSE_SGT_OPTION_NONE;
	srv_desc.hseSrv.signReq.inputLength = message.size;
	srv_desc.hseSrv.signReq.pInput = message.paddr;
	srv_desc.hseSrv.signReq.pSignatureLength[0] = sign_len.paddr;
	srv_desc.hseSrv.signReq.pSignatureLength[1] = 0u;
	srv_desc.hseSrv.signReq.pSignature[0] = signature.paddr;
	srv_desc.hseSrv.signReq.pSignature[1] = 0u;

	res = hse_srv_req_sync(HSE_CHANNEL_ANY, &srv_desc);

	if (direction == HSE_AUTH_DIR_GENERATE) {
		cache_operation(TEE_CACHEINVALIDATE, signature.data,
				signature.size);
		memcpy(ssa_data->signature.data, signature.data,
		       signature.size);
	}

	hse_buf_free(&sign_len);
out_free_sign:
	hse_buf_free(&signature);
out_free_message:
	hse_buf_free(&message);
out_erase_key:
	hse_erase_rsakey(key_handle);
out_free_keyslot:
	hse_keyslot_release(key_handle);
out:
	if (res != TEE_SUCCESS)
		DMSG("HSE RSA sign request failed with err 0x%x", res);

	return res;
}

static TEE_Result hse_gen_keypair(struct rsa_keypair *key __unused,
				  size_t size_bits __unused)
{
	return TEE_SUCCESS;
}

static TEE_Result hse_encrypt(struct drvcrypt_rsa_ed *rsa_data)
{
	return hse_rsa_enc_req(rsa_data, HSE_CIPHER_DIR_ENCRYPT);
}

static TEE_Result hse_decrypt(struct drvcrypt_rsa_ed *rsa_data)
{
	return hse_rsa_enc_req(rsa_data, HSE_CIPHER_DIR_DECRYPT);
}

static TEE_Result hse_ssa_sign(struct drvcrypt_rsa_ssa *ssa_data)
{
	return hse_rsa_sign_req(ssa_data, HSE_AUTH_DIR_GENERATE);
}

static TEE_Result hse_ssa_verify(struct drvcrypt_rsa_ssa *ssa_data)
{
	return hse_rsa_sign_req(ssa_data, HSE_AUTH_DIR_VERIFY);
}

static const struct drvcrypt_rsa driver_rsa = {
	.alloc_keypair = hse_allocate_keypair,
	.alloc_publickey = hse_allocate_publickey,
	.free_publickey = hse_free_publickey,
	.free_keypair = hse_free_keypair,
	.gen_keypair = hse_gen_keypair,
	.encrypt = hse_encrypt,
	.decrypt = hse_decrypt,
	.optional.ssa_sign = hse_ssa_sign,
	.optional.ssa_verify = hse_ssa_verify,
};

TEE_Result hse_rsa_register(void)
{
	return drvcrypt_register_rsa(&driver_rsa);
}
