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

static uint8_t bin_key_param[HSE_BITS_TO_BYTES(HSE_MAX_RSA_KEY_BITS_LEN)];

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

static TEE_Result hse_import_rsakey(struct hse_buf *e, struct hse_buf *n,
				    struct hse_buf *d,
				    hseKeyHandle_t *key_handle,
				    hseKeyFlags_t key_flags,
				    hseKeyType_t key_type)
{
	hseKeyInfo_t key_info = {0};
	size_t n_bitlen = HSE_BYTES_TO_BITS(hse_buf_get_size(n));
	uint32_t e_len = hse_buf_get_size(e);

	/* The bit length of n is stored in an uint16_t field of key_info
	 * and e length is stored in an uint8_t field
	 */
	if (n_bitlen > UINT16_MAX || e_len > UINT8_MAX)
		return TEE_ERROR_BAD_PARAMETERS;

	key_info.keyFlags = key_flags;
	key_info.keyBitLen = n_bitlen;
	key_info.keyType = key_type;
	key_info.specific.pubExponentSize = e_len;

	return hse_acquire_and_import_key(key_handle, &key_info, n, e, d);
}

static TEE_Result hse_import_keypair(struct rsa_keypair *key,
				     hseKeyHandle_t *key_handle,
				     hseKeyFlags_t flag)
{
	TEE_Result ret = TEE_SUCCESS;
	struct hse_buf *e = NULL, *n = NULL, *d = NULL;
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
	crypto_bignum_bn2bin(key->e, bin_key_param);
	e = hse_buf_init(bin_key_param, e_len);
	if (!e) {
		ret = TEE_ERROR_OUT_OF_MEMORY;
		goto out;
	}

	n_len = crypto_bignum_num_bytes(key->n);
	if (n_len < min_keylen || n_len > max_keylen) {
		ret = TEE_ERROR_BAD_PARAMETERS;
		goto out_free_e;
	}
	crypto_bignum_bn2bin(key->n, bin_key_param);
	n = hse_buf_init(bin_key_param, n_len);
	if (!n) {
		ret = TEE_ERROR_OUT_OF_MEMORY;
		goto out_free_e;
	}

	d_len = crypto_bignum_num_bytes(key->d);
	if (d_len < min_keylen || d_len > max_keylen) {
		ret = TEE_ERROR_BAD_PARAMETERS;
		goto out_free_n;
	}
	crypto_bignum_bn2bin(key->d, bin_key_param);
	d = hse_buf_init(bin_key_param, d_len);
	if (!d) {
		ret = TEE_ERROR_OUT_OF_MEMORY;
		goto out_free_n;
	}

	ret = hse_import_rsakey(e, n, d, key_handle, flag,
				HSE_KEY_TYPE_RSA_PAIR);

	hse_buf_free(d);
out_free_n:
	hse_buf_free(n);
out_free_e:
	hse_buf_free(e);
out:
	if (ret != TEE_SUCCESS)
		DMSG("HSE RSA Keypair request failed with err 0x%x", ret);
	return ret;
}

static TEE_Result hse_import_pubkey(struct rsa_public_key *key,
				    hseKeyHandle_t *key_handle,
				    hseKeyFlags_t flag)
{
	TEE_Result ret = TEE_SUCCESS;
	struct hse_buf *e = NULL, *n = NULL, *d = NULL;
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
	crypto_bignum_bn2bin(key->e, bin_key_param);
	e = hse_buf_init(bin_key_param, e_len);
	if (!e) {
		ret = TEE_ERROR_OUT_OF_MEMORY;
		goto out;
	}

	n_len = crypto_bignum_num_bytes(key->n);
	if (n_len < min_keylen || n_len > max_keylen) {
		ret = TEE_ERROR_BAD_PARAMETERS;
		goto out_free_e;
	}
	crypto_bignum_bn2bin(key->n, bin_key_param);
	n = hse_buf_init(bin_key_param, n_len);
	if (!n) {
		ret = TEE_ERROR_OUT_OF_MEMORY;
		goto out_free_e;
	}

	ret = hse_import_rsakey(e, n, d, key_handle, flag,
				HSE_KEY_TYPE_RSA_PUB);

	hse_buf_free(n);
out_free_e:
	hse_buf_free(e);
out:
	if (ret != TEE_SUCCESS)
		DMSG("HSE RSA Public Key request failed with err 0x%x", ret);
	return ret;
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

	if (rsa_algo != HSE_RSA_ALGO_RSAES_OAEP)
		return TEE_SUCCESS;

	if (label.length && label.length < 128) {
		label_buf = hse_buf_init(label.data, label.length);
		if (!label_buf) {
			res = TEE_ERROR_OUT_OF_MEMORY;
			return res;
		}
	}

	cipher_sch->sch.rsaOAEP.hashAlgo = hash_algo;
	cipher_sch->sch.rsaOAEP.labelLength = hse_buf_get_size(label_buf);
	cipher_sch->sch.rsaOAEP.pLabel = hse_buf_get_paddr(label_buf);

	return TEE_SUCCESS;
}

static TEE_Result hse_rsa_enc_req(struct drvcrypt_rsa_ed *rsa_data,
				  hseCipherDir_t direction)
{
	HSE_SRV_INIT(hseSrvDescriptor_t, srv_desc);
	hseRsaCipherSrv_t *rsa_cipher_req = &srv_desc.hseSrv.rsaCipherReq;
	HSE_SRV_INIT(hseRsaCipherScheme_t, cipher_sch);
	TEE_Result res;
	struct hse_buf *label = NULL, *hse_in = NULL, *hse_out = NULL,
		       *hse_out_len = NULL;
	hseKeyHandle_t key_handle = HSE_INVALID_KEY_HANDLE;
	struct drvcrypt_buf *in_buf, *out_buf;
	uint32_t off = 0, out_len;

	res = fill_cipher_sch(rsa_data, label, &cipher_sch);
	if (res != TEE_SUCCESS)
		goto out;

	res = (direction == HSE_CIPHER_DIR_ENCRYPT) ?
	hse_import_pubkey(rsa_data->key.key, &key_handle,
			  HSE_KF_USAGE_ENCRYPT) :
	hse_import_keypair(rsa_data->key.key, &key_handle,
			   HSE_KF_USAGE_DECRYPT);

	if (res != TEE_SUCCESS)
		goto out_free_label;

	if (direction == HSE_CIPHER_DIR_ENCRYPT) {
		in_buf = &rsa_data->message;
		out_buf = &rsa_data->cipher;

	} else {
		in_buf = &rsa_data->cipher;
		out_buf = &rsa_data->message;
	}

	hse_in = hse_buf_init(in_buf->data, in_buf->length);
	if (!hse_in) {
		res = TEE_ERROR_OUT_OF_MEMORY;
		goto out_erase_key;
	}

	hse_out = hse_buf_alloc(out_buf->length);
	if (!hse_out) {
		res = TEE_ERROR_OUT_OF_MEMORY;
		goto out_free_input;
	}

	hse_out_len = hse_buf_init(&out_buf->length, sizeof(uint32_t));
	if (!hse_out_len) {
		res = TEE_ERROR_OUT_OF_MEMORY;
		goto out_free_output;
	}

	srv_desc.srvId = HSE_SRV_ID_RSA_CIPHER;
	rsa_cipher_req->rsaScheme = cipher_sch;
	rsa_cipher_req->cipherDir = direction;
	rsa_cipher_req->keyHandle = key_handle;
	rsa_cipher_req->inputLength = hse_buf_get_size(hse_in);
	rsa_cipher_req->pInput = hse_buf_get_paddr(hse_in);
	rsa_cipher_req->pOutputLength = hse_buf_get_paddr(hse_out_len);
	rsa_cipher_req->pOutput = hse_buf_get_paddr(hse_out);

	res = hse_srv_req_sync(HSE_CHANNEL_ANY, &srv_desc);
	if (res != TEE_SUCCESS) {
		DMSG("HSE RSA Cipher Request failed with ret=0x%x", res);
		goto out_free_len;
	}

	hse_buf_get_data(hse_out_len, &out_len, sizeof(uint32_t), 0);
	hse_buf_get_data(hse_out, out_buf->data, out_buf->length, 0);

	/* Remove the trailing zeros. Leave one zero if output is only zeros */
	if (rsa_data->rsa_id == DRVCRYPT_RSA_NOPAD)
		while ((off < out_len - 1) && (out_buf->data[off] == 0))
			off++;

	out_buf->length = out_len - off;
	memcpy(out_buf->data, out_buf->data + off, out_buf->length);

out_free_len:
	hse_buf_free(hse_out_len);
out_free_output:
	hse_buf_free(hse_out);
out_free_input:
	hse_buf_free(hse_in);
out_erase_key:
	hse_release_and_erase_key(key_handle);
out_free_label:
	hse_buf_free(label);
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
	hseSignSrv_t *sign_req = &srv_desc.hseSrv.signReq;
	HSE_SRV_INIT(hseSignScheme_t, sign_scheme);
	TEE_Result res = TEE_SUCCESS;
	hseKeyHandle_t key_handle;
	struct hse_buf *message = NULL, *sign_len = NULL, *signature = NULL;

	res = fill_sign_sch(ssa_data, &sign_scheme);
	if (res != TEE_SUCCESS)
		goto out;

	res = (direction == HSE_AUTH_DIR_GENERATE) ?
	hse_import_keypair(ssa_data->key.key, &key_handle,
			   HSE_KF_USAGE_SIGN) :
	hse_import_pubkey(ssa_data->key.key, &key_handle,
			  HSE_KF_USAGE_VERIFY);

	if (res != TEE_SUCCESS)
		goto out;

	if (ssa_data->signature.length > UINT32_MAX ||
	    ssa_data->message.length > UINT32_MAX) {
		res = TEE_ERROR_BAD_PARAMETERS;
		goto out_erase_key;
	}

	message = hse_buf_init(ssa_data->message.data,
			       ssa_data->message.length);
	if (!message) {
		res = TEE_ERROR_OUT_OF_MEMORY;
		goto out_erase_key;
	}

	signature = hse_buf_alloc(ssa_data->signature.length);
	if (!signature) {
		res = TEE_ERROR_OUT_OF_MEMORY;
		goto out_free_message;
	}

	if (direction == HSE_AUTH_DIR_VERIFY)
		hse_buf_put_data(signature, ssa_data->signature.data,
				 ssa_data->signature.length, 0);

	sign_len = hse_buf_init(&ssa_data->signature.length, sizeof(uint32_t));
	if (!sign_len) {
		res = TEE_ERROR_OUT_OF_MEMORY;
		goto out_free_sign;
	}

	srv_desc.srvId = HSE_SRV_ID_SIGN;
	sign_req->accessMode = HSE_ACCESS_MODE_ONE_PASS;
	sign_req->streamId = 0u;
	sign_req->authDir = direction;
	sign_req->bInputIsHashed = true;
	sign_req->signScheme = sign_scheme;
	sign_req->keyHandle = key_handle;
	sign_req->sgtOption = HSE_SGT_OPTION_NONE;
	sign_req->inputLength = hse_buf_get_size(message);
	sign_req->pInput = hse_buf_get_paddr(message);
	sign_req->pSignatureLength[0] = hse_buf_get_paddr(sign_len);
	sign_req->pSignatureLength[1] = 0u;
	sign_req->pSignature[0] = hse_buf_get_paddr(signature);
	sign_req->pSignature[1] = 0u;

	res = hse_srv_req_sync(HSE_CHANNEL_ANY, &srv_desc);

	if (direction == HSE_AUTH_DIR_GENERATE)
		hse_buf_get_data(signature, ssa_data->signature.data,
				 ssa_data->signature.length, 0);

	hse_buf_free(sign_len);
out_free_sign:
	hse_buf_free(signature);
out_free_message:
	hse_buf_free(message);
out_erase_key:
	hse_release_and_erase_key(key_handle);
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
