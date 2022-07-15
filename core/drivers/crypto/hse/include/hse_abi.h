/* SPDX-License-Identifier: BSD-3-Clause */
/*
 * Copyright 2022 NXP
 */

#ifndef HSE_ABI_H
#define HSE_ABI_H

#include <util.h>

#define HSE_SRV_DESC_MAX_SIZE    256u /* maximum service descriptor size */

#define HSE_KEY_CATALOG_ID_RAM    2u /* RAM key catalog ID */

#define HSE_KEY_HANDLE(group, slot)    ((HSE_KEY_CATALOG_ID_RAM << 16u) |      \
					((group) << 8u) | (slot))

#define HSE_INVALID_KEY_HANDLE    0xFFFFFFFFul /* invalid key handle */

/**
 * enum hse_status - HSE status
 * @HSE_STATUS_RNG_INIT_OK: RNG initialization successfully completed
 * @HSE_STATUS_INIT_OK: HSE initialization successfully completed
 * @HSE_STATUS_INSTALL_OK: HSE installation phase successfully completed,
 *                         key stores have been formatted and can be used
 * @HSE_STATUS_PUBLISH_SYS_IMAGE: volatile HSE configuration detected
 */
enum hse_status {
	HSE_STATUS_RNG_INIT_OK = BIT(5),
	HSE_STATUS_INIT_OK = BIT(8),
	HSE_STATUS_INSTALL_OK = BIT(9),
	HSE_STATUS_PUBLISH_SYS_IMAGE = BIT(13),
};

/**
 * enum hse_srv_response - HSE service response
 * @HSE_SRV_RSP_OK: service successfully executed with no error
 * @HSE_SRV_RSP_VERIFY_FAILED: authentication tag/signature verification failed
 * @HSE_SRV_RSP_INVALID_ADDR: invalid service descriptor address parameters
 * @HSE_SRV_RSP_INVALID_PARAM: invalid service descriptor request parameters
 * @HSE_SRV_RSP_NOT_SUPPORTED: operation or feature not supported
 * @HSE_SRV_RSP_NOT_ALLOWED: operation subject to restrictions (in attributes,
 *                           life-cycle dependent operations, key-management)
 * @HSE_SRV_RSP_NOT_ENOUGH_SPACE: not enough space to perform the service
 * @HSE_SRV_RSP_READ_FAILURE: service request failed, read access denied
 * @HSE_SRV_RSP_WRITE_FAILURE: service request failed, write access denied
 * @HSE_SRV_RSP_STREAMING_MODE_FAILURE: service request in streaming mode failed
 * @HSE_SRV_RSP_KEY_NOT_AVAILABLE: key locked due to failed boot measurement or
 *                                 an active debugger
 * @HSE_SRV_RSP_KEY_INVALID: the key flags don't match the crypto operation
 * @HSE_SRV_RSP_KEY_EMPTY: specified key slot empty
 * @HSE_SRV_RSP_KEY_WRITE_PROTECTED: key slot write protected
 * @HSE_SRV_RSP_KEY_UPDATE_ERROR: specified key slot cannot be updated due to
 *                                errors in verification of the parameters
 * @HSE_SRV_RSP_MEMORY_FAILURE: physical errors (e.g. flipped bits) detected
 *                              during memory read or write
 * @HSE_SRV_RSP_CANCEL_FAILURE: service cannot be canceled
 * @HSE_SRV_RSP_CANCELED: service has been canceled
 * @HSE_SRV_RSP_GENERAL_ERROR: error not covered by the error codes above
 */
enum hse_srv_response {
	HSE_SRV_RSP_OK = 0x55A5AA33ul,
	HSE_SRV_RSP_VERIFY_FAILED = 0x55A5A164ul,
	HSE_SRV_RSP_INVALID_ADDR = 0x55A5A26Aul,
	HSE_SRV_RSP_INVALID_PARAM = 0x55A5A399ul,
	HSE_SRV_RSP_NOT_SUPPORTED = 0xAA55A11Eul,
	HSE_SRV_RSP_NOT_ALLOWED = 0xAA55A21Cul,
	HSE_SRV_RSP_NOT_ENOUGH_SPACE = 0xAA55A371ul,
	HSE_SRV_RSP_READ_FAILURE = 0xAA55A427ul,
	HSE_SRV_RSP_WRITE_FAILURE = 0xAA55A517ul,
	HSE_SRV_RSP_STREAMING_MODE_FAILURE = 0xAA55A6B1ul,
	HSE_SRV_RSP_KEY_NOT_AVAILABLE = 0xA5AA51B2ul,
	HSE_SRV_RSP_KEY_INVALID = 0xA5AA52B4ul,
	HSE_SRV_RSP_KEY_EMPTY = 0xA5AA5317ul,
	HSE_SRV_RSP_KEY_WRITE_PROTECTED = 0xA5AA5436ul,
	HSE_SRV_RSP_KEY_UPDATE_ERROR = 0xA5AA5563ul,
	HSE_SRV_RSP_MEMORY_FAILURE = 0x33D6D136ul,
	HSE_SRV_RSP_CANCEL_FAILURE = 0x33D6D261ul,
	HSE_SRV_RSP_CANCELED = 0x33D6D396ul,
	HSE_SRV_RSP_GENERAL_ERROR = 0x33D6D4F1ul,
};

/**
 * enum hse_srv_id - HSE service ID
 * @HSE_SRV_ID_GET_ATTR: get attribute, such as firmware version
 */
enum hse_srv_id {
	HSE_SRV_ID_GET_ATTR = 0x00A50002ul,
	HSE_SRV_ID_GET_RANDOM_NUM = 0x00000300ul,
	HSE_SRV_ID_IMPORT_KEY = 0x00000104ul,
	HSE_SRV_ID_SYM_CIPHER = 0x00A50203ul,
};

/**
 * enum hse_srv_access_mode - HSE access modes
 * @HSE_ACCESS_MODE_ONE_PASS: ONE-PASS access mode
 * @HSE_ACCESS_MODE_START: START access mode
 * @HSE_ACCESS_MODE_UPDATE: UPDATE access mode
 * @HSE_ACCESS_MODE_FINISH: FINISH access mode
 */
enum hse_srv_access_mode {
	HSE_ACCESS_MODE_ONE_PASS = 0u,
	HSE_ACCESS_MODE_START = 1u,
	HSE_ACCESS_MODE_UPDATE = 2u,
	HSE_ACCESS_MODE_FINISH = 3u,
};

/**
 * enum hse_attr - HSE attribute
 * @HSE_FW_VERSION_ATTR_ID: firmware version
 */
enum hse_attr {
	HSE_FW_VERSION_ATTR_ID = 1u,
};

/**
 * enum hse_key_type - key types used by HSE
 * @HSE_KEY_TYPE_AES: AES 128, 192 or 256-bit key
 * @HSE_KEY_TYPE_HMAC: Symmetric HMAC key
 * @HSE_KEY_TYPE_SHARED_SECRET: Shared Secret key, used for derivation
 */
enum hse_key_type {
	HSE_KEY_TYPE_AES = 0x12u,
	HSE_KEY_TYPE_HMAC = 0x20u,
	HSE_KEY_TYPE_SHARED_SECRET = 0x30u,
};

/**
 * enum hse_rng_class - random number generation method
 * @HSE_RNG_CLASS_PTG3: prediction resistance, reseed every 16 bytes
 */
enum hse_rng_class {
	HSE_RNG_CLASS_PTG3 = 2u,
};

/**
 * enum hse_cipher_algorithm - supported cipher algorithm types
 * @HSE_CIPHER_ALGO_AES: AES cipher
 */
enum hse_cipher_algorithm {
	HSE_CIPHER_ALGO_AES = 0x10u,
};

/**
 * enum hse_block_mode - supported symmetric cipher block modes
 * @HSE_CIPHER_BLOCK_MODE_CTR: counter mode
 * @HSE_CIPHER_BLOCK_MODE_CBC: cipher block chaining mode
 * @HSE_CIPHER_BLOCK_MODE_ECB: electronic codebook mode
 * @HSE_CIPHER_BLOCK_MODE_CFB: cipher feedback mode
 */
enum hse_block_mode {
	HSE_CIPHER_BLOCK_MODE_CTR = 1u,
	HSE_CIPHER_BLOCK_MODE_CBC = 2u,
	HSE_CIPHER_BLOCK_MODE_ECB = 3u,
	HSE_CIPHER_BLOCK_MODE_CFB = 4u,
};

/**
 * enum hse_key_flags - key properties
 * @HSE_KF_USAGE_ENCRYPT: key used for encryption (and AEAD tag computation)
 * @HSE_KF_USAGE_DECRYPT: key used for decryption (and AEAD tag verification)
 * @HSE_KF_USAGE_SIGN: key used for message authentication code/tag generation
 */
enum hse_key_flags {
	HSE_KF_USAGE_ENCRYPT = BIT(0),
	HSE_KF_USAGE_DECRYPT = BIT(1),
	HSE_KF_USAGE_SIGN = BIT(2),
};

/**
 * enum hse_cipher_dir - symmetric cipher direction
 * @HSE_CIPHER_DIR_DECRYPT: decrypt
 * @HSE_CIPHER_DIR_ENCRYPT: encrypt
 */
enum hse_cipher_dir {
	HSE_CIPHER_DIR_DECRYPT = 0u,
	HSE_CIPHER_DIR_ENCRYPT = 1u,
};

/**
 * enum hse_sgt_opt - scatter-gather table option
 * @HSE_SGT_OPT_NONE: scatter-gather tables are not used
 * @HSE_SGT_OPT_INPUT: input provided as scatter-gather table
 * @HSE_SGT_OPT_OUTPUT: output provided as scatter-gather table
 */
enum hse_sgt_opt {
	HSE_SGT_OPT_NONE = 0u,
	HSE_SGT_OPT_INPUT = BIT(0),
	HSE_SGT_OPT_OUTPUT = BIT(1),
};

/**
 * struct hse_skcipher_srv - symmetric key cipher encryption/decryption
 * @access_mode: only ONE-PASS mode supported
 * @cipher_algo: cipher algorithm
 * @block_mode: cipher block mode
 * @cipher_dir: direction - encrypt/decrypt from &enum hse_cipher_dir
 * @sgt_opt: specify whether input/output is provided as scatter-gather table
 * @key_handle: RAM catalog key handle
 * @iv: address of the initialization vector/nonce. Ignored for NULL and ECB
 *      block modes
 * @input_len: plaintext/ciphertext length, in bytes. For ECB, CBC and CFB
 *             cipher block modes, must be a multiple of block length
 * @input: address of the plaintext for encryption, or ciphertext for decryption
 * @output: address of ciphertext for encryption or plaintext for decryption
 *
 * To perform encryption/decryption with a block cipher in ECB or CBC mode, the
 * length of the input must be an exact multiple of the block size. For all AES
 * variants it is 16 bytes (128 bits). If the input plaintext is not an exact
 * multiple of block size, it must be padded by application. For other modes,
 * such as counter mode (CTR) or OFB or CFB, padding is not required. In these
 * cases, the ciphertext is always the same length as the plaintext.
 */
struct hse_cipher_srv {
	uint8_t access_mode;
	uint8_t reserved0[1];
	uint8_t cipher_algo;
	uint8_t block_mode;
	uint8_t cipher_dir;
	uint8_t sgt_opt;
	uint8_t reserved1[2];
	uint32_t key_handle;
	uint64_t iv;
	uint32_t input_len;
	uint64_t input;
	uint64_t output;
} __packed;

/**
 * struct hse_import_key_srv - import/update key into a key store
 * @key_handle: key slot to update
 * @key_info: address of associated hse_key_info struct (specifying usage
 *            flags, access restrictions, key length in bits, etc.)
 * @sym.key: address of symmetric key
 * @sym.keylen: symmetric key length in bytes
 * @cipher_key: unused, must be set to HSE_INVALID_KEY_HANDLE
 * @auth_key: unused, must be set to HSE_INVALID_KEY_HANDLE
 *
 * Key buffers and information must be located in the 32-bit address range.
 */
struct hse_import_key_srv {
	uint32_t key_handle;
	uint64_t key_info;
	struct {
		uint8_t reserved0[16];
		uint64_t key;
		uint8_t reserved1[4];
		uint16_t keylen;
		uint8_t reserved2[2];
	} __packed sym;
	uint32_t cipher_key;
	uint8_t reserved3[48];
	uint32_t auth_key;
	uint8_t reserved4[36];
} __packed;

/**
 * struct hse_attr_fw_version - firmware version
 * @fw_type: attribute ID
 * @major: major revision
 * @minor: minor revision
 * @patch: patch version
 */
struct hse_attr_fw_version {
	uint8_t reserved[2];
	uint16_t fw_type;
	uint8_t major;
	uint8_t minor;
	uint16_t patch;
} __packed;

/**
 * struct hse_get_attr_srv - get attribute, such as firmware version
 * @attr_id: attribute ID
 * @attr_len: attribute length, in bytes
 * @attr: DMA address of the attribute
 */
struct hse_get_attr_srv {
	uint16_t attr_id;
	uint8_t reserved[2];
	uint32_t attr_len;
	uint64_t attr;
} __packed;

/**
 * struct hse_rng_srv - random number generation
 * @rng_class: random number generation method
 * @random_num_len: length of the generated number in bytes
 * @random_num: the address where the generated number will be stored
 */
struct hse_rng_srv {
	uint8_t rng_class;
	uint8_t reserved[3];
	uint32_t random_num_len;
	uint64_t random_num;
} __packed;

struct hse_srv_desc {
	uint32_t srv_id;
	uint8_t reserved[4];
	union {
		struct hse_get_attr_srv get_attr_req;
		struct hse_rng_srv rng_req;
		struct hse_cipher_srv cipher_req;
		struct hse_import_key_srv import_key_req;
	};
} __packed;

/**
 * struct hse_key_info - key properties
 * @key_flags: the targeted key flags; see &enum hse_key_flags
 * @key_bit_len: length of the key in bits
 * @key_type: targeted key type; see &enum hse_key_type
 */
struct hse_key_info {
	uint16_t key_flags;
	uint16_t key_bit_len;
	uint8_t reserved0[8];
	uint8_t key_type;
	uint8_t reserved1[3];
} __packed;

#endif /* HSE_ABI_H */
