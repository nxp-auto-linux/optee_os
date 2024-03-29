/* SPDX-License-Identifier: BSD-3-Clause */
/*
 * Copyright 2023 NXP
 */

#include <hse_interface.h>

#define HSE_NVM_KEK_GROUP	HSE_NVM_AES_GROUP
#define HSE_NVM_KEK_HANDLE	GET_KEY_HANDLE(HSE_KEY_CATALOG_ID_NVM, \
					       HSE_NVM_KEK_GROUP, 0)

#define HSE_NVM_AES_GROUP	1
#define HSE_NVM_AES_KEY1	GET_KEY_HANDLE(HSE_KEY_CATALOG_ID_NVM, \
					       HSE_NVM_AES_GROUP, 1)
#define HSE_NVM_AES_KEY2	GET_KEY_HANDLE(HSE_KEY_CATALOG_ID_NVM, \
					       HSE_NVM_AES_GROUP, 2)

#define HSE_NVM_HMAC_GROUP	2
#define HSE_NVM_HMAC_KEY0	GET_KEY_HANDLE(HSE_KEY_CATALOG_ID_NVM, \
					       HSE_NVM_HMAC_GROUP, 0)
#define HSE_NVM_HMAC_KEY1	GET_KEY_HANDLE(HSE_KEY_CATALOG_ID_NVM, \
					       HSE_NVM_HMAC_GROUP, 1)

#define HSE_NVM_SYM_KEYS	{ HSE_NVM_AES_KEY1, HSE_NVM_AES_KEY2, \
				  HSE_NVM_HMAC_KEY0, HSE_NVM_HMAC_KEY1 }

#define HSE_GCM_TAG_SIZE	16
#define HSE_GCM_IV_SIZE		12
#define HSE_SYM_KEY_SIZE	64

struct hse_kp_payload {
	hseKeyInfo_t key_info;
	uint8_t tag[HSE_GCM_TAG_SIZE];
	uint8_t iv[HSE_GCM_IV_SIZE];
	uint32_t enckey_size;
	uint8_t enckey[HSE_SYM_KEY_SIZE];
};
