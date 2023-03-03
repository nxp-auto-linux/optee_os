/* SPDX-License-Identifier: BSD-3-Clause */
/*
 * Copyright (C) 2023 NXP
 */

#include <tee_api_types.h>

/**
 * hse_provision_sym_key - Provisions an encrypted symmetric key into HSE's
 *                         NVM Key Catalog
 * @ctx: context of PTA's session (input)
 * @enckey: encrypted key (input)
 *
 * Imports an encrypted symmetric key into HSE's NVM Key Catalog. The
 * ciphertext key is decrypted using HSE's KEK. No other key can be used
 * to decrypt the ciphertext key. The function will return the key handle of
 * the slot where the key's been imported.
 *
 * Return: TEE_SUCCESS on success, error code based on HSE's service response
 */
TEE_Result hse_provision_sym_key(void *payload,
				 uint8_t key_group,
				 uint8_t key_slot);
