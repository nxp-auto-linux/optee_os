/* SPDX-License-Identifier: BSD-3-Clause */
/*
 * Copyright 2022 NXP
 */

#ifndef HSE_SERVICES_H
#define HSE_SERVICES_H

#include <tee_api_types.h>

/* Cipher Services */
TEE_Result hse_cipher_register(void);

/* HUK Services */
TEE_Result hse_retrieve_huk(void);

/* RNG Services */
TEE_Result hse_rng_initialize(void);

#endif /* HSE_SERVICES_H */
