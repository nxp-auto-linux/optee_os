/* SPDX-License-Identifier: BSD-3-Clause */
/*
 * Copyright 2022 NXP
 */

#ifndef HSE_UTIL_H
#define HSE_UTIL_H

#include <tee_api_types.h>
#include <types_ext.h>

struct hse_buf {
	uint8_t *data; /* Data buffer */
	paddr_t paddr; /* Physical address of the buffer */
	size_t size;   /* Number of bytes in the data buffer */
};

TEE_Result hse_buf_alloc(struct hse_buf *buf, size_t size);
void hse_buf_free(struct hse_buf *buf);

#endif /* HSE_UTIL_H */
