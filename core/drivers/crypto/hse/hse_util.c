// SPDX-License-Identifier: BSD-3-Clause
/*
 * Copyright 2022 NXP
 */

#include <hse_util.h>
#include <malloc.h>
#include <platform_config.h>
#include <mm/core_memprot.h>

TEE_Result hse_buf_alloc(struct hse_buf *buf, size_t size)
{
	size_t alloc_size = size;

	if (!buf || !size)
		return TEE_ERROR_BAD_PARAMETERS;

	/* Round up the size argument to the CACHELINE_ALIGN
	 * so that the buffer will take up whole line(s) of cache
	 */
	alloc_size = ROUNDUP(size, CACHELINE_ALIGN);

	buf->data = memalign(CACHELINE_ALIGN, alloc_size);
	if (!buf->data)
		return TEE_ERROR_OUT_OF_MEMORY;

	buf->paddr = virt_to_phys(buf->data);
	if (!buf->paddr) {
		free(buf->data);
		return TEE_ERROR_NO_DATA;
	}

	buf->size = size;

	return TEE_SUCCESS;
}

void hse_buf_free(struct hse_buf *buf)
{
	if (!buf)
		return;

	free(buf->data);

	buf->data = NULL;
	buf->paddr = 0;
	buf->size = 0;
}
