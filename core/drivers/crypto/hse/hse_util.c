// SPDX-License-Identifier: BSD-3-Clause
/*
 * Copyright 2022 NXP
 */

#include <hse_util.h>
#include <malloc.h>
#include <platform_config.h>
#include <mm/core_memprot.h>

static void *aligned_malloc(size_t size)
{
	void *ptr, *off_ptr;
	size_t extra_alignment, align = CACHELINE_ALIGN;

	if (!size)
		return NULL;

	/* Round up the size argument to the CACHELINE_ALIGN
	 * so that the buffer will take up whole line(s) of cache
	 */
	size = ROUNDUP(size, align);

	/* Make room for extra alignment bytes and for
	 * storing the actual address returned by malloc:
	 *  - 'align - 1' bytes are needded for aligning the buffer
	 *  - 'align' bytes are needed for safe-keeping the address
	 *     returned by malloc on its own cache line.
	 */
	extra_alignment = 2 * align - 1;

	ptr = malloc(size + extra_alignment);
	if (!ptr)
		return NULL;

	/* The returned pointer is aligned according to align
	 * at a maximum (2 * align - 1) offset from the original address
	 * returned by malloc
	 */
	off_ptr = (void *)ROUNDUP(((vaddr_t)ptr + align), align);

	/* The address returned by malloc is stored at a vaddr_t offset
	 * behind the aligned pointer. We need the actual pointer later
	 * when free is called
	 */
	*((vaddr_t *)off_ptr - 1) = (vaddr_t)ptr;

	return off_ptr;
}

static void aligned_free(void *ptr)
{
	vaddr_t p;

	if (!ptr)
		return;

	p = *((vaddr_t *)ptr - 1);

	free((void *)p);
}

TEE_Result hse_buf_alloc(struct hse_buf *buf, size_t size)
{
	buf->data = aligned_malloc(size);
	if (!buf->data)
		return TEE_ERROR_OUT_OF_MEMORY;

	buf->paddr = virt_to_phys(buf->data);
	if (!buf->paddr) {
		aligned_free(buf->data);
		return TEE_ERROR_NO_DATA;
	}

	buf->size = size;

	return TEE_SUCCESS;
}

void hse_buf_free(struct hse_buf *buf)
{
	aligned_free(buf->data);

	buf->data = NULL;
	buf->paddr = 0;
	buf->size = 0;
}
