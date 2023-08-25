// SPDX-License-Identifier: BSD-3-Clause
/*
 * Copyright 2022-2023 NXP
 */

#include <hse_core.h>
#include <malloc.h>
#include <platform_config.h>
#include <mm/core_memprot.h>
#include <string.h>
#include <tee/cache.h>

/**
 * struct hse_buf - HSE buffer management struct
 * @data: data buffer
 * @paddr: physical address of the buffer
 * @size: number of bytes in the data buffer
 */
struct hse_buf {
	uint8_t *data; /* Data buffer */
	paddr_t paddr; /* Physical address of the buffer */
	uint32_t size;   /* Number of bytes in the data buffer */
};

/**
 * __hse_buf_alloc - allocates a hse buffer
 * @size: size of the buffer (in bytes)
 * @zero_init: populates the buffer with zeros if true
 *
 * Buffers referenced in HSE Service Requests must be cache-aligned
 * and take over whole line(s) of cache – this is a precautionary
 * measure so that other cache operations on neighboring data would
 * not interfere with these buffers. Cache operations such as flushes/
 * invalidations are performed to ensure that the posibly cached data
 * is coherent with the main memory as HSE will fetch data from the main
 * memory upon executing the service request.
 *
 * Return: pointer to a struct hse_buf on success, NULL on error
 */
static struct hse_buf *__hse_buf_alloc(size_t size, bool zero_init)
{
	size_t alloc_size = size;
	struct hse_buf *buf = NULL;

	if (!size || size > UINT32_MAX)
		return NULL;

	buf = calloc(1, sizeof(struct hse_buf));
	if (!buf)
		goto err;

	/* Round up the size argument to the CACHELINE_ALIGN
	 * so that the buffer will take up whole line(s) of cache
	 */
	alloc_size = ROUNDUP(size, CACHELINE_ALIGN);
	buf->data = memalign(CACHELINE_ALIGN, alloc_size);
	if (!buf->data)
		goto err;

	if (zero_init) {
		memset(buf->data, 0, size);
		cache_operation(TEE_CACHEFLUSH, buf->data, size);
	}

	buf->paddr = virt_to_phys(buf->data);
	if (!buf->paddr)
		goto err;

	buf->size = (uint32_t)size;

	return buf;
err:
	if (buf) {
		free(buf->data);
		free(buf);
	}

	return NULL;
}

/**
 * hse_buf_alloc - wrapper for __hse_buf_alloc()
 * @size: size of the buffer (in bytes)
 *
 * Will allocate a 0-initialized hse buffer
 *
 * Return: pointer to a struct hse_buf on success, NULL on error
 */
struct hse_buf *hse_buf_alloc(size_t size)
{
	return __hse_buf_alloc(size, true);
}

/**
 * hse_buf_free - frees a HSE buffer
 * @buf: pointer to a struct hse_buf buffer
 *
 */
void hse_buf_free(struct hse_buf *buf)
{
	if (!buf)
		return;

	free(buf->data);
	free(buf);
}

/**
 * hse_buf_put_data - copies data into a hse buffer starting from offset
 * @buf: pointer to a struct hse_buf buffer
 * @data: data to be copied into the hse buffer
 * @size: size of data (in bytes)
 * @offset:  starting offset of hse buffer where data will be put in
 *
 * After the bytes are copied, the range (offset + size) of the buffer that has
 * been filled through this operation is flushed.
 */
TEE_Result hse_buf_put_data(struct hse_buf *buf, const void *data, size_t size,
			    size_t offset)
{
	size_t end_offset;

	if (ADD_OVERFLOW(offset, size, &end_offset))
		return TEE_ERROR_OVERFLOW;

	if (end_offset > buf->size || !data)
		return TEE_ERROR_BAD_PARAMETERS;

	memcpy(buf->data + offset, data, size);
	return cache_operation(TEE_CACHEFLUSH, buf->data + offset, size);
}

/**
 * hse_buf_get_data - copies data from a hse buffer starting from offset
 * @buf: pointer to a struct hse_buf buffer
 * @data: data to be copied from the hse buffer
 * @size: size of data
 * @offset: offset of hse buffer where data will be put in
 *
 * Before the bytes are copied into 'data', the specific range (offset + size)
 * of the buffer is invalidated.
 */
TEE_Result hse_buf_get_data(struct hse_buf *buf, void *data, size_t size,
			    size_t offset)
{
	TEE_Result res;
	size_t end_offset;

	if (ADD_OVERFLOW(offset, size, &end_offset))
		return TEE_ERROR_OVERFLOW;

	if (end_offset > buf->size || !data)
		return TEE_ERROR_BAD_PARAMETERS;

	res = cache_operation(TEE_CACHEINVALIDATE, buf->data + offset, size);
	if (res != TEE_SUCCESS)
		return res;
	memcpy(data, buf->data + offset, size);

	return TEE_SUCCESS;
}

/**
 * hse_buf_copy - copies data from a source buffer to a destination buffer
 * @src: The source buffer
 * @dst: The destination buffer
 *
 * This operation is a wrapper over memcpy
 * used to copy data of size `size` from hse_buf `dst`
 * to hse_buf `src`. It also has a few checks for the size
 * to be valid and the src and dst to be allocated
 */
TEE_Result
hse_buf_copy(struct hse_buf *src, struct hse_buf *dst, uint32_t size)
{
	if (!src || !dst)
		return TEE_ERROR_BAD_PARAMETERS;

	if (dst->size < size || src->size < size)
		return TEE_ERROR_BAD_PARAMETERS;

	if (dst->data < src->data && dst->data + size > src->data)
		return TEE_ERROR_BAD_PARAMETERS;

	if (src->data < dst->data && src->data + size > dst->data)
		return TEE_ERROR_BAD_PARAMETERS;

	cache_operation(TEE_CACHEINVALIDATE, src->data, src->size);

	memcpy(dst->data, src->data, size);

	cache_operation(TEE_CACHEFLUSH, src->data, src->size);
	cache_operation(TEE_CACHEFLUSH, dst->data, dst->size);
	return TEE_SUCCESS;
}

/**
 * hse_buf_init - allocates a hse buffer and copies data into it
 * @data: data to be copied into the hse buffer
 * @size: size of data (in bytes)
 *
 * This operation is a combination of hse_buf_alloc() + hse_buf_put_data().
 * The data is put into the buffer starting from offset 0.
 *
 * Return: pointer to a struct hse_buf on success, NULL on error
 */
struct hse_buf *hse_buf_init(const void *data, size_t size)
{
	TEE_Result res;
	struct hse_buf *buf = __hse_buf_alloc(size, false);

	if (!buf)
		return NULL;

	res = hse_buf_put_data(buf, data, size, 0);
	if (res != TEE_SUCCESS) {
		hse_buf_free(buf);
		return NULL;
	}

	return buf;
}

/**
 * hse_buf_get_size - retrieves the size of the buffer
 * @buf: pointer to a struct hse_buf
 *
 * Return: size of the buffer or 0 if the buffer is NULL
 */
uint32_t hse_buf_get_size(struct hse_buf *buf)
{
	if (buf)
		return buf->size;
	return 0;
}

/**
 * hse_buf_get_size - retrieves the physical address of the buffer
 * @buf: pointer to a struct hse_buf
 *
 * Return: physical address of the buffer or 0 if the buffer is NULL
 */
paddr_t hse_buf_get_paddr(struct hse_buf *buf)
{
	if (buf)
		return buf->paddr;
	return 0;
}

/**
 * hse_ctr_inc - in counter mode, each time a block is encrypted/decrypted,
 *               the iv is incremented by 1
 * @iv: iv
 * @blks: number of blocks that have been encrypted/decrypted during the
 *        update operation
 * @blocksize: size of the block -- 16 for AES-CTR. The iv has the size
 *             of the block size.
 */
void hse_ctr_inc(uint8_t *iv, size_t blks, size_t blocksize)
{
	for (; blks > 0; blks--)
		for (int64_t i = blocksize - 1; i >= 0; i--) {
			iv[i] = (iv[i] + 1) & 0xff;
			if (iv[i])
				break;
		}
}
