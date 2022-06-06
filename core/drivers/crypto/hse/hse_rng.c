// SPDX-License-Identifier: BSD 3-clause
/*
 * NXP HSE Driver - Hardware True Random Number Generator Support
 *
 * Copyright 2022 NXP
 */

#include <crypto/crypto.h>
#include <hse_abi.h>
#include <hse_core.h>
#include <hse_rng.h>
#include <hse_util.h>
#include <kernel/spinlock.h>
#include <rng_support.h>
#include <string.h>
#include <tee/cache.h>
#include <tee/tee_cryp_utl.h>

#define HSE_RNG_CACHE_MAX    128u /* total size of driver internal cache */

/**
 * struct hse_rng_ctx - RNG context
 * @cache: driver internal random data cache
 * @srv_desc: service descriptor used for cache refill
 * @cache_idx: current index in internal cache
 * @req_lock: spinlock used for retrieving data from cache
 *
 * The HSE Firmware will fill the cache.data buffer with random data.
 * In this regard, the contents of the cache.data from main memory must be
 * kept in sync with the contents of the system cache. The data buffer of the
 * struct hse_buf is cacheline-aligned and solely occupies the whole cache
 * line(s) so that no other data will be affected by the possible cache
 * operations performed on this memory range, nor will other cache operations
 * on neighboring data will affect these buffer's contents.
 */
struct hse_rng_ctx {
	struct hse_buf cache;
	struct hse_srv_desc srv_desc;
	unsigned int cache_idx;
	unsigned int req_lock; /* data request spinlock */
};

static struct hse_rng_ctx ctx;

/**
 * hse_rng_refill_cache - refill internal cache if below threshold
 */
static TEE_Result hse_rng_refill_cache(void)
{
	TEE_Result err;
	struct hse_buf cache = ctx.cache;

	err = hse_srv_req_sync(HSE_CHANNEL_ANY, &ctx.srv_desc);
	if (err) {
		DMSG("HSE RNG cache refill request failed: %d", err);
		return err;
	}

	/* The HSE Firmware has written the response to the service request
	 * into the main memory. Invalidate the stale data that's in the system
	 * cache so that the new data can be fetched from the main memory.
	 */
	cache_operation(TEE_CACHEINVALIDATE, cache.data, cache.size);

	ctx.cache_idx = HSE_RNG_CACHE_MAX;

	return TEE_SUCCESS;
}

/**
 * hse_rng_read - generate random bytes of data into a supplied buffer
 * @buf: destination buffer
 * @blen: number of bytes
 *
 * If possible, get random data from internal cache, otherwise trigger a
 * cache refill and wait to return the new random data.
 */
static TEE_Result hse_rng_read(void *buf, size_t blen)
{
	TEE_Result ret;
	struct hse_buf cache = ctx.cache;
	unsigned int *cache_idx = &ctx.cache_idx;
	unsigned int remlen = blen, copylen;
	uint32_t exceptions;

	exceptions = cpu_spin_lock_xsave(&ctx.req_lock);

	if (blen <= *cache_idx) {
		memcpy(buf, &cache.data[*cache_idx - blen], blen);
		*cache_idx -= blen;
	} else {
		do {
			ret = hse_rng_refill_cache();
			if (ret) {
				cpu_spin_unlock_xrestore(&ctx.req_lock,
							 exceptions);
				return ret;
			}

			copylen = MIN(remlen, *cache_idx);
			memcpy(buf, &cache.data[*cache_idx - copylen], copylen);
			*cache_idx -= copylen;

			remlen -= copylen;

		} while (remlen > 0);
	}

	cpu_spin_unlock_xrestore(&ctx.req_lock, exceptions);

	return TEE_SUCCESS;
}

/**
 * hse_rng_init - initialize RNG
 */
TEE_Result hse_rng_initialize(void)
{
	TEE_Result err;

	err = hse_buf_alloc(&ctx.cache, HSE_RNG_CACHE_MAX);
	if (err)
		return err;

	ctx.srv_desc.srv_id = HSE_SRV_ID_GET_RANDOM_NUM;
	ctx.srv_desc.rng_req.rng_class = HSE_RNG_CLASS_PTG3;
	ctx.srv_desc.rng_req.random_num_len = HSE_RNG_CACHE_MAX;
	ctx.srv_desc.rng_req.random_num = ctx.cache.paddr;

	ctx.cache_idx = 0;
	ctx.req_lock = SPINLOCK_UNLOCK;

	IMSG("HSE RNG has been initialized");
	return TEE_SUCCESS;
}

void plat_rng_init(void)
{
}

TEE_Result crypto_rng_read(void *buf, size_t blen)
{
	if (!buf)
		return TEE_ERROR_BAD_PARAMETERS;

	return hse_rng_read(buf, blen);
}

uint8_t hw_get_random_byte(void)
{
	uint8_t buf;

	hse_rng_read(&buf, 1);

	return buf;
}
