// SPDX-License-Identifier: BSD 3-clause
/*
 * NXP HSE Driver - Hardware True Random Number Generator Support
 *
 * Copyright 2022 NXP
 */

#include <crypto/crypto.h>
#include <hse_core.h>
#include <hse_interface.h>
#include <hse_mu.h>
#include <hse_services.h>
#include <kernel/spinlock.h>
#include <kernel/interrupt.h>
#include <rng_support.h>
#include <string.h>
#include <tee/cache.h>
#include <tee/tee_cryp_utl.h>

#define HSE_RNG_CACHE_MAX    1024u /* total size of driver internal cache */
#define HSE_RNG_CACHE_MIN    256u /* minimum threshold for cache refill */

/**
 * struct hse_rng_ctx - RNG context
 * @cache: driver internal random data cache
 * @cache_idx: current index in internal cache
 * @srv_desc: service descriptor used for cache refill
 * @req_lock: spinlock used for retrieving data from cache
 * @in_progress: indicates if an async request is in progress
 */
struct hse_rng_ctx {
	struct hse_buf cache;
	unsigned int cache_idx;
	hseSrvDescriptor_t srv_desc;
	unsigned int req_lock; /* data request spinlock */
	bool in_progress;
};

static struct hse_rng_ctx rng_ctx;

static inline void set_rand_size(unsigned int size)
{
	rng_ctx.srv_desc.hseSrv.getRandomNumReq.randomNumLength = size;
}

/**
 * hse_rng_sync_refill - synchronously refill internal cache
 *
 * Issue a RNG service request and wait for the response
 */
static TEE_Result hse_rng_sync_refill(unsigned int size)
{
	TEE_Result err;
	struct hse_buf cache = rng_ctx.cache;

	set_rand_size(size);
	err = hse_srv_req_sync(HSE_CHANNEL_ANY, &rng_ctx.srv_desc);
	if (err) {
		DMSG("HSE RNG cache refill sync request failed: %x", err);
		return err;
	}

	cache_operation(TEE_CACHEINVALIDATE, cache.data, cache.size);

	rng_ctx.cache_idx = size;

	return TEE_SUCCESS;
}

/**
 * hse_rng_refill_done - callback function for the asynchronous cache refill
 * @err: error code returned upon receiving HSE's response
 * @ctx: unused
 */
static void hse_rng_refill_done(TEE_Result err, void *ctx __unused)
{
	uint32_t exceptions;
	struct hse_buf cache = rng_ctx.cache;

	if (err != TEE_SUCCESS) {
		DMSG("HSE RNG cache refill callback failed: %x", err);
		return;
	}

	exceptions = cpu_spin_lock_xsave(&rng_ctx.req_lock);

	cache_operation(TEE_CACHEINVALIDATE, cache.data, cache.size);

	rng_ctx.cache_idx = HSE_RNG_CACHE_MAX;

	rng_ctx.in_progress = false;

	cpu_spin_unlock_xrestore(&rng_ctx.req_lock, exceptions);
}

/**
 * hse_rng_async_refill - asynchronously refill internal cache
 *
 * Issue a RNG service request and return.
 */
static TEE_Result hse_rng_async_refill(void)
{
	TEE_Result err;

	if (rng_ctx.in_progress)
		return TEE_SUCCESS;

	rng_ctx.in_progress = true;

	set_rand_size(HSE_RNG_CACHE_MAX);
	err = hse_srv_req_async(HSE_CHANNEL_ANY, &rng_ctx.srv_desc, NULL,
				hse_rng_refill_done);
	if (err) {
		EMSG("HSE RNG cache refill async request failed: %x", err);
		return err;
	}

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
	TEE_Result ret = TEE_SUCCESS;
	struct hse_buf cache = rng_ctx.cache;
	unsigned int *cache_idx = &rng_ctx.cache_idx;
	uint32_t exceptions;

	exceptions = cpu_spin_lock_xsave(&rng_ctx.req_lock);

	if (blen <= *cache_idx) {
		memcpy(buf, &cache.data[*cache_idx - blen], blen);
		*cache_idx -= blen;

		if (*cache_idx < HSE_RNG_CACHE_MIN)
			ret = hse_rng_async_refill();

	} else if (blen <= HSE_RNG_CACHE_MAX) {
		ret = hse_rng_async_refill();
		if (ret != TEE_SUCCESS)
			goto out;

		ret = TEE_ERROR_BUSY;

	} else {
		unsigned int remlen = blen, copylen;

		do {
			ret = hse_rng_sync_refill(HSE_RNG_CACHE_MAX);
			if (ret != TEE_SUCCESS)
				goto out;

			copylen = MIN(remlen, *cache_idx);
			memcpy(buf, &cache.data[*cache_idx - copylen], copylen);
			*cache_idx -= copylen;

			remlen -= copylen;

		} while (remlen > 0);
	}
out:
	cpu_spin_unlock_xrestore(&rng_ctx.req_lock, exceptions);
	return ret;
}

/**
 * hse_rng_init - initialize RNG
 *
 * Initialize RNG's private data and perform a sync request to
 * fill the cache with half of its MAX value due to boot time
 * considerations.
 */
TEE_Result hse_rng_initialize(void)
{
	TEE_Result err;
	hseGetRandomNumSrv_t rand_srv;

	err = hse_buf_alloc(&rng_ctx.cache, HSE_RNG_CACHE_MAX);
	if (err)
		return err;

	rand_srv.rngClass = HSE_RNG_CLASS_PTG3;
	rand_srv.pRandomNum = rng_ctx.cache.paddr;

	rng_ctx.srv_desc.srvId = HSE_SRV_ID_GET_RANDOM_NUM;
	rng_ctx.srv_desc.hseSrv.getRandomNumReq = rand_srv;

	rng_ctx.cache_idx = 0;
	rng_ctx.req_lock = SPINLOCK_UNLOCK;
	rng_ctx.in_progress = false;

	/* Perform a sync refill as secure irqs are not yet enabled */
	err = hse_rng_sync_refill(HSE_RNG_CACHE_MAX / 2);
	if (err != TEE_SUCCESS)
		return err;

	return TEE_SUCCESS;
}

void plat_rng_init(void)
{
}

TEE_Result crypto_rng_read(void *buf, size_t blen)
{
	TEE_Result ret;

	if (!buf)
		return TEE_ERROR_BAD_PARAMETERS;

	ret = hse_rng_read(buf, blen);

	while (ret == TEE_ERROR_BUSY)
		ret = hse_rng_read(buf, blen);

	return ret;
}

uint8_t hw_get_random_byte(void)
{
	uint8_t buf = 0;

	hse_rng_read(&buf, 1);

	return buf;
}
