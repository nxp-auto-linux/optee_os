// SPDX-License-Identifier: BSD-3-Clause
/*
 * NXP HSE Driver - Messaging Unit Interface
 *
 * This file contains the interface implementation for the Messaging Unit
 * instance used by host application cores to request services from HSE.
 *
 * Copyright 2022 NXP
 */

#include <bitstring.h>
#include <hse_dt.h>
#include <hse_mu.h>
#include <io.h>
#include <malloc.h>
#include <mm/core_memprot.h>
#include <kernel/spinlock.h>
#include <trace.h>

/**
 * struct hse_mu_regs - HSE Messaging Unit Registers
 * @ver: Version ID Register, offset 0x0
 * @par: Parameter Register, offset 0x4
 * @cr: Control Register, offset 0x8
 * @sr: Status Register, offset 0xC
 * @fcr: Flag Control Register, offset 0x100
 * @fsr: Flag Status Register, offset 0x104
 * @gier: General Interrupt Enable Register, offset 0x110
 * @gcr: General Control Register, offset 0x114
 * @gsr: General Status Register, offset 0x118
 * @tcr: Transmit Control Register, offset 0x120
 * @tsr: Transmit Status Register, offset 0x124
 * @rcr: Receive Control Register, offset 0x128
 * @rsr: Receive Status Register, offset 0x12C
 * @tr[n]: Transmit Register n, offset 0x200 + 4*n
 * @rr[n]: Receive Register n, offset 0x280 + 4*n
 */
struct hse_mu_regs {
	const uint32_t ver;
	const uint32_t par;
	uint32_t cr;
	uint32_t sr;
	uint8_t reserved0[240]; /* 0xF0 */
	uint32_t fcr;
	const uint32_t fsr;
	uint8_t reserved1[8]; /* 0x8 */
	uint32_t gier;
	uint32_t gcr;
	uint32_t gsr;
	uint8_t reserved2[4]; /* 0x4 */
	uint32_t tcr;
	const uint32_t tsr;
	uint32_t rcr;
	const uint32_t rsr;
	uint8_t reserved3[208]; /* 0xD0 */
	uint32_t tr[16];
	uint8_t reserved4[64]; /* 0x40 */
	const uint32_t rr[16];
};

/**
 * struct hse_mu_data - MU interface private data
 * @regs: MU instance register space base virtual address
 * @desc_base_ptr: descriptor space base virtual address
 * @desc_base_dma: descriptor space base DMA address
 */
struct hse_mu_data {
	struct hse_mu_regs *regs;
	void *desc_base_ptr;
	paddr_t desc_base_dma;
};

/**
 * hse_ioread32 - read from a 32-bit MU register
 * @addr: address of the register to read from
 *
 * Return: value of read register
 */
static uint32_t hse_ioread32(const uint32_t *addr)
{
	return io_read32((vaddr_t)addr);
}

/**
 * hse_iowrite32 - write value to a 32-bit MU register
 * @addr: address of the register to write to
 * @val: value to write
 *
 */
static void hse_iowrite32(const uint32_t *addr, uint32_t val)
{
	io_write32((vaddr_t)addr, val);
}

/**
 * hse_mu_check_status - check the HSE global status
 * @mu: MU instance handle
 *
 * Return: 16 MSB of MU instance FSR
 */
uint16_t hse_mu_check_status(void *mu)
{
	struct hse_mu_data *priv = mu;
	uint32_t fsrval;

	if (!mu)
		return 0;

	fsrval = hse_ioread32(&priv->regs->fsr);
	fsrval = (fsrval & HSE_STATUS_MASK) >> 16u;

	return (uint16_t)fsrval;
}

/**
 * hse_mu_check_event - check for HSE system events
 * @mu: MU instance handle
 *
 * Return: HSE system event mask
 */
TEE_Result hse_mu_check_event(void *mu, uint32_t *val)
{
	struct hse_mu_data *priv = mu;

	if (!mu)
		return TEE_ERROR_BAD_PARAMETERS;

	*val = hse_ioread32(&priv->regs->gsr);

	return TEE_SUCCESS;
}

/**
 * hse_mu_irq_disable - disable a specific type of interrupt using a mask
 * @mu: MU instance handle
 * @irq_type: interrupt type
 * @irq_mask: interrupt mask
 */
static void hse_mu_irq_disable(void *mu, enum hse_irq_type irq_type,
			       uint32_t irq_mask)
{
	struct hse_mu_data *priv = mu;
	void *regaddr;

	switch (irq_type) {
	case HSE_INT_ACK_REQUEST:
		regaddr = &priv->regs->tcr;
		irq_mask &= HSE_CH_MASK_ALL;
		break;
	case HSE_INT_RESPONSE:
		regaddr = &priv->regs->rcr;
		irq_mask &= HSE_CH_MASK_ALL;
		break;
	case HSE_INT_SYS_EVENT:
		regaddr = &priv->regs->gier;
		irq_mask &= HSE_EVT_MASK_ALL;
		break;
	default:
		return;
	}

	hse_iowrite32(regaddr, hse_ioread32(regaddr) & ~irq_mask);
}

/**
 * hse_mu_channel_available - check service channel status
 * @mu: MU instance handle
 * @channel: channel index
 *
 * The 16 LSB of MU instance FSR are used by HSE for signaling channel status
 * as busy after a service request has been sent, until the HSE reply is ready.
 *
 * Return: true for channel available, false for invalid index or channel busy
 */
static bool hse_mu_channel_available(void *mu, uint8_t channel)
{
	struct hse_mu_data *priv = mu;
	uint32_t fsrval, tsrval, rsrval;

	if (channel >= HSE_NUM_CHANNELS)
		return false;

	fsrval = hse_ioread32(&priv->regs->fsr) & BIT(channel);
	tsrval = hse_ioread32(&priv->regs->tsr) & BIT(channel);
	rsrval = hse_ioread32(&priv->regs->rsr) & BIT(channel);

	if (fsrval || !tsrval || rsrval)
		return false;

	return true;
}

/**
 * hse_mu_next_pending_channel - find the next channel with pending message
 * @mu: MU instance handle
 *
 * Return: channel index, HSE_CHANNEL_INV if no message pending
 */
uint8_t hse_mu_next_pending_channel(void *mu)
{
	struct hse_mu_data *priv = mu;
	void *rsr_ptr;
	uint32_t rsrval;
	int v;

	if (!mu)
		return HSE_CHANNEL_INV;

	rsrval = hse_ioread32(&priv->regs->rsr) & HSE_CH_MASK_ALL;
	rsr_ptr = &rsrval;

	bit_ffs(rsr_ptr, 32, &v);
	if (v < 0)
		return HSE_CHANNEL_INV;

	return v;
}

/**
 * hse_mu_msg_pending - check if a service request response is pending
 * @mu: MU instance handle
 * @channel: channel index
 *
 * Return: true for response ready, false otherwise
 */
bool hse_mu_msg_pending(void *mu, uint8_t channel)
{
	struct hse_mu_data *priv = mu;
	uint32_t rsrval;

	if (!mu || channel >= HSE_NUM_CHANNELS)
		return false;

	rsrval = hse_ioread32(&priv->regs->rsr) & BIT(channel);
	if (!rsrval)
		return false;

	return true;
}

/**
 * hse_mu_msg_send - send a message over MU (non-blocking)
 * @mu: MU instance handle
 * @channel: channel index
 * @msg: input message
 *
 * Return: 0 on success, TEE_ERROR_BAD_PARAMETERS for invalid channel or mu,
 *         TEE_ERROR_BUSY for selected channel busy
 */
TEE_Result hse_mu_msg_send(void *mu, uint8_t channel, uint32_t msg)
{
	struct hse_mu_data *priv = mu;

	if (!mu)
		return TEE_ERROR_BAD_PARAMETERS;

	if (channel >= HSE_NUM_CHANNELS)
		return TEE_ERROR_BAD_PARAMETERS;

	if (!hse_mu_channel_available(mu, channel)) {
		DMSG("channel %d busy\n", channel);
		return TEE_ERROR_BUSY;
	}

	hse_iowrite32(&priv->regs->tr[channel], msg);

	return 0;
}

/**
 * hse_mu_msg_recv - read a message received over MU (non-blocking)
 * @mu: MU instance handle
 * @channel: channel index
 * @msg: output message
 *
 * Return: 0 on success, TEE_ERROR_BAD_PARAMETERS for invalid channel or mu,
 *         TEE_ERROR_NO_DATA if no pending message is available
 */
TEE_Result hse_mu_msg_recv(void *mu, uint8_t channel, uint32_t *msg)
{
	struct hse_mu_data *priv = mu;

	if (!mu || !msg)
		return TEE_ERROR_BAD_PARAMETERS;

	if (channel >= HSE_NUM_CHANNELS)
		return TEE_ERROR_BAD_PARAMETERS;

	if (!hse_mu_msg_pending(mu, channel)) {
		DMSG("no message pending on channel %d\n", channel);
		return TEE_ERROR_NO_DATA;
	}

	*msg = hse_ioread32(&priv->regs->rr[channel]);

	return 0;
}

void *hse_mu_desc_base_ptr(void *mu)
{
	struct hse_mu_data *priv = mu;

	if (!mu)
		return NULL;

	return priv->desc_base_ptr;
}

paddr_t hse_mu_desc_base_dma(void *mu)
{
	struct hse_mu_data *priv = mu;

	if (!mu)
		return 0;

	return priv->desc_base_dma;
}

/**
 * hse_mu_space_map - map the physical address space to virtual addresses
 * @base: base physical address
 * @len: length of the physical space
 *
 * Return: starting virtual address on success, NULL on error
 */
static void *hse_mu_space_map(paddr_t base, size_t len)
{
	void *space = NULL;

	space = phys_to_virt_io(base);
	if (!space) {
		if (!core_mmu_add_mapping(MEM_AREA_IO_SEC, base, len)) {
			EMSG("Unable to map HSE_MU Space");
			return NULL;
		}

		space = phys_to_virt_io(base);
		if (!space) {
			EMSG("Unable to get the MU Base address");
			return NULL;
		}
	}

	return space;
}

/**
 * hse_mu_init - initial setup of MU interface
 *
 * Return: MU instance handle on success, NULL otherwise
 */
void *hse_mu_init(void)
{
	struct hse_mu_data *mu = NULL;
	uint8_t channel;
	uint32_t msg;
	int err;
	paddr_t regs_base, desc_base;
	size_t regs_size, desc_size;

	mu = malloc(sizeof(*mu));
	if (!mu) {
		EMSG("Could not malloc");
		return NULL;
	}

	err = hse_dt_get_regs(&regs_base, &regs_size, &desc_base, &desc_size);
	if (err) {
		EMSG("Failed to parse \"regs\" properties from the DT");
		return NULL;
	}
	mu->regs = hse_mu_space_map(regs_base, regs_size);
	if (!mu->regs)
		return NULL;

	mu->desc_base_ptr = hse_mu_space_map(desc_base, desc_size);
	if (!mu->desc_base_ptr)
		return NULL;

	mu->desc_base_dma = desc_base;

	hse_mu_irq_disable(mu, HSE_INT_ACK_REQUEST, HSE_CH_MASK_ALL);
	hse_mu_irq_disable(mu, HSE_INT_RESPONSE, HSE_CH_MASK_ALL);
	hse_mu_irq_disable(mu, HSE_INT_SYS_EVENT, HSE_EVT_MASK_ALL);

	/* discard any pending messages */
	for (channel = 0; channel < HSE_NUM_CHANNELS; channel++)
		if (hse_mu_msg_pending(mu, channel)) {
			err = hse_mu_msg_recv(mu, channel, &msg);
			if (!err)
				IMSG("channel %d: msg %08x dropped\n",
				     channel, msg);
		}

	return mu;
}
