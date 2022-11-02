/* SPDX-License-Identifier: BSD-3-Clause */
/*
 * NXP HSE Driver - Messaging Unit Interface
 *
 * This file defines the interface specification for the Messaging Unit
 * instance used by host application cores to request services from HSE.
 *
 * Copyright 2022 NXP
 */

#ifndef HSE_MU_H
#define HSE_MU_H

#include <kernel/interrupt.h>
#include <stdlib.h>
#include <types_ext.h>
#include <tee_api_types.h>

#define HSE_CHANNEL_INV    0xFFu /* invalid acquired service channel index */
#define HSE_CH_MASK_ALL    0x0000FFFFul /* all available channels irq mask */

#define HSE_STATUS_MASK    0xFFFF0000ul /* HSE global status FSR mask */

#define HSE_EVT_MASK_ERR     0x000000FFul /* fatal error GSR mask */
#define HSE_EVT_MASK_WARN    0x0000FF00ul /* warning GSR mask */
#define HSE_EVT_MASK_INTL    0xFFFF0000ul /* NXP internal flags GSR mask */
#define HSE_EVT_MASK_ALL     0xFFFFFFFFul /* all events GSR mask */

/**
 * enum hse_irq_type - HSE interrupt type
 * @HSE_INT_ACK_REQUEST: TX Interrupt, triggered when HSE acknowledged the
 *                       service request and released the service channel
 * @HSE_INT_RESPONSE: RX Interrupt, triggered when HSE wrote the response
 * @HSE_INT_SYS_EVENT: General Purpose Interrupt, triggered when HSE sends
 *                     a system event, generally an error notification
 */
enum hse_irq_type {
	HSE_INT_ACK_REQUEST = 0u,
	HSE_INT_RESPONSE = 1u,
	HSE_INT_SYS_EVENT = 2u,
};

void *hse_mu_init(void);
static inline void hse_mu_free(void *mu)
{
	free(mu);
}

TEE_Result hse_mu_msg_recv(void *mu, uint8_t channel, uint32_t *msg);
TEE_Result hse_mu_msg_send(void *mu, uint8_t channel, uint32_t msg);

uint16_t hse_mu_check_status(void *mu);
TEE_Result hse_mu_check_event(void *mu, uint32_t *val);

uint8_t hse_mu_next_pending_channel(void *mu);
bool hse_mu_msg_pending(void *mu, uint8_t channel);

void *hse_mu_desc_base_ptr(void *mu);
paddr_t hse_mu_desc_base_dma(void *mu);

#endif /* HSE_MU_H */
