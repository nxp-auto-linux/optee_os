// SPDX-License-Identifier: BSD-3-Clause
/*
 * Copyright 2020, 2022 NXP
 */

#include <drivers/s32_uart.h>
#include <io.h>
#include <util.h>

/* LINFLEXD REGISTERS */
#define LINCR1  0x00
#define LINIER  0x04
#define LINSR   0x08
#define LINESR  0x0C
#define UARTCR  0x10
#define UARTSR  0x14
#define LINTCSR 0x18
#define LINOCR  0x1C
#define LINTOCR 0x20
#define LINFBRR 0x24
#define LINIBRR 0x28
#define LINCFR  0x2C
#define LINCR2  0x30
#define BIDR    0x34
#define BDRL    0x38
#define BDRM    0x3C
#define GCR     0x4C
#define UARTPTO 0x50
#define UARTCTO 0x54
#define DMATXE  0x58
#define DMARXE  0x5C

/* USEFUL REGISTER FIELDS */
#define LINCR1_INIT		BIT(0)
#define LINCR1_MME		BIT(4)
#define LINSR_LINS_INITMODE	(0x00001000)
#define LINSR_LINS_MASK		(0x0000F000)
#define UARTCR_UART		BIT(0)
#define UARTCR_WL0		BIT(1)
#define UARTCR_PC0		BIT(3)
#define UARTCR_TXEN		BIT(4)
#define UARTCR_RXEN		BIT(5)
#define UARTCR_PC1		BIT(6)
#define UARTCR_TFBM		BIT(8)
#define UARTCR_RFBM		BIT(9)
#define UARTSR_DTFTFF		BIT(1)
#define UARTSR_DRFRFE		BIT(2)
#define UARTSR_RMB		BIT(9)
#define UARTCR_ROSE		BIT(23)
#define UARTCR_OSR_MASK		(0xF << 24)
#define UARTCR_OSR(uartcr)	(((uartcr) \
				 & UARTCR_OSR_MASK) >> 24)

#define LDIV_MULTIPLIER		(16)

static int s32_uart_read32(vaddr_t base, uint32_t off, uint32_t *res)
{
	vaddr_t addr;

	if (ADD_OVERFLOW(base, off, &addr))
		return -1;

	*res = io_read32(addr);
	return 0;
}

static int s32_uart_write32(vaddr_t base, uint32_t off, uint32_t val)
{
	vaddr_t addr;

	if (ADD_OVERFLOW(base, off, &addr))
		return -1;

	io_write32(addr, val);
	return 0;
}

static int s32_uart_write8(vaddr_t base, uint32_t off, int ch)
{
	vaddr_t addr;
	uint8_t ch8;

	if (ADD_OVERFLOW(base, off, &addr))
		return -1;

	if (ch < 0 || ch > UCHAR_MAX)
		return -1;

	ch8 = (uint8_t)ch;
	io_write8(addr, ch8);

	return 0;
}

static void s32_uart_flush(struct serial_chip *chip __unused)
{
}

static void s32_uart_putc(struct serial_chip *chip, int ch)
{
	struct s32_uart_data *pd;
	vaddr_t base;
	uint32_t uartsr, uartcr;
	int ret;

	if (!chip)
		return;

	pd = container_of(chip, struct s32_uart_data, chip);
	base = io_pa_or_va(&pd->base, pd->len);

	ret = s32_uart_read32(base, UARTCR, &uartcr);
	if (ret < 0)
		return;

	/* UART is in FIFO mode */
	if ((uartcr & UARTCR_TFBM)) {
		do {
			ret = s32_uart_read32(base, UARTSR, &uartsr);
			if (ret < 0)
				return;
		} while (uartsr & UARTSR_DTFTFF);

		s32_uart_write8(base, BDRL, ch);

	/* UART is in Buffer mode */
	} else {
		ret = s32_uart_write8(base, BDRL, ch);
		if (ret < 0)
			return;

		do {
			ret = s32_uart_read32(base, UARTSR, &uartsr);
			if (ret < 0)
				return;
		} while (!(uartsr & UARTSR_DTFTFF));

		/* In Buffer Mode the DTFTFF bit of UARTSR register
		 * has to be cleared in software
		 */
		uartsr &= ~(UARTSR_DTFTFF);
		s32_uart_write32(base, UARTSR, uartsr);
	}
}

static const struct serial_ops s32_uart_ops = {
	.flush = s32_uart_flush,
	.putc = s32_uart_putc,
};

static uint32_t get_ldiv_mult(struct s32_uart_data *pd)
{
	uint32_t mult, cr = 0;
	vaddr_t base = io_pa_or_va(&pd->base, pd->len);

	s32_uart_read32(base, UARTCR, &cr);

	if (cr & UARTCR_ROSE)
		mult = UARTCR_OSR(cr);
	else
		mult = LDIV_MULTIPLIER;

	return mult;
}

static void s32_uart_set_brg(struct s32_uart_data *pd)
{
	uint32_t ibr, fbr;
	vaddr_t base = io_pa_or_va(&pd->base, pd->len);
	uint32_t divisr = pd->clock;
	uint32_t dividr = (uint32_t)(pd->baud * get_ldiv_mult(pd));

	ibr = (uint32_t)(divisr / dividr);
	fbr = (uint32_t)((divisr % dividr) * 16 / dividr) & 0xF;

	s32_uart_write32(base, LINIBRR, ibr);
	s32_uart_write32(base, LINFBRR, fbr);
}

void s32_uart_init(struct s32_uart_data *pd, paddr_t pbase, size_t len,
		   uint32_t clock, uint32_t baud)
{
	vaddr_t base;
	uint32_t ctrl, linsr;

	pd->base.pa = pbase;
	pd->len = len;
	pd->clock = clock;
	pd->baud = baud;
	pd->chip.ops = &s32_uart_ops;

	base = io_pa_or_va(&pd->base, pd->len);

	/* Set master mode and init mode */
	ctrl = LINCR1_MME | LINCR1_INIT;
	if (s32_uart_write32(base, LINCR1, ctrl))
		return;

	/* wait for init mode entry */
	do {
		if (s32_uart_read32(base, LINSR, &linsr))
			goto out;
	} while ((linsr & LINSR_LINS_MASK) != LINSR_LINS_INITMODE);

	/* Set UART bit */
	if (s32_uart_write32(base, UARTCR, UARTCR_UART))
		goto out;

	s32_uart_set_brg(pd);

	/* Set preset timeout register value. */
	if (s32_uart_write32(base, UARTPTO, 0xf))
		goto out;

	/* 8-bit data, no parity, Tx/Rx enabled, UART mode */
	ctrl = UARTCR_PC1 | UARTCR_RXEN | UARTCR_TXEN | UARTCR_PC0 |
		UARTCR_WL0 | UARTCR_UART | UARTCR_RFBM | UARTCR_TFBM;
	if (s32_uart_write32(base, UARTCR, ctrl))
		goto out;

out:
	s32_uart_read32(base, LINCR1, &ctrl);
	ctrl &= ~LINCR1_INIT;
	/* end init mode */
	s32_uart_write32(base, LINCR1, ctrl);
}
