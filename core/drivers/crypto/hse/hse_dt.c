// SPDX-License-Identifier: BSD-3-Clause
/*
 * Copyright 2022 NXP
 */

#include <hse_dt.h>
#include <kernel/boot.h>
#include <kernel/dt.h>
#include <libfdt.h>
#include <trace.h>

static const char *hse_compatible = "nxp,s32cc-hse";

static int fdt_find_compatible_enabled(void *fdt, const char *compatible)
{
	int offs = -1;

	while (true) {
		offs = fdt_node_offset_by_compatible(fdt, offs, compatible);

		if (offs < 0)
			break;

		if (_fdt_get_status(fdt, offs) == (DT_STATUS_OK_NSEC |
						   DT_STATUS_OK_SEC))
			break;
	}

	return offs;
}

static uint64_t fdt_read_reg_cells(const fdt32_t *prop, int nr_cells)
{
	uint64_t reg = fdt32_to_cpu(prop[0]);

	if (nr_cells > 1)
		reg = (reg << 32) | fdt32_to_cpu(prop[1]);

	return reg;
}

static int fdt_get_reg_props_by_index(const void *dtb, int node, int index,
				      paddr_t *base, size_t *size)
{
	const fdt32_t *prop;
	int parent, len = 0;
	int ac, sc, res = 0;
	int cell;

	parent = fdt_parent_offset(dtb, node);
	if (parent < 0)
		return -FDT_ERR_BADOFFSET;

	ac = fdt_address_cells(dtb, parent);
	sc = fdt_size_cells(dtb, parent);

	if (ADD_OVERFLOW(ac, sc, &res))
		return -FDT_ERR_BADVALUE;

	if (MUL_OVERFLOW(index, res, &cell))
		return -FDT_ERR_BADVALUE;

	prop = fdt_getprop(dtb, node, "reg", &len);
	if (!prop) {
		IMSG("Couldn't find \"reg\" property in dtb\n");
		return -FDT_ERR_NOTFOUND;
	}

	if (ADD_OVERFLOW(cell, res, &res))
		return -FDT_ERR_BADVALUE;

	if (MUL_OVERFLOW(res, (int)sizeof(uint32_t), &res))
		return -FDT_ERR_BADVALUE;

	/* res = (cell + ac + sc) * (int)sizeof(uint32_t) */
	if (res > len)
		return -FDT_ERR_BADVALUE;

	if (base)
		*base = (paddr_t)fdt_read_reg_cells(&prop[cell], ac);

	if (size)
		*size = (size_t)fdt_read_reg_cells(&prop[cell + ac], sc);

	return 0;
}

int hse_dt_get_regs(paddr_t *regs_base, size_t *regs_size,
		    paddr_t *desc_base, size_t *desc_size)
{
	void *fdt = NULL;
	int offset;
	int regs_off, desc_off;
	paddr_t base;
	size_t size;
	int ret;

	fdt = get_dt();
	if (!fdt) {
		EMSG("No Device Tree found");
		return -1;
	}

	offset = fdt_find_compatible_enabled(fdt, hse_compatible);
	if (offset < 0) {
		EMSG("Could not find node with matching compatible \"%s\"",
		     hse_compatible);
		return offset;
	}

	regs_off = fdt_stringlist_search(fdt, offset, "reg-names",
					 "hse-regs");
	if (regs_off < 0)
		return regs_off;

	desc_off = fdt_stringlist_search(fdt, offset, "reg-names",
					 "hse-desc");
	if (desc_off < 0)
		return desc_off;

	ret = fdt_get_reg_props_by_index(fdt, offset, regs_off, &base, &size);
	if (ret < 0)
		return ret;
	*regs_base = base;
	*regs_size = size;

	ret = fdt_get_reg_props_by_index(fdt, offset, desc_off, &base, &size);
	if (ret < 0)
		return ret;
	*desc_base = base;
	*desc_size = size;

	return 0;
}
