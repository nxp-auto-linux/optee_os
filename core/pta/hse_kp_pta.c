// SPDX-License-Identifier: BSD-3-Clause
/*
 * Copyright 2023 NXP
 */

#include <crypto/crypto_hse.h>
#include <kernel/pseudo_ta.h>
#include <malloc.h>
#include <pta_hse_kp.h>

#define PTA_NAME "pta.hse_kp"

static TEE_Result hse_kp_provision_cmd(uint32_t ptypes,
				       TEE_Param params[TEE_NUM_PARAMS])
{
	if (ptypes != TEE_PARAM_TYPES(TEE_PARAM_TYPE_MEMREF_INPUT,
				      TEE_PARAM_TYPE_VALUE_INPUT,
				      TEE_PARAM_TYPE_NONE,
				      TEE_PARAM_TYPE_NONE)) {
		DMSG("Bad parameters types: 0x%" PRIx32, ptypes);

		return TEE_ERROR_BAD_PARAMETERS;
	}

	if (!(params[0].memref.buffer) && params[0].memref.size > 0)
		return TEE_ERROR_BAD_PARAMETERS;

	if (params[1].value.a > UINT8_MAX || params[1].value.b > UINT8_MAX)
		return TEE_ERROR_BAD_PARAMETERS;

	return hse_provision_sym_key(params[0].memref.buffer,
				     params[1].value.a,
				     params[1].value.b);
}

static TEE_Result invoke_command(void *session_ctx __maybe_unused,
				 uint32_t cmd, uint32_t ptypes,
				 TEE_Param params[TEE_NUM_PARAMS])
{
	TEE_Result res;

	switch (cmd) {
	case PTA_CMD_SYM_KEY_PROVISION:
		res = hse_kp_provision_cmd(ptypes, params);
		break;

	default:
		res = TEE_ERROR_BAD_PARAMETERS;
		break;
	}

	return res;
}

pseudo_ta_register(.uuid = PTA_HSE_KP_UUID, .name = PTA_NAME,
		   .flags = PTA_DEFAULT_FLAGS,
		   .invoke_command_entry_point = invoke_command);
