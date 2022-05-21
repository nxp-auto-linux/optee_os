/* SPDX-License-Identifier: BSD-3-Clause */
/*
 * Copyright 2022 NXP
 */

#ifndef HSE_ABI_H
#define HSE_ABI_H

#include <util.h>

#define HSE_SRV_DESC_MAX_SIZE    256u /* maximum service descriptor size */

/**
 * enum hse_status - HSE status
 * @HSE_STATUS_RNG_INIT_OK: RNG initialization successfully completed
 * @HSE_STATUS_INIT_OK: HSE initialization successfully completed
 * @HSE_STATUS_INSTALL_OK: HSE installation phase successfully completed,
 *                         key stores have been formatted and can be used
 * @HSE_STATUS_PUBLISH_SYS_IMAGE: volatile HSE configuration detected
 */
enum hse_status {
	HSE_STATUS_RNG_INIT_OK = BIT(5),
	HSE_STATUS_INIT_OK = BIT(8),
	HSE_STATUS_INSTALL_OK = BIT(9),
	HSE_STATUS_PUBLISH_SYS_IMAGE = BIT(13),
};

/**
 * enum hse_srv_response - HSE service response
 * @HSE_SRV_RSP_OK: service successfully executed with no error
 * @HSE_SRV_RSP_VERIFY_FAILED: authentication tag/signature verification failed
 * @HSE_SRV_RSP_INVALID_ADDR: invalid service descriptor address parameters
 * @HSE_SRV_RSP_INVALID_PARAM: invalid service descriptor request parameters
 * @HSE_SRV_RSP_NOT_SUPPORTED: operation or feature not supported
 * @HSE_SRV_RSP_NOT_ALLOWED: operation subject to restrictions (in attributes,
 *                           life-cycle dependent operations, key-management)
 * @HSE_SRV_RSP_NOT_ENOUGH_SPACE: not enough space to perform the service
 * @HSE_SRV_RSP_READ_FAILURE: service request failed, read access denied
 * @HSE_SRV_RSP_WRITE_FAILURE: service request failed, write access denied
 * @HSE_SRV_RSP_STREAMING_MODE_FAILURE: service request in streaming mode failed
 * @HSE_SRV_RSP_KEY_NOT_AVAILABLE: key locked due to failed boot measurement or
 *                                 an active debugger
 * @HSE_SRV_RSP_KEY_INVALID: the key flags don't match the crypto operation
 * @HSE_SRV_RSP_KEY_EMPTY: specified key slot empty
 * @HSE_SRV_RSP_KEY_WRITE_PROTECTED: key slot write protected
 * @HSE_SRV_RSP_KEY_UPDATE_ERROR: specified key slot cannot be updated due to
 *                                errors in verification of the parameters
 * @HSE_SRV_RSP_MEMORY_FAILURE: physical errors (e.g. flipped bits) detected
 *                              during memory read or write
 * @HSE_SRV_RSP_CANCEL_FAILURE: service cannot be canceled
 * @HSE_SRV_RSP_CANCELED: service has been canceled
 * @HSE_SRV_RSP_GENERAL_ERROR: error not covered by the error codes above
 */
enum hse_srv_response {
	HSE_SRV_RSP_OK = 0x55A5AA33ul,
	HSE_SRV_RSP_VERIFY_FAILED = 0x55A5A164ul,
	HSE_SRV_RSP_INVALID_ADDR = 0x55A5A26Aul,
	HSE_SRV_RSP_INVALID_PARAM = 0x55A5A399ul,
	HSE_SRV_RSP_NOT_SUPPORTED = 0xAA55A11Eul,
	HSE_SRV_RSP_NOT_ALLOWED = 0xAA55A21Cul,
	HSE_SRV_RSP_NOT_ENOUGH_SPACE = 0xAA55A371ul,
	HSE_SRV_RSP_READ_FAILURE = 0xAA55A427ul,
	HSE_SRV_RSP_WRITE_FAILURE = 0xAA55A517ul,
	HSE_SRV_RSP_STREAMING_MODE_FAILURE = 0xAA55A6B1ul,
	HSE_SRV_RSP_KEY_NOT_AVAILABLE = 0xA5AA51B2ul,
	HSE_SRV_RSP_KEY_INVALID = 0xA5AA52B4ul,
	HSE_SRV_RSP_KEY_EMPTY = 0xA5AA5317ul,
	HSE_SRV_RSP_KEY_WRITE_PROTECTED = 0xA5AA5436ul,
	HSE_SRV_RSP_KEY_UPDATE_ERROR = 0xA5AA5563ul,
	HSE_SRV_RSP_MEMORY_FAILURE = 0x33D6D136ul,
	HSE_SRV_RSP_CANCEL_FAILURE = 0x33D6D261ul,
	HSE_SRV_RSP_CANCELED = 0x33D6D396ul,
	HSE_SRV_RSP_GENERAL_ERROR = 0x33D6D4F1ul,
};

/**
 * enum hse_srv_id - HSE service ID
 * @HSE_SRV_ID_GET_ATTR: get attribute, such as firmware version
 */
enum hse_srv_id {
	HSE_SRV_ID_GET_ATTR = 0x00A50002ul,
};

/**
 * enum hse_attr - HSE attribute
 * @HSE_FW_VERSION_ATTR_ID: firmware version
 */
enum hse_attr {
	HSE_FW_VERSION_ATTR_ID = 1u,
};

/**
 * struct hse_attr_fw_version - firmware version
 * @fw_type: attribute ID
 * @major: major revision
 * @minor: minor revision
 * @patch: patch version
 */
struct hse_attr_fw_version {
	uint8_t reserved[2];
	uint16_t fw_type;
	uint8_t major;
	uint8_t minor;
	uint16_t patch;
} __packed;

/**
 * struct hse_get_attr_srv - get attribute, such as firmware version
 * @attr_id: attribute ID
 * @attr_len: attribute length, in bytes
 * @attr: DMA address of the attribute
 */
struct hse_get_attr_srv {
	uint16_t attr_id;
	uint8_t reserved[2];
	uint32_t attr_len;
	uint64_t attr;
} __packed;

struct hse_srv_desc {
	uint32_t srv_id;
	uint8_t reserved[4];
	union {
		struct hse_get_attr_srv get_attr_req;
	};
} __packed;

#endif /* HSE_ABI_H */
