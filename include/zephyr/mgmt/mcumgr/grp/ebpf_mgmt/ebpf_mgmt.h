/*
 * Copyright (c) 2026 NXP
 *
 * SPDX-License-Identifier: Apache-2.0
 */

#ifndef ZEPHYR_INCLUDE_ZEPHYR_MCUMGR_GRP_EBPF_MGMT_H_
#define ZEPHYR_INCLUDE_ZEPHYR_MCUMGR_GRP_EBPF_MGMT_H_

/**
 * @brief MCUmgr Zephyr eBPF Management API
 * @defgroup mcumgr_zephyr_ebpf_mgmt Zephyr eBPF Management
 * @ingroup mcumgr_mgmt_api
 * @{
 */

#ifdef __cplusplus
extern "C" {
#endif

/** @name Command IDs for the Zephyr eBPF management group.
 * @{
 */
#define ZEPHYR_MGMT_GRP_EBPF_CMD_LOAD 0
#define ZEPHYR_MGMT_GRP_EBPF_CMD_ENABLE 1
#define ZEPHYR_MGMT_GRP_EBPF_CMD_DISABLE 2
#define ZEPHYR_MGMT_GRP_EBPF_CMD_UNLOAD 3
#define ZEPHYR_MGMT_GRP_EBPF_CMD_DUMP 4
#define ZEPHYR_MGMT_GRP_EBPF_CMD_MAP_READ 5
/** @} */

/** Command result codes for Zephyr eBPF management. */
enum zephyr_ebpf_group_err_code_t {
	ZEPHYR_EBPF_MGMT_ERR_OK = 0,
	ZEPHYR_EBPF_MGMT_ERR_UNKNOWN,
	ZEPHYR_EBPF_MGMT_ERR_MALFORMED,
	ZEPHYR_EBPF_MGMT_ERR_UPLOAD_OFFSET,
	ZEPHYR_EBPF_MGMT_ERR_UPLOAD_TOO_LARGE,
	ZEPHYR_EBPF_MGMT_ERR_UPLOAD_IN_PROGRESS,
	ZEPHYR_EBPF_MGMT_ERR_LOAD_FAILED,
	ZEPHYR_EBPF_MGMT_ERR_NOT_FOUND,
	ZEPHYR_EBPF_MGMT_ERR_VERIFY_FAILED,
	ZEPHYR_EBPF_MGMT_ERR_NAME_CONFLICT,
	ZEPHYR_EBPF_MGMT_ERR_NO_MEMORY,
	ZEPHYR_EBPF_MGMT_ERR_BUSY,
	ZEPHYR_EBPF_MGMT_ERR_DATA_TOO_LARGE,
	ZEPHYR_EBPF_MGMT_ERR_UNSUPPORTED,
};

#ifdef __cplusplus
}
#endif

/** @} */

#endif /* ZEPHYR_INCLUDE_ZEPHYR_MCUMGR_GRP_EBPF_MGMT_H_ */