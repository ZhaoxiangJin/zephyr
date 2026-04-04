/*
 * SPDX-FileCopyrightText: Copyright 2026 NXP
 *
 * SPDX-License-Identifier: Apache-2.0
 */

/**
 * @file
 * @brief Stable eBPF hook identifiers.
 * @ingroup ebpf
 */

#ifndef ZEPHYR_INCLUDE_EBPF_HOOK_H_
#define ZEPHYR_INCLUDE_EBPF_HOOK_H_

#include <stdbool.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

/** @brief Stable hook identifiers exposed by the Zephyr eBPF runtime. */
enum ebpf_hook_id {
	EBPF_HOOK_THREAD_SWITCHED_IN = 0,
	EBPF_HOOK_THREAD_SWITCHED_OUT,
	EBPF_HOOK_ISR_ENTER,
	EBPF_HOOK_ISR_EXIT,
	EBPF_HOOK_IDLE_ENTER,
	EBPF_HOOK_IDLE_EXIT,
	EBPF_HOOK_PM_STATE_ENTRY,
	EBPF_HOOK_PM_STATE_EXIT,
	EBPF_HOOK_ID_MAX,
};

/** @brief Stable metadata for one public eBPF hook. */
struct ebpf_hook_info {
	/** Stable hook identifier. */
	enum ebpf_hook_id hook_id;

	/** Stable string name used by runtime-loaded probe objects. */
	const char *name;

	/** Size of the typed context passed in register R1. */
	uint32_t ctx_size;
};

/**
 * @brief Return true if @p hook_id names a supported hook.
 */
bool ebpf_hook_id_is_valid(enum ebpf_hook_id hook_id);

/**
 * @brief Return a stable string name for one eBPF hook.
 */
const char *ebpf_hook_id_name(enum ebpf_hook_id hook_id);

/**
 * @brief Resolve one stable hook string name into a hook identifier.
 *
 * @param[in] name Stable hook name.
 * @param[out] hook_id Receives the resolved hook identifier.

 * @retval 0 Resolution succeeded.
 * @retval -EINVAL @p name or @p hook_id is invalid, or the hook name is unknown.
 */
int ebpf_hook_name_to_id(const char *name, enum ebpf_hook_id *hook_id);

/**
 * @brief Get stable metadata for one hook.
 *
 * @param[in] hook_id Stable hook identifier.
 * @param[out] info Receives the hook metadata.

 * @retval 0 Metadata lookup succeeded.
 * @retval -EINVAL @p hook_id or @p info is invalid.
 */
int ebpf_hook_get_info(enum ebpf_hook_id hook_id, struct ebpf_hook_info *info);

#ifdef __cplusplus
}
#endif

#endif /* ZEPHYR_INCLUDE_EBPF_HOOK_H_ */
