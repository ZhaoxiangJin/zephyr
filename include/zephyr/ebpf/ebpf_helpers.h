/*
 * SPDX-FileCopyrightText: Copyright 2026 NXP
 *
 * SPDX-License-Identifier: Apache-2.0
 */

/**
 * @file
 * @brief eBPF helper function IDs and dispatch.
 * @ingroup ebpf
 */

#ifndef ZEPHYR_INCLUDE_EBPF_HELPERS_H_
#define ZEPHYR_INCLUDE_EBPF_HELPERS_H_

#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

/** @cond INTERNAL_HIDDEN */

/**
 * @brief Helper function IDs used by the eBPF CALL instruction.
 *
 * The helper ID is encoded in the instruction immediate field.
 */
enum ebpf_helper_id {
	/** Reserved invalid helper ID. */
	EBPF_HELPER_INVALID = 0,

	/** Look up an element in a map. */
	EBPF_HELPER_MAP_LOOKUP_ELEM = 1,

	/** Return a monotonic kernel timestamp in nanoseconds. */
	EBPF_HELPER_KTIME_GET_NS,

	/** Number of supported helper IDs. */
	EBPF_HELPER_MAX
};

/** @endcond */

/**
 * @brief Host-side restricted-C wrapper for the map lookup helper.
 *
 * Restricted-C probe sources can call this symbol directly. The host-side
 * compiler lowers the function pointer constant into the helper ID expected by
 * the eBPF CALL instruction.
 */
static void *(*ebpf_map_lookup_elem)(const void *map, const void *key) =
			(void *)(uintptr_t)EBPF_HELPER_MAP_LOOKUP_ELEM;

/**
 * @brief Host-side restricted-C wrapper for the monotonic time helper.
 */
static uint64_t (*ebpf_ktime_get_ns)(void) =
			(void *)(uintptr_t)EBPF_HELPER_KTIME_GET_NS;

#ifdef __cplusplus
}
#endif

#endif /* ZEPHYR_INCLUDE_EBPF_HELPERS_H_ */
