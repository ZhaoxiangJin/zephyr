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

/**
 * @brief Helper function IDs used by the eBPF CALL instruction.
 *
 * The helper ID is encoded in the instruction immediate field.
 */
enum ebpf_helper_id {
	/** Look up an element in a map. */
	EBPF_HELPER_MAP_LOOKUP_ELEM = 0,

	/** Return a monotonic kernel timestamp in nanoseconds. */
	EBPF_HELPER_KTIME_GET_NS,

	/** Append a record to a ring buffer map. */
	EBPF_HELPER_RINGBUF_OUTPUT,

	/** Number of supported helper IDs. */
	EBPF_HELPER_MAX
};

/** @cond INTERNAL_HIDDEN */

/**
 * @brief Type for helper function implementations.
 *
 * Helper implementations take up to five arguments from registers ``R1``
 * through ``R5`` and return a value in register ``R0``.
 */
typedef uint64_t (*ebpf_helper_fn)(uint64_t r1, uint64_t r2, uint64_t r3,
				   uint64_t r4, uint64_t r5);

/**
 * @brief Get helper function by ID.
 *
 * @param[in] id Helper function ID.
 * @retval NULL No helper is registered for @p id.
 * @retval fn Function pointer for @p id.
 */
ebpf_helper_fn ebpf_get_helper(uint32_t id);

/** @endcond */

#ifdef __cplusplus
}
#endif

#endif /* ZEPHYR_INCLUDE_EBPF_HELPERS_H_ */
