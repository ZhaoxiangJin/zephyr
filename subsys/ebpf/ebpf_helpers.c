/*
 * SPDX-FileCopyrightText: Copyright 2026 NXP
 *
 * SPDX-License-Identifier: Apache-2.0
 */

#include <zephyr/logging/log.h>
#include <string.h>

#include <zephyr/ebpf/ebpf_helpers.h>
#include <zephyr/ebpf/ebpf_map.h>

LOG_MODULE_REGISTER(ebpf_helpers, CONFIG_EBPF_LOG_LEVEL);

/** @brief Resolve a map lookup helper call and return the value pointer in R0. */
static uint64_t ebpf_helper_map_lookup_elem(uint64_t r1, uint64_t r2, uint64_t r3,
					    uint64_t r4, uint64_t r5)
{
	struct ebpf_map *map = ebpf_map_from_id((uint32_t)r1);
	const void *key = (const void *)(uintptr_t)r2;

	if (map == NULL) {
		return 0;
	}

	void *val = ebpf_map_lookup_elem(map, key);

	return (uint64_t)(uintptr_t)val;
}

/** @brief Return a monotonic timestamp in nanoseconds with hardware-cycle precision. */
static uint64_t ebpf_helper_ktime_get_ns(uint64_t r1, uint64_t r2, uint64_t r3,
					 uint64_t r4, uint64_t r5)
{
	return k_cyc_to_ns_floor64(k_cycle_get_64());
}

#ifdef CONFIG_EBPF_MAP_RINGBUF
/** @brief Publish a payload into an eBPF ring buffer map. */
static uint64_t ebpf_helper_ringbuf_output(uint64_t r1, uint64_t r2, uint64_t r3,
					   uint64_t r4, uint64_t r5)
{
	struct ebpf_map *map = ebpf_map_from_id((uint32_t)r1);
	const void *data = (const void *)(uintptr_t)r2;

	if (map == NULL) {
		return (uint64_t)(int64_t)-ENOENT;
	}

	return (uint64_t)(int64_t)ebpf_ringbuf_output(map, data, (uint32_t)r3, r4);
}
#endif

/** @brief Resolve a helper ID to its implementation entry point. */
ebpf_helper_fn ebpf_get_helper(uint32_t id)
{
	switch (id) {
	case EBPF_HELPER_MAP_LOOKUP_ELEM: return &ebpf_helper_map_lookup_elem;
	case EBPF_HELPER_KTIME_GET_NS: return &ebpf_helper_ktime_get_ns;
#ifdef CONFIG_EBPF_MAP_RINGBUF
	case EBPF_HELPER_RINGBUF_OUTPUT: return &ebpf_helper_ringbuf_output;
#endif
	default:
		return NULL;
	}
}
