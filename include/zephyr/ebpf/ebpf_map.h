/*
 * SPDX-FileCopyrightText: Copyright 2026 NXP
 *
 * SPDX-License-Identifier: Apache-2.0
 */

/**
 * @file
 * @brief eBPF map descriptor and API.
 * @ingroup ebpf
 */

#ifndef ZEPHYR_INCLUDE_EBPF_MAP_H_
#define ZEPHYR_INCLUDE_EBPF_MAP_H_

#include <stdint.h>
#include <stdbool.h>

#include <zephyr/ebpf/ebpf_prog.h>

#ifdef __cplusplus
extern "C" {
#endif

struct ebpf_map;

/** @brief Supported eBPF map types. */
enum ebpf_map_type {
	/** Fixed-size array indexed by integer key. */
	EBPF_MAP_TYPE_ARRAY = 0,

	/** Number of supported map types. */
	EBPF_MAP_TYPE_MAX
};

/** @cond INTERNAL_HIDDEN */

/**
 * @brief Authoring-only map definition record emitted into '.maps'.
 *
 * This definition remains in the public header because macro 'EBPF_MAP'
 * expands to it, but it is not part of the target-side runtime map API.
 *
 * The field order, width, and encoding form the '.maps' section ABI shared
 * by the restricted-C probe object, 'west ebpf build', and the  runtime
 * loader image format.
 */
struct ebpf_map_def {
	/**
	 * Serialized map type ID.
	 *
	 * Keep this as 'uint32_t' rather than 'enum ebpf_map_type' so
	 * the '.maps' record layout stays a fixed-width ABI contract across
	 * toolchains and matches 'ebpf_loader_image_map'.
	 */
	uint32_t type;
	uint32_t key_size;
	uint32_t value_size;
	uint32_t max_entries;
};

/** @endcond */

/** @brief Define one map for a restricted-C probe source. */
#define EBPF_MAP(_name, _type, _key_t, _value_t, _max_entries)	\
	struct ebpf_map_def _name EBPF_SEC(".maps") = {		\
		.type = (_type),				\
		.key_size = sizeof(_key_t),			\
		.value_size = sizeof(_value_t),			\
		.max_entries = (_max_entries),			\
	}

#if defined(__ZEPHYR__) || defined(__DOXYGEN__)

/**
 * @brief Look up a value in a map.
 *
 * @param[in] map Map to look up in.
 * @param[in] key Pointer to the key.
 *
 * @retval NULL Argument validation failed or the key was not found.
 * @retval value Pointer to the value associated with @p key.
 */
void *ebpf_map_lookup_elem(struct ebpf_map *map, const void *key);

/**
 * @brief Insert or update a map element from host code.
 *
 * Host-side counterpart to the probe's @c bpf_map_update_elem helper. The
 * semantics of @p flags are backend-defined.
 *
 * @param[in] map   Map to update.
 * @param[in] key   Pointer to the key.
 * @param[in] value Pointer to the value to store.
 * @param     flags Backend-defined update flags.
 *
 * @retval 0        Element inserted or updated.
 * @retval -EINVAL  Argument validation failed.
 * @retval -errno   Backend-specific failure.
 */
int ebpf_map_update_elem(struct ebpf_map *map, const void *key,
			 const void *value, uint64_t flags);

#endif /* __ZEPHYR__ || __DOXYGEN__ */

#ifdef __cplusplus
}
#endif

#endif /* ZEPHYR_INCLUDE_EBPF_MAP_H_ */
