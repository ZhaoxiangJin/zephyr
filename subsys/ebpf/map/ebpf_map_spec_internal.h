/*
 * SPDX-FileCopyrightText: Copyright 2026 NXP
 *
 * SPDX-License-Identifier: Apache-2.0
 */

/**
 * @file
 * @brief Internal eBPF map creation descriptors.
 */

#ifndef ZEPHYR_SUBSYS_EBPF_MAP_SPEC_INTERNAL_H_
#define ZEPHYR_SUBSYS_EBPF_MAP_SPEC_INTERNAL_H_

#include <zephyr/ebpf/ebpf_map.h>

#ifdef __cplusplus
extern "C" {
#endif

/**
 * @brief Map description used to create one runtime map.
 *
 * Callers such as bundle management and the loader construct this descriptor
 * before passing it to ebpf_map_create() or ebpf_bundle_add_map(). It describes
 * the map to create, but it is not part of the private runtime map object layout.
 */
struct ebpf_map_spec {
	const char *name;
	enum ebpf_map_type type;
	uint32_t key_size;
	uint32_t value_size;
	uint32_t max_entries;
};

#ifdef __cplusplus
}
#endif

#endif /* ZEPHYR_SUBSYS_EBPF_MAP_SPEC_INTERNAL_H_ */
