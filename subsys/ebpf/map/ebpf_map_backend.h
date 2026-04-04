/*
 * SPDX-FileCopyrightText: Copyright 2026 NXP
 *
 * SPDX-License-Identifier: Apache-2.0
 */

/**
 * @file
 * @brief Internal eBPF map backend interfaces.
 */

#ifndef ZEPHYR_SUBSYS_EBPF_MAP_BACKEND_H_
#define ZEPHYR_SUBSYS_EBPF_MAP_BACKEND_H_

#include "ebpf_map_spec_internal.h"
#include "ebpf_map_private.h"

#ifdef __cplusplus
extern "C" {
#endif

struct ebpf_map_ops {
	void *(*lookup_elem)(struct ebpf_map *map, const void *key);
	int (*update_elem)(struct ebpf_map *map, const void *key,
			   const void *value, uint64_t flags);
	int (*delete_elem)(struct ebpf_map *map, const void *key);
};

const struct ebpf_map_ops *ebpf_map_array_ops(void);

bool ebpf_map_array_spec_is_valid(const struct ebpf_map_spec *spec);

int ebpf_map_array_initialize(struct ebpf_map *map);

#ifdef __cplusplus
}
#endif

#endif /* ZEPHYR_SUBSYS_EBPF_MAP_BACKEND_H_ */
