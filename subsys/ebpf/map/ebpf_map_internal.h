/*
 * SPDX-FileCopyrightText: Copyright 2026 NXP
 *
 * SPDX-License-Identifier: Apache-2.0
 */

/**
 * @file
 * @brief Internal eBPF map runtime interfaces.
 */

#ifndef ZEPHYR_SUBSYS_EBPF_MAP_INTERNAL_H_
#define ZEPHYR_SUBSYS_EBPF_MAP_INTERNAL_H_

#include <zephyr/ebpf/ebpf_map.h>

#ifdef __cplusplus
extern "C" {
#endif

struct ebpf_map_spec;

int ebpf_map_create(const struct ebpf_map_spec *spec, struct ebpf_map **map_out);

int ebpf_map_claim_owner(struct ebpf_map *map, void *owner);

int ebpf_map_destroy(struct ebpf_map *map);

int ebpf_map_destroy_owned(struct ebpf_map *map, void *owner);

uint32_t ebpf_map_get_id(const struct ebpf_map *map);

const char *ebpf_map_get_name(const struct ebpf_map *map);

enum ebpf_map_type ebpf_map_get_type(const struct ebpf_map *map);

uint32_t ebpf_map_get_key_size(const struct ebpf_map *map);

uint32_t ebpf_map_get_value_size(const struct ebpf_map *map);

uint32_t ebpf_map_get_max_entries(const struct ebpf_map *map);

struct ebpf_map *ebpf_map_from_id(uint32_t id);

#ifdef __cplusplus
}
#endif

#endif /* ZEPHYR_SUBSYS_EBPF_MAP_INTERNAL_H_ */
