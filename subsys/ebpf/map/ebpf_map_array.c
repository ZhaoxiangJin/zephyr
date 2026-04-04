/*
 * SPDX-FileCopyrightText: Copyright 2026 NXP
 *
 * SPDX-License-Identifier: Apache-2.0
 */

#include <string.h>

#include "ebpf_map_backend.h"

static void *ebpf_array_lookup(struct ebpf_map *map, const void *key)
{
	uint32_t idx = *(const uint32_t *)key;

	if (idx >= map->max_entries) {
		return NULL;
	}

	return (uint8_t *)map->data + (idx * map->value_size);
}

static int ebpf_array_update(struct ebpf_map *map, const void *key,
			     const void *value, uint64_t flags)
{
	uint32_t idx = *(const uint32_t *)key;

	if (idx >= map->max_entries) {
		return -ENOENT;
	}

	memcpy((uint8_t *)map->data + (idx * map->value_size), value, map->value_size);
	return 0;
}

static int ebpf_array_delete(struct ebpf_map *map, const void *key)
{
	ARG_UNUSED(map);
	ARG_UNUSED(key);

	return -ENOTSUP;
}

static const struct ebpf_map_ops ebpf_map_array_backend_ops = {
	.lookup_elem = ebpf_array_lookup,
	.update_elem = ebpf_array_update,
	.delete_elem = ebpf_array_delete,
};

const struct ebpf_map_ops *ebpf_map_array_ops(void)
{
	return &ebpf_map_array_backend_ops;
}

bool ebpf_map_array_spec_is_valid(const struct ebpf_map_spec *spec)
{
	return spec->key_size == sizeof(uint32_t) && spec->value_size > 0U;
}

int ebpf_map_array_initialize(struct ebpf_map *map)
{
	memset(map->data, 0, map->value_size * map->max_entries);

	return 0;
}
