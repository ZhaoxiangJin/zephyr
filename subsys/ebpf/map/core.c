/*
 * SPDX-FileCopyrightText: Copyright 2026 NXP
 *
 * SPDX-License-Identifier: Apache-2.0
 */

#include <string.h>
#include <zephyr/logging/log.h>
#include <zephyr/sys/slist.h>
#include <zephyr/sys/util.h>

#include "backends/backend.h"

LOG_MODULE_REGISTER(ebpf_maps, CONFIG_EBPF_LOG_LEVEL);

struct ebpf_dynamic_map {
	struct ebpf_map map;
	sys_snode_t registry_node;
	char *name;
	void *storage;
};

K_MUTEX_DEFINE(ebpf_map_registry_lock);
static sys_slist_t ebpf_dynamic_maps;
static uint32_t ebpf_next_map_id = 1U;

static const struct ebpf_map_ops *ebpf_map_ops_get(const struct ebpf_map *map)
{
	if (map == NULL) {
		return NULL;
	}

	switch (map->type) {
	case EBPF_MAP_TYPE_ARRAY:
		return ebpf_map_array_ops();
	default:
		return NULL;
	}
}

void *ebpf_map_lookup_elem(struct ebpf_map *map, const void *key)
{
	const struct ebpf_map_ops *ops = ebpf_map_ops_get(map);

	if (ops == NULL || key == NULL) {
		return NULL;
	}

	k_spinlock_key_t k = k_spin_lock(&map->lock);
	void *value = ops->lookup_elem(map, key);

	k_spin_unlock(&map->lock, k);

	return value;
}

int ebpf_map_update_elem(struct ebpf_map *map, const void *key,
			 const void *value, uint64_t flags)
{
	const struct ebpf_map_ops *ops = ebpf_map_ops_get(map);

	if (ops == NULL || key == NULL || value == NULL) {
		return -EINVAL;
	}

	k_spinlock_key_t k = k_spin_lock(&map->lock);
	int ret = ops->update_elem(map, key, value, flags);

	k_spin_unlock(&map->lock, k);

	return ret;
}

static bool ebpf_map_spec_is_valid(const struct ebpf_map_spec *spec)
{
	if (spec == NULL || spec->name == NULL || spec->max_entries == 0U) {
		return false;
	}

	switch (spec->type) {
	case EBPF_MAP_TYPE_ARRAY:
		return ebpf_map_array_spec_is_valid(spec);
	default:
		return false;
	}
}

static int ebpf_map_initialize(struct ebpf_map *map)
{
	switch (map->type) {
	case EBPF_MAP_TYPE_ARRAY:
		return ebpf_map_array_initialize(map);
	default:
		LOG_ERR("Unknown map type %d for '%s'", map->type, map->name);
		return -ENOTSUP;
	}
}

int ebpf_map_create(const struct ebpf_map_spec *spec, struct ebpf_map **map_out)
{
	struct ebpf_dynamic_map *dynamic;
	uint32_t data_size;
	size_t name_len;
	int ret;

	if (!ebpf_map_spec_is_valid(spec) || map_out == NULL) {
		return -EINVAL;
	}

	dynamic = k_malloc(sizeof(*dynamic));
	if (dynamic == NULL) {
		return -ENOMEM;
	}

	memset(dynamic, 0, sizeof(*dynamic));

	/* Duplicate spec->name so the map owns a stable copy independent of the caller. */
	name_len = strlen(spec->name) + 1U;
	dynamic->name = k_malloc(name_len);
	if (dynamic->name == NULL) {
		k_free(dynamic);
		return -ENOMEM;
	}
	memcpy(dynamic->name, spec->name, name_len);

	dynamic->map.name = dynamic->name;
	dynamic->map.type = spec->type;
	dynamic->map.key_size = spec->key_size;
	dynamic->map.value_size = spec->value_size;
	dynamic->map.max_entries = spec->max_entries;
	dynamic->map.dynamic = true;
	dynamic->map.owner = NULL;

	data_size = dynamic->map.value_size * dynamic->map.max_entries;
	dynamic->storage = k_malloc(data_size);
	if (dynamic->storage == NULL) {
		k_free(dynamic->name);
		k_free(dynamic);
		return -ENOMEM;
	}

	dynamic->map.data = dynamic->storage;
	ret = ebpf_map_initialize(&dynamic->map);
	if (ret != 0) {
		k_free(dynamic->storage);
		k_free(dynamic->name);
		k_free(dynamic);
		return ret;
	}

	k_mutex_lock(&ebpf_map_registry_lock, K_FOREVER);
	dynamic->map.runtime_id = ebpf_next_map_id++;
	sys_slist_append(&ebpf_dynamic_maps, &dynamic->registry_node);
	k_mutex_unlock(&ebpf_map_registry_lock);

	*map_out = &dynamic->map;

	return 0;
}

static int ebpf_dynamic_map_destroy(struct ebpf_map *map, void *expected_owner,
				    bool owner_must_match)
{
	struct ebpf_dynamic_map *dynamic;
	bool removed;

	if (map == NULL || !map->dynamic) {
		return -EINVAL;
	}

	dynamic = CONTAINER_OF(map, struct ebpf_dynamic_map, map);

	k_mutex_lock(&ebpf_map_registry_lock, K_FOREVER);
	if (owner_must_match) {
		if (map->owner != expected_owner) {
			k_mutex_unlock(&ebpf_map_registry_lock);
			return -EPERM;
		}
	} else if (map->owner != NULL) {
		k_mutex_unlock(&ebpf_map_registry_lock);
		return -EBUSY;
	}

	removed = sys_slist_find_and_remove(&ebpf_dynamic_maps,
					    &dynamic->registry_node);
	if (removed) {
		map->runtime_id = 0U;
		map->owner = NULL;
	}
	k_mutex_unlock(&ebpf_map_registry_lock);

	if (!removed) {
		return -ENOENT;
	}

	k_free(dynamic->storage);
	k_free(dynamic->name);
	k_free(dynamic);

	return 0;
}

int ebpf_map_destroy(struct ebpf_map *map)
{
	return ebpf_dynamic_map_destroy(map, NULL, false);
}

int ebpf_map_destroy_owned(struct ebpf_map *map, void *owner)
{
	if (owner == NULL) {
		return -EINVAL;
	}

	return ebpf_dynamic_map_destroy(map, owner, true);
}

int ebpf_map_claim_owner(struct ebpf_map *map, void *owner)
{
	if (map == NULL || owner == NULL || !map->dynamic) {
		return -EINVAL;
	}

	k_mutex_lock(&ebpf_map_registry_lock, K_FOREVER);
	if (map->owner != NULL) {
		k_mutex_unlock(&ebpf_map_registry_lock);
		return -EBUSY;
	}

	map->owner = owner;
	k_mutex_unlock(&ebpf_map_registry_lock);

	return 0;
}

struct ebpf_map *ebpf_map_from_id(uint32_t id)
{
	struct ebpf_dynamic_map *dynamic;

	if (id == 0U) {
		return NULL;
	}

	k_mutex_lock(&ebpf_map_registry_lock, K_FOREVER);
	SYS_SLIST_FOR_EACH_CONTAINER(&ebpf_dynamic_maps, dynamic, registry_node) {
		if (dynamic->map.runtime_id == id) {
			k_mutex_unlock(&ebpf_map_registry_lock);
			return &dynamic->map;
		}
	}
	k_mutex_unlock(&ebpf_map_registry_lock);

	return NULL;
}

uint32_t ebpf_map_get_id(const struct ebpf_map *map)
{
	if (map == NULL) {
		return 0U;
	}

	return map->runtime_id;
}

const char *ebpf_map_get_name(const struct ebpf_map *map)
{
	return map != NULL ? map->name : NULL;
}

uint32_t ebpf_map_get_value_size(const struct ebpf_map *map)
{
	return map != NULL ? map->value_size : 0U;
}
