/*
 * SPDX-FileCopyrightText: Copyright 2026 NXP
 *
 * SPDX-License-Identifier: Apache-2.0
 */

#include <string.h>
#include <zephyr/logging/log.h>
#include <zephyr/sys/slist.h>
#include <zephyr/sys/util.h>

#include "ebpf_map_backend.h"

LOG_MODULE_REGISTER(ebpf_maps, CONFIG_EBPF_LOG_LEVEL);

struct ebpf_dynamic_map {
	struct ebpf_map map;
	sys_snode_t registry_node;
	char *owned_name;
	void *storage;
};

K_MUTEX_DEFINE(ebpf_map_registry_bootstrap_lock);

static struct k_mutex ebpf_map_registry_lock;
static sys_slist_t ebpf_dynamic_maps;
static bool ebpf_map_registry_ready;
static uint32_t ebpf_next_map_id = 1U;

static const struct ebpf_map_ops *ebpf_map_ops_get(const struct ebpf_map *map);

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

int ebpf_map_delete_elem(struct ebpf_map *map, const void *key)
{
	const struct ebpf_map_ops *ops = ebpf_map_ops_get(map);

	if (ops == NULL || key == NULL) {
		return -EINVAL;
	}

	k_spinlock_key_t k = k_spin_lock(&map->lock);
	int ret = ops->delete_elem(map, key);

	k_spin_unlock(&map->lock, k);

	return ret;
}

static char *ebpf_strdup(const char *src)
{
	char *copy;
	size_t len;

	if (src == NULL) {
		return NULL;
	}

	len = strlen(src) + 1U;
	copy = k_malloc(len);
	if (copy == NULL) {
		return NULL;
	}

	memcpy(copy, src, len);

	return copy;
}

static void ebpf_map_registry_ensure_ready(void)
{
	if (ebpf_map_registry_ready) {
		return;
	}

	k_mutex_lock(&ebpf_map_registry_bootstrap_lock, K_FOREVER);
	if (ebpf_map_registry_ready) {
		k_mutex_unlock(&ebpf_map_registry_bootstrap_lock);
		return;
	}

	k_mutex_init(&ebpf_map_registry_lock);
	sys_slist_init(&ebpf_dynamic_maps);
	ebpf_next_map_id = 1U;
	ebpf_map_registry_ready = true;
	k_mutex_unlock(&ebpf_map_registry_bootstrap_lock);
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

int ebpf_map_create(const struct ebpf_map_spec *spec, struct ebpf_map **map_out)
{
	struct ebpf_dynamic_map *dynamic;
	uint32_t data_size;
	int ret;

	if (!ebpf_map_spec_is_valid(spec) || map_out == NULL) {
		return -EINVAL;
	}

	ebpf_map_registry_ensure_ready();

	dynamic = k_malloc(sizeof(*dynamic));
	if (dynamic == NULL) {
		return -ENOMEM;
	}

	memset(dynamic, 0, sizeof(*dynamic));
	dynamic->owned_name = ebpf_strdup(spec->name);
	if (dynamic->owned_name == NULL) {
		k_free(dynamic);
		return -ENOMEM;
	}

	dynamic->map.name = dynamic->owned_name;
	dynamic->map.type = spec->type;
	dynamic->map.key_size = spec->key_size;
	dynamic->map.value_size = spec->value_size;
	dynamic->map.max_entries = spec->max_entries;
	dynamic->map.dynamic = true;
	dynamic->map.owner = NULL;

	data_size = dynamic->map.value_size * dynamic->map.max_entries;
	dynamic->storage = k_malloc(data_size);
	if (dynamic->storage == NULL) {
		k_free(dynamic->owned_name);
		k_free(dynamic);
		return -ENOMEM;
	}

	dynamic->map.data = dynamic->storage;
	ret = ebpf_map_initialize(&dynamic->map);
	if (ret != 0) {
		k_free(dynamic->storage);
		k_free(dynamic->owned_name);
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

	ebpf_map_registry_ensure_ready();
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
	k_free(dynamic->owned_name);
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

	ebpf_map_registry_ensure_ready();
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

	ebpf_map_registry_ensure_ready();

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

	ebpf_map_registry_ensure_ready();

	return map->runtime_id;
}

const char *ebpf_map_get_name(const struct ebpf_map *map)
{
	return map != NULL ? map->name : NULL;
}

enum ebpf_map_type ebpf_map_get_type(const struct ebpf_map *map)
{
	return map != NULL ? map->type : EBPF_MAP_TYPE_MAX;
}

uint32_t ebpf_map_get_key_size(const struct ebpf_map *map)
{
	return map != NULL ? map->key_size : 0U;
}

uint32_t ebpf_map_get_value_size(const struct ebpf_map *map)
{
	return map != NULL ? map->value_size : 0U;
}

uint32_t ebpf_map_get_max_entries(const struct ebpf_map *map)
{
	return map != NULL ? map->max_entries : 0U;
}
