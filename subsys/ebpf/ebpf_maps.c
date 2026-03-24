/*
 * SPDX-FileCopyrightText: Copyright 2026 NXP
 *
 * SPDX-License-Identifier: Apache-2.0
 */

#include <zephyr/logging/log.h>
#include <string.h>

#include <zephyr/ebpf/ebpf_map.h>

LOG_MODULE_REGISTER(ebpf_maps, CONFIG_EBPF_LOG_LEVEL);

/** @brief Array-map implementation. */
static const struct ebpf_map_ops array_ops;
#ifdef CONFIG_EBPF_MAP_RINGBUF
static const struct ebpf_map_ops ringbuf_ops;
#endif

static const struct ebpf_map_ops *ebpf_map_ops_get(const struct ebpf_map *map)
{
	if (map == NULL) {
		return NULL;
	}

	switch (map->type) {
	case EBPF_MAP_TYPE_ARRAY:
		return &array_ops;
#ifdef CONFIG_EBPF_MAP_RINGBUF
	case EBPF_MAP_TYPE_RINGBUF:
		return &ringbuf_ops;
#endif
	default:
		return NULL;
	}
}

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

	memcpy((uint8_t *)map->data + (idx * map->value_size),
	       value, map->value_size);
	return 0;
}

static int ebpf_array_delete(struct ebpf_map *map, const void *key)
{
	return -ENOTSUP; /* Arrays do not support delete */
}

static const struct ebpf_map_ops array_ops = {
	.lookup_elem = ebpf_array_lookup,
	.update_elem = ebpf_array_update,
	.delete_elem = ebpf_array_delete,
};

/** @brief Ring-buffer map implementation. */
#ifdef CONFIG_EBPF_MAP_RINGBUF
/**
 * Write data into the ring buffer; caller must hold map->lock.
 */
static int ebpf_ringbuf_write_locked(struct ebpf_map *map, const void *data, uint32_t size)
{
	struct ebpf_ringbuf_data *rb_data = (struct ebpf_ringbuf_data *)map->data;
	struct ring_buf *rb = &rb_data->rb;
	uint32_t header = size;
	uint32_t total = sizeof(header) + size;

	if (ring_buf_space_get(rb) < total) {
		return -ENOMEM;
	}

	ring_buf_put(rb, (uint8_t *)&header, sizeof(header));
	ring_buf_put(rb, data, size);

	return 0;
}

int ebpf_ringbuf_output(struct ebpf_map *map, const void *data,
			uint32_t size, uint64_t flags)
{
	ARG_UNUSED(flags);

	if (map->type != EBPF_MAP_TYPE_RINGBUF) {
		return -EINVAL;
	}

	k_spinlock_key_t key = k_spin_lock(&map->lock);
	int ret = ebpf_ringbuf_write_locked(map, data, size);

	k_spin_unlock(&map->lock, key);

	return ret;
}

int ebpf_ringbuf_read(struct ebpf_map *map, void *data,
		      uint32_t capacity, uint32_t *size_out)
{
	struct ebpf_ringbuf_data *rb_data;
	struct ring_buf *rb;
	uint32_t payload_size;
	uint32_t got;
	k_spinlock_key_t key;

	if (map == NULL || map->type != EBPF_MAP_TYPE_RINGBUF ||
	    size_out == NULL) {
		return -EINVAL;
	}

	rb_data = (struct ebpf_ringbuf_data *)map->data;
	rb = &rb_data->rb;

	key = k_spin_lock(&map->lock);
	if (ring_buf_size_get(rb) < sizeof(payload_size)) {
		k_spin_unlock(&map->lock, key);
		return -EAGAIN;
	}

	got = ring_buf_get(rb, (uint8_t *)&payload_size, sizeof(payload_size));
	if (got != sizeof(payload_size)) {
		k_spin_unlock(&map->lock, key);
		return -EIO;
	}

	if (payload_size > ring_buf_size_get(rb)) {
		ring_buf_reset(rb);
		k_spin_unlock(&map->lock, key);
		return -EIO;
	}

	if (payload_size > capacity) {
		ring_buf_get(rb, NULL, payload_size);
		k_spin_unlock(&map->lock, key);
		return -EMSGSIZE;
	}

	got = ring_buf_get(rb, data, payload_size);
	k_spin_unlock(&map->lock, key);

	if (got != payload_size) {
		return -EIO;
	}

	*size_out = payload_size;
	return 0;
}

static void *ebpf_ringbuf_lookup(struct ebpf_map *map, const void *key)
{
	ARG_UNUSED(key);
	return NULL; /* Ring buffers don't support lookup */
}

static int ebpf_ringbuf_update(struct ebpf_map *map, const void *key,
			       const void *value, uint64_t flags)
{
	ARG_UNUSED(key);
	ARG_UNUSED(flags);
	/* Called from ebpf_map_update_elem which already holds map->lock. */
	return ebpf_ringbuf_write_locked(map, value, map->value_size);
}

static int ebpf_ringbuf_delete(struct ebpf_map *map, const void *key)
{
	ARG_UNUSED(key);
	return -ENOTSUP; /* Ring buffers don't support delete */
}

static const struct ebpf_map_ops ringbuf_ops = {
	.lookup_elem = ebpf_ringbuf_lookup,
	.update_elem = ebpf_ringbuf_update,
	.delete_elem = ebpf_ringbuf_delete,
};
#endif /* CONFIG_EBPF_MAP_RINGBUF */

/** @brief Generic public map API wrappers. */
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

struct ebpf_map *ebpf_map_from_id(uint32_t id)
{
	uint32_t next_id = 1U;

	STRUCT_SECTION_FOREACH(ebpf_map, map) {
		if (next_id++ == id) {
			return map;
		}
	}

	return NULL;
}

uint32_t ebpf_map_get_id(const struct ebpf_map *map)
{
	uint32_t next_id = 1U;

	if (map == NULL) {
		return 0U;
	}

	STRUCT_SECTION_FOREACH(ebpf_map, iter) {
		if (iter == map) {
			return next_id;
		}

		next_id++;
	}

	return 0U;
}

/** @brief Initialize all statically registered eBPF maps. */
int ebpf_maps_init(void)
{
	STRUCT_SECTION_FOREACH(ebpf_map, map) {
		switch (map->type) {
		case EBPF_MAP_TYPE_ARRAY:
			memset(map->data, 0, map->value_size * map->max_entries);
			break;
#ifdef CONFIG_EBPF_MAP_RINGBUF
		case EBPF_MAP_TYPE_RINGBUF:
			memset(map->data, 0, ebpf_map_data_size(map));
			ring_buf_init(&((struct ebpf_ringbuf_data *)map->data)->rb,
				      map->max_entries, ((struct ebpf_ringbuf_data *)map->data)->buffer);
			break;
#endif
		default:
			LOG_ERR("Unknown map type %d for '%s'", map->type, map->name);
			break;
		}
	}

	return 0;
}
