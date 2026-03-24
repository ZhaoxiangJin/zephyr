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

#include <zephyr/kernel.h>
#include <zephyr/sys/ring_buffer.h>
#include <zephyr/sys/iterable_sections.h>

#ifdef __cplusplus
extern "C" {
#endif

/** @brief Supported eBPF map types. */
enum ebpf_map_type {
	/** Fixed-size array indexed by integer key. */
	EBPF_MAP_TYPE_ARRAY         = 0,

	/** Ring buffer used for variable-size event records. */
	EBPF_MAP_TYPE_RINGBUF       = 1,

	/** Number of supported map types. */
	EBPF_MAP_TYPE_MAX
};

struct ebpf_map;

/** @cond INTERNAL_HIDDEN */

struct ebpf_map_ops {
	void *(*lookup_elem)(struct ebpf_map *map, const void *key);
	int (*update_elem)(struct ebpf_map *map, const void *key,
		      const void *value, uint64_t flags);
	int (*delete_elem)(struct ebpf_map *map, const void *key);
};

struct ebpf_ringbuf_data {
	struct ring_buf rb;
	uint8_t buffer[];
};

/** @endcond */

/**
 * @brief eBPF map descriptor.
 *
 * Placed in RAM iterable section so the data storage is mutable.
 */
struct ebpf_map {
	/** Map name. */
	const char *name;

	/** Map type. */
	enum ebpf_map_type type;

	/** Key size in bytes. */
	uint32_t key_size;

	/** Value size in bytes. */
	uint32_t value_size;

	/** Maximum number of entries. */
	uint32_t max_entries;

	/** @cond INTERNAL_HIDDEN */

	/** Pointer to the statically allocated backing store. */
	void *data;

	/** Spinlock for concurrent access. */
	struct k_spinlock lock;

	/** @endcond */
};

/** @cond INTERNAL_HIDDEN */

/**
 * @brief Compute required data size for a map.
 */
#define _EBPF_MAP_DATA_SIZE(_type, _ks, _vs, _max)	\
	((_type) == EBPF_MAP_TYPE_ARRAY ?		\
	 ((_vs) * (_max)) :				\
	 (_type) == EBPF_MAP_TYPE_RINGBUF ?		\
	 (sizeof(struct ring_buf) + (_max)) :		\
	 ((_vs) * (_max)))

/** @endcond */

/**
 * @brief Define an eBPF map at compile time.
 *
 * This allocates static storage for the map data.
 *
 * @param[in] _name C identifier for this map.
 * @param[in] _type Map type.
 * @param[in] _key_size Key size in bytes.
 * @param[in] _value_size Value size in bytes.
 * @param[in] _max_entries Maximum number of entries.
 */
#define EBPF_MAP_DEFINE(_name, _type, _key_size, _value_size, _max_entries)		\
	static uint8_t _ebpf_map_data_##_name						\
		[_EBPF_MAP_DATA_SIZE(_type, _key_size, _value_size, _max_entries)];	\
											\
	STRUCT_SECTION_ITERABLE(ebpf_map, _name) = {					\
		.name        = STRINGIFY(_name),					\
		.type        = (_type),							\
		.key_size    = (_key_size),						\
		.value_size  = (_value_size),						\
		.max_entries = (_max_entries),						\
		.data        = _ebpf_map_data_##_name,					\
	}

/**
 * @brief Look up a value in a map.
 *
 * @param[in] map Map to look up in.
 * @param[in] key Pointer to the key.
 * @retval NULL Argument validation failed or the key was not found.
 * @retval value Pointer to the value associated with @p key.
 */
void *ebpf_map_lookup_elem(struct ebpf_map *map, const void *key);

/**
 * @brief Update a value in a map.
 *
 * @param[in] map Map to update.
 * @param[in] key Pointer to the key.
 * @param[in] value Pointer to the new value.
 * @param[in] flags Update flags.
 * @retval 0 Element updated successfully.
 * @retval -EINVAL One or more arguments are invalid.
 * @retval -ENOENT The target slot does not exist for array-backed maps.
 * @retval -ENOMEM The map cannot allocate space for a new element.
 */
int ebpf_map_update_elem(struct ebpf_map *map, const void *key,
			 const void *value, uint64_t flags);

/**
 * @brief Delete an element from a map.
 *
 * @param[in] map Map to delete from.
 * @param[in] key Pointer to the key.
 * @retval 0 Element deleted successfully.
 * @retval -EINVAL One or more arguments are invalid or the map type does not support delete.
 * @retval -ENOENT No element matching @p key exists.
 */
int ebpf_map_delete_elem(struct ebpf_map *map, const void *key);

/**
 * @brief Write data to a ring buffer map.
 *
 * @param[in] map Ring buffer map.
 * @param[in] data Pointer to data to write.
 * @param[in] size Size of data in bytes.
 * @param[in] flags Update flags.
 * @retval 0 Record written successfully.
 * @retval -EINVAL @p map is not a ring buffer map.
 * @retval -ENOMEM The ring buffer does not have enough free space.
 */
int ebpf_ringbuf_output(struct ebpf_map *map, const void *data,
			uint32_t size, uint64_t flags);

/**
 * @brief Read one record from a ring buffer map.
 *
 * @param[in] map Ring buffer map.
 * @param[out] data Destination buffer, or NULL to discard the record payload.
 * @param[in] capacity Capacity of @p data in bytes.
 * @param[out] size_out On success, receives the payload size.
 * @retval 0 Record read successfully.
 * @retval -EINVAL One or more arguments are invalid or @p map is not a ring buffer map.
 * @retval -EAGAIN The ring buffer is empty.
 * @retval -EMSGSIZE The next record does not fit in @p data.
 * @retval -EIO The ring buffer contents are malformed or truncated.
 */
int ebpf_ringbuf_read(struct ebpf_map *map, void *data,
		      uint32_t capacity, uint32_t *size_out);

/** @cond INTERNAL_HIDDEN */

/**
 * @brief Find a map by runtime-assigned handle.
 *
 * @param[in] id Runtime-assigned map handle.
 * @retval NULL No map with handle @p id was found.
 * @retval map Pointer to the matching map descriptor.
 */
struct ebpf_map *ebpf_map_from_id(uint32_t id);

static inline uint32_t ebpf_map_data_size(const struct ebpf_map *map)
{
	if (map == NULL) {
		return 0U;
	}

	switch (map->type) {
	case EBPF_MAP_TYPE_ARRAY:
		return map->value_size * map->max_entries;
	case EBPF_MAP_TYPE_RINGBUF:
		return sizeof(struct ebpf_ringbuf_data) + map->max_entries;
	default:
		return map->value_size * map->max_entries;
	}
}

/** @endcond */

/**
 * @brief Get the runtime-assigned small integer handle for one map.
 *
 * The handle is stable for the lifetime of the current image and is derived
 * from the static iterable-section registration order. A NULL map returns
 * handle 0, which is never assigned to a valid map.
 *
 * @param[in] map Map descriptor.
 * @return Runtime-assigned handle, or 0 if @p map is NULL.
 */
uint32_t ebpf_map_get_id(const struct ebpf_map *map);

#ifdef __cplusplus
}
#endif

#endif /* ZEPHYR_INCLUDE_EBPF_MAP_H_ */
