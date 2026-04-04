/*
 * SPDX-FileCopyrightText: Copyright 2026 NXP
 *
 * SPDX-License-Identifier: Apache-2.0
 */

/**
 * @file
 * @brief Internal eBPF map runtime interfaces.
 *
 * @note Visibility: eBPF subsystem components only (bundle, loader, vm,
 *       verifier, helpers). Not for application code. Not for map backends.
 */

#ifndef ZEPHYR_SUBSYS_EBPF_MAP_H_
#define ZEPHYR_SUBSYS_EBPF_MAP_H_

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

/**
 * @brief Create one dynamic runtime map and register it with the map registry.
 *
 * The map is created without an owner. Callers must either bind it to an owner
 * via ebpf_map_claim_owner() or destroy it via ebpf_map_destroy() once done.
 *
 * @param[in] spec Map description.
 * @param[out] map_out Receives the newly created map.

 * @retval 0 Map created successfully.
 * @retval -EINVAL @p spec is invalid or @p map_out is NULL.
 * @retval -ENOMEM Allocation failed.
 * @return Negative errno from backend initialization otherwise.
 */
int ebpf_map_create(const struct ebpf_map_spec *spec, struct ebpf_map **map_out);

/**
 * @brief Bind one ownerless map to an owner object.
 *
 * Establishes the invariant that only @p owner can subsequently destroy the
 * map via ebpf_map_destroy_owned(). Typically called by the bundle layer
 * right after ebpf_map_create() to link the map's lifetime to a bundle.
 *
 * @param[in,out] map Map to bind.
 * @param[in] owner Opaque owner token (must be non-NULL).

 * @retval 0 Ownership claimed successfully.
 * @retval -EINVAL @p map or @p owner is NULL, or the map is not dynamic.
 * @retval -EBUSY The map already has an owner.
 */
int ebpf_map_claim_owner(struct ebpf_map *map, void *owner);

/**
 * @brief Destroy one ownerless map and release its storage.
 *
 * Only succeeds when the map has no owner; this prevents accidental
 * destruction of maps that still belong to a bundle. For owner-scoped teardown
 * use ebpf_map_destroy_owned() instead.
 *
 * @param[in,out] map Map to destroy.

 * @retval 0 Map destroyed successfully.
 * @retval -EINVAL @p map is NULL or not dynamic.
 * @retval -EBUSY The map has an owner; use ebpf_map_destroy_owned().
 * @retval -ENOENT The map is not registered (double-destroy).
 */
int ebpf_map_destroy(struct ebpf_map *map);

/**
 * @brief Destroy one owned map after verifying the owner matches.
 *
 * Used by the owner (typically a bundle) during teardown. Fails with -EPERM
 * if @p owner does not match the bound owner, which catches cross-owner
 * destruction bugs.
 *
 * @param[in,out] map Map to destroy.
 * @param[in] owner Expected owner token.

 * @retval 0 Map destroyed successfully.
 * @retval -EINVAL @p map or @p owner is NULL or the map is not dynamic.
 * @retval -EPERM The map is owned by a different object.
 * @retval -ENOENT The map is not registered (double-destroy).
 */
int ebpf_map_destroy_owned(struct ebpf_map *map, void *owner);

/**
 * @brief Get the runtime ID assigned to one map.
 *
 * Runtime IDs are monotonically assigned at creation time and are embedded
 * into program instructions by the loader relocation pass so the verifier
 * and VM can resolve map references.
 *
 * @param[in] map Map to query.
 *
 * @retval id Non-zero runtime ID.
 * @retval 0 @p map is NULL or has been destroyed.
 */
uint32_t ebpf_map_get_id(const struct ebpf_map *map);

/**
 * @brief Get the name of one map.
 *
 * The returned pointer aliases storage owned by the map and is valid for
 * the lifetime of the map.
 *
 * @param[in] map Map to query.
 *
 * @retval name Map name string.
 * @retval NULL @p map is NULL.
 */
const char *ebpf_map_get_name(const struct ebpf_map *map);

/**
 * @brief Get the value size of one map in bytes.
 *
 * @param[in] map Map to query.
 *
 * @retval size Value size in bytes.
 * @retval 0 @p map is NULL.
 */
uint32_t ebpf_map_get_value_size(const struct ebpf_map *map);

/**
 * @brief Resolve one runtime map ID back to its map pointer.
 *
 * Used on the hot path by the interpreter and by helpers to translate IDs
 * embedded in program instructions into live map objects.
 *
 * @param[in] id Runtime map ID as returned by ebpf_map_get_id().
 *
 * @retval map The registered map matching @p id.
 * @retval NULL @p id is zero, or no registered map matches it.
 */
struct ebpf_map *ebpf_map_from_id(uint32_t id);

#ifdef __cplusplus
}
#endif

#endif /* ZEPHYR_SUBSYS_EBPF_MAP_H_ */
