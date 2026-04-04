/*
 * SPDX-FileCopyrightText: Copyright 2026 NXP
 *
 * SPDX-License-Identifier: Apache-2.0
 */

/**
 * @file
 * @brief Public runtime loader control API.
 * @ingroup ebpf
 */

#ifndef ZEPHYR_INCLUDE_EBPF_LOADER_H_
#define ZEPHYR_INCLUDE_EBPF_LOADER_H_

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#include <zephyr/ebpf/ebpf_map.h>

#ifdef __cplusplus
extern "C" {
#endif

struct ebpf_loader_handle;
struct ebpf_loader_status;

/** @brief Snapshot of one loaded runtime bundle for control-plane consumers. */
struct ebpf_loader_status {
	const char *name;
	uint32_t ttl_ms;
	bool enabled;
	bool auto_unloaded;
	bool loaded;
};

/** @brief Snapshot of one runtime-owned map inside a loaded bundle. */
struct ebpf_loader_map_info {
	const char *name;
	enum ebpf_map_type type;
	uint32_t key_size;
	uint32_t value_size;
	uint32_t max_entries;
};

/** @brief Registry enumeration callback for runtime-loaded bundles. */
typedef bool (*ebpf_loader_foreach_cb_t)(const struct ebpf_loader_status *status,
				         void *user_data);

/**
 * @brief Parse and instantiate one runtime probe object.
 *
 * This creates the bundle, maps, and attachments, but does not enable them.
 *
 * @param[in] image Probe object bytes.
 * @param[in] image_size Size of @p image in bytes.
 * @param[out] handle_out Receives the loaded runtime handle.

 * @retval 0 Object loaded successfully.
 * @retval -EINVAL The object format is malformed.
 * @retval -ENOMEM Allocation failed.
 * @retval -EBADMSG The object authentication check failed.
 * @return Negative errno from bundle, map, or attachment creation otherwise.
 */
int ebpf_loader_load(const void *image, size_t image_size,
		     struct ebpf_loader_handle **handle_out);

/**
 * @brief Enable one loaded probe object.
 *
 * If the image declared a non-zero TTL, successful enable also schedules an
 * automatic unload when the TTL expires.
 *
 * @param[in,out] handle Loaded runtime handle.

 * @retval 0 Object enabled successfully.
 * @retval -EINVAL @p handle is NULL.
 * @return Negative errno from bundle enable otherwise.
 */
int ebpf_loader_enable(struct ebpf_loader_handle *handle);

/**
 * @brief Disable one loaded probe object without unloading it.
 *
 * @param[in,out] handle Loaded runtime handle.

 * @retval 0 Object disabled successfully.
 * @retval -EINVAL @p handle is NULL.
 * @return Negative errno from bundle disable otherwise.
 */
int ebpf_loader_disable(struct ebpf_loader_handle *handle);

/**
 * @brief Disable and unload one loaded probe object.
 *
 * @param[in,out] handle Loaded runtime handle.

 * @retval 0 Object unloaded successfully.
 * @retval -EINVAL @p handle is NULL.
 * @return Negative errno from disable or bundle destroy otherwise.
 */
int ebpf_loader_unload(struct ebpf_loader_handle *handle);

/**
 * @brief Enable one loaded probe object by stable bundle name.
 *
 * @param[in] name Loaded bundle name.

 * @retval 0 Object enabled successfully.
 * @retval -EINVAL @p name is NULL.
 * @retval -ENOENT No loaded object matches @p name.
 * @return Negative errno from bundle enable otherwise.
 */
int ebpf_loader_enable_by_name(const char *name);

/**
 * @brief Disable one loaded probe object by stable bundle name.
 *
 * @param[in] name Loaded bundle name.

 * @retval 0 Object disabled successfully.
 * @retval -EINVAL @p name is NULL.
 * @retval -ENOENT No loaded object matches @p name.
 * @return Negative errno from bundle disable otherwise.
 */
int ebpf_loader_disable_by_name(const char *name);

/**
 * @brief Unload one loaded probe object by stable bundle name.
 *
 * @param[in] name Loaded bundle name.

 * @retval 0 Object unloaded successfully.
 * @retval -EINVAL @p name is NULL.
 * @retval -ENOENT No loaded object matches @p name.
 * @return Negative errno from unload otherwise.
 */
int ebpf_loader_unload_by_name(const char *name);

/**
 * @brief Fill one control-plane status snapshot by loaded bundle name.
 *
 * @param[in] name Loaded bundle name.
 * @param[out] status_out Receives the status snapshot.

 * @retval 0 Status filled successfully.
 * @retval -EINVAL Any argument is NULL.
 * @retval -ENOENT No loaded object matches @p name.
 */
int ebpf_loader_status_by_name(const char *name, struct ebpf_loader_status *status_out);

/**
 * @brief Fill one runtime-owned map snapshot by bundle and map name.
 *
 * @param[in] bundle_name Loaded bundle name.
 * @param[in] map_name Map name inside the loaded bundle.
 * @param[out] info_out Receives the map snapshot.

 * @retval 0 Map snapshot filled successfully.
 * @retval -EINVAL Any argument is NULL.
 * @retval -ENOENT No loaded bundle or map matches the supplied names.
 */
int ebpf_loader_map_info_by_name(const char *bundle_name, const char *map_name,
				 struct ebpf_loader_map_info *info_out);

/**
 * @brief Copy one map value out of a loaded bundle by stable names.
 *
 * This helper looks up a loaded runtime bundle and one of its owned maps by
 * name, then copies the value for @p key into @p value_out before releasing
 * the loader locks. It avoids exposing bundle-owned map pointers whose
 * lifetime could otherwise race with concurrent unload operations.
 *
 * @param[in] bundle_name Loaded bundle name.
 * @param[in] map_name Map name inside the loaded bundle.
 * @param[in] key Pointer to the lookup key.
 * @param[out] value_out Destination buffer for the copied value.
 * @param[in] value_size Capacity of @p value_out in bytes.

 * @retval 0 Value copied successfully.
 * @retval -EINVAL One or more arguments are invalid.
 * @retval -ENOENT No loaded bundle, map, or element matches the supplied
 *         names and key.
 * @retval -EMSGSIZE @p value_out is too small for the map value type.
 */
int ebpf_loader_map_lookup_copy_by_name(const char *bundle_name, const char *map_name,
					const void *key, void *value_out, size_t value_size);

/**
 * @brief Enumerate all loaded runtime bundles.
 *
 * The callback runs while the loader registry lock is held, so it must not
 * call mutating loader APIs.
 *
 * @param[in] cb Enumeration callback.
 * @param[in,out] user_data Opaque user data forwarded to @p cb.
 */
void ebpf_loader_foreach(ebpf_loader_foreach_cb_t cb, void *user_data);

/**
 * @brief Get the stable name of one loaded probe object.
 *
 * @param[in] handle Loaded runtime handle.
 * @return Object name, or NULL if @p handle is NULL.
 */
const char *ebpf_loader_name(const struct ebpf_loader_handle *handle);

#ifdef __cplusplus
}
#endif

#endif /* ZEPHYR_INCLUDE_EBPF_LOADER_H_ */
