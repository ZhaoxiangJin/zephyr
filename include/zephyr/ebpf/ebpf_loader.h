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

#ifdef __cplusplus
extern "C" {
#endif

struct ebpf_loader_handle;

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
 * @brief Disable and unload one loaded probe object.
 *
 * @param[in,out] handle Loaded runtime handle.

 * @retval 0 Object unloaded successfully.
 * @retval -EINVAL @p handle is NULL.
 * @return Negative errno from disable or bundle destroy otherwise.
 */
int ebpf_loader_unload(struct ebpf_loader_handle *handle);

/**
 * @brief Enable one loaded probe object.
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
 * @brief Copy one map value out of a loaded bundle by handle.
 *
 * Looks up @p map_name inside the bundle owned by @p handle, then copies the
 * value associated with @p key into @p value_out while holding the handle
 * lock. Callers never observe a bundle-owned map pointer, which keeps the
 * bundle's lifetime invariants intact.
 *
 * @param[in] handle Loaded runtime handle.
 * @param[in] map_name Map name inside the loaded bundle.
 * @param[in] key Pointer to the lookup key.
 * @param[out] value_out Destination buffer for the copied value.
 * @param[in] value_size Capacity of @p value_out in bytes.

 * @retval 0 Value copied successfully.
 * @retval -EINVAL One or more arguments are invalid.
 * @retval -ENOENT No owned map or element matches @p map_name and @p key.
 * @retval -EMSGSIZE @p value_out is too small for the map value type.
 */
int ebpf_loader_map_lookup_copy(struct ebpf_loader_handle *handle, const char *map_name,
				const void *key, void *value_out, size_t value_size);

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
