/*
 * SPDX-FileCopyrightText: Copyright 2026 NXP
 *
 * SPDX-License-Identifier: Apache-2.0
 */

/**
 * @file
 * @brief Internal runtime-owned eBPF bundle interfaces.
 *
 * @note Visibility: eBPF subsystem internals only; not exposed to applications.
 */

#ifndef ZEPHYR_SUBSYS_EBPF_BUNDLE_H_
#define ZEPHYR_SUBSYS_EBPF_BUNDLE_H_

#include <zephyr/ebpf/ebpf_bundle.h>

#include "../attach/attachment.h"
#include "../map/map.h"

#ifdef __cplusplus
extern "C" {
#endif

struct ebpf_bundle;

/**
 * @brief Create one empty runtime bundle.
 *
 * The bundle duplicates @p name so the caller need not keep the string
 * alive. The returned bundle owns no maps or attachments until callers
 * add them with ebpf_bundle_add_map() or ebpf_bundle_add_attachment().
 *
 * @param[in] name Bundle name; duplicated into bundle-owned storage.
 * @param[out] bundle_out Receives the newly created bundle.

 * @retval 0 Bundle created successfully.
 * @retval -EINVAL @p name or @p bundle_out is NULL.
 * @retval -ENOMEM Allocation failed.
 */
int ebpf_bundle_create(const char *name, struct ebpf_bundle **bundle_out);

/**
 * @brief Destroy one bundle and every map and attachment it owns.
 *
 * Tears down attachments first so no running program can observe a freed
 * map, then destroys maps, then frees the bundle shell. Continues past
 * per-resource failures to avoid leaks and reports the first error.
 *
 * @param[in,out] bundle Bundle to destroy; must not be enabled.

 * @retval 0 Bundle and all owned resources destroyed successfully.
 * @retval -EINVAL @p bundle is NULL.
 * @return First negative errno from attachment or map destruction otherwise.
 */
int ebpf_bundle_destroy(struct ebpf_bundle *bundle);

/**
 * @brief Enable every attachment owned by @p bundle.
 *
 * Publishes all attachments onto their hooks. If any attachment fails to
 * enable, the operation rolls back by disabling every attachment and
 * returns the first error observed (enable or rollback-disable).
 *
 * @param[in,out] bundle Bundle to enable.

 * @retval 0 All attachments enabled successfully.
 * @retval -EINVAL @p bundle is NULL.
 * @return Negative errno from attachment enable or rollback otherwise.
 */
int ebpf_bundle_enable(struct ebpf_bundle *bundle);

/**
 * @brief Disable every attachment owned by @p bundle.
 *
 * Removes all attachments from their hooks. Continues past per-attachment
 * failures and reports the first error.
 *
 * @param[in,out] bundle Bundle to disable.

 * @retval 0 All attachments disabled successfully.
 * @retval -EINVAL @p bundle is NULL.
 * @return First negative errno from attachment disable otherwise.
 */
int ebpf_bundle_disable(struct ebpf_bundle *bundle);

/**
 * @brief Create one map owned by @p bundle.
 *
 * The bundle becomes the map's sole owner and will destroy it during
 * ebpf_bundle_destroy(). On failure no map is leaked.
 *
 * @param[in,out] bundle Owning bundle.
 * @param[in] spec Map specification.
 * @param[out] map_out Receives the new map; aliases bundle-owned storage.

 * @retval 0 Map created and attached to the bundle.
 * @retval -EINVAL One or more arguments are invalid.
 * @retval -ENOMEM Allocation failed.
 * @return Negative errno from map creation or ownership claim otherwise.
 */
int ebpf_bundle_add_map(struct ebpf_bundle *bundle,
			const struct ebpf_map_spec *spec,
			struct ebpf_map **map_out);

/**
 * @brief Create one attachment owned by @p bundle.
 *
 * The attachment is created in the disabled state; callers must invoke
 * ebpf_bundle_enable() to make it visible on the hot path.
 *
 * @param[in,out] bundle Owning bundle.
 * @param[in] spec Attachment specification.
 * @param[out] attachment_out Receives the new attachment; aliases
 *                            bundle-owned storage.

 * @retval 0 Attachment created and added to the bundle.
 * @retval -EINVAL One or more arguments are invalid.
 * @retval -ENOMEM Allocation failed.
 * @return Negative errno from attachment creation otherwise.
 */
int ebpf_bundle_add_attachment(struct ebpf_bundle *bundle,
			       const struct ebpf_attachment_spec *spec,
			       struct ebpf_attachment **attachment_out);

#ifdef __cplusplus
}
#endif

#endif /* ZEPHYR_SUBSYS_EBPF_BUNDLE_H_ */
