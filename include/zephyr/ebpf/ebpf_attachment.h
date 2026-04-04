/*
 * SPDX-FileCopyrightText: Copyright 2026 NXP
 *
 * SPDX-License-Identifier: Apache-2.0
 */

/**
 * @file
 * @brief Public runtime eBPF attachment handle API.
 * @ingroup ebpf
 */

#ifndef ZEPHYR_INCLUDE_EBPF_ATTACHMENT_H_
#define ZEPHYR_INCLUDE_EBPF_ATTACHMENT_H_

#ifdef __cplusplus
extern "C" {
#endif

struct ebpf_attachment;

/**
 * @brief Disable, detach, and destroy one runtime attachment.
 *
 * This synchronously removes the attachment from the live dispatch path before
 * freeing the underlying runtime object.
 *
 * @param[in,out] attachment Attachment handle.
 *
 * @retval 0 Attachment destroyed successfully.
 * @retval -EINVAL @p attachment is NULL.
 * @return Negative errno from synchronized disable or detach otherwise.
 */
int ebpf_attachment_destroy(struct ebpf_attachment *attachment);

/**
 * @brief Enable one runtime attachment.
 *
 * @param[in,out] attachment Attachment handle.
 *
 * @retval 0 Attachment enabled successfully.
 * @retval -EINVAL @p attachment is NULL.
 * @return Negative errno from verification or enable commit otherwise.
 */
int ebpf_attachment_enable(struct ebpf_attachment *attachment);

/**
 * @brief Disable one runtime attachment.
 *
 * @param[in,out] attachment Attachment handle.
 *
 * @retval 0 Attachment disabled successfully.
 * @retval -EINVAL @p attachment is NULL.
 * @return Negative errno from disable otherwise.
 */
int ebpf_attachment_disable(struct ebpf_attachment *attachment);

/**
 * @brief Get the runtime name of one attachment.
 *
 * @param[in] attachment Attachment handle.
 *
 * @return Attachment name, or NULL if @p attachment is NULL.
 */
const char *ebpf_attachment_name(const struct ebpf_attachment *attachment);

/**
 * @brief Get the hook name bound by one attachment.
 *
 * @param[in] attachment Attachment handle.
 *
 * @return Hook name, or NULL if @p attachment is NULL.
 */
const char *ebpf_attachment_hook_name(const struct ebpf_attachment *attachment);

#ifdef __cplusplus
}
#endif

#endif /* ZEPHYR_INCLUDE_EBPF_ATTACHMENT_H_ */
