/*
 * SPDX-FileCopyrightText: Copyright 2026 NXP
 *
 * SPDX-License-Identifier: Apache-2.0
 */

/**
 * @file
 * @brief Internal eBPF attachment object interfaces.
 *
 * @note Visibility: eBPF subsystem internals only.
 */

#ifndef ZEPHYR_SUBSYS_EBPF_ATTACHMENT_H_
#define ZEPHYR_SUBSYS_EBPF_ATTACHMENT_H_

#include <zephyr/ebpf/ebpf_attachment.h>

#include "../prog/prog.h"

#ifdef __cplusplus
extern "C" {
#endif

/**
 * @brief Attachment description used to create one runtime attachment.
 *
 * Callers such as bundle management and the loader construct this descriptor
 * before passing it to ebpf_attachment_create() or ebpf_bundle_add_attachment().
 * It describes the attachment to create, but it is not part of the public
 * attachment handle API or the private runtime attachment object layout.
 *
 * This remains internal for now because creation still depends on internal
 * bytecode and program-family types.
 */
struct ebpf_attachment_spec {
	const char *name;
	enum ebpf_prog_type type;
	const struct ebpf_insn *insns;
	uint32_t insn_cnt;
	const char *hook_name;
};

/**
 * @brief Create one attachment and bind it to a named hook.
 *
 * Copies @p spec's name, hook name, and instruction buffer into attachment-
 * owned storage, compiles the program, resolves @p spec->hook_name to a hook
 * target, and attaches the program to it. On success the attachment is in the
 * disabled state; call @ref ebpf_attachment_enable to start dispatching.
 *
 * @param[in]  spec            Attachment description; all fields are required.
 * @param[out] attachment_out  Receives the new attachment on success.
 *
 * @retval 0        Attachment created and bound to the hook.
 * @retval -EINVAL  @p spec or @p attachment_out is invalid.
 * @retval -ENOMEM  Allocation of attachment storage failed.
 * @retval -errno   Program compile, hook resolution, or attach failure.
 */
int ebpf_attachment_create(const struct ebpf_attachment_spec *spec,
			   struct ebpf_attachment **attachment_out);

/**
 * @brief Disable an attachment and wait for in-flight invocations to drain.
 *
 * After this call returns 0, no hook dispatch can observe the attachment's
 * program and all running invocations have completed. The attachment remains
 * bound to its hook and may be re-enabled.
 *
 * @param[in] attachment Attachment to quiesce.
 *
 * @retval 0        Attachment disabled and quiesced.
 * @retval -EINVAL  @p attachment is NULL.
 * @retval -errno   Underlying program disable failure.
 */
int ebpf_attachment_disable_sync(struct ebpf_attachment *attachment);

#ifdef __cplusplus
}
#endif

#endif /* ZEPHYR_SUBSYS_EBPF_ATTACHMENT_H_ */
