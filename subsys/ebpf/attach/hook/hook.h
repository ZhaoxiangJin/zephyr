/*
 * SPDX-FileCopyrightText: Copyright 2026 NXP
 *
 * SPDX-License-Identifier: Apache-2.0
 */

/**
 * @file
 * @brief Internal eBPF hook-to-target translation.
 *
 * @note Visibility: eBPF subsystem internals only.
 */

#ifndef ZEPHYR_SUBSYS_EBPF_HOOK_H_
#define ZEPHYR_SUBSYS_EBPF_HOOK_H_

#include "../target/target_types.h"

#ifdef __cplusplus
extern "C" {
#endif

/**
 * @brief Resolve a stable hook name to its attach target descriptor.
 *
 * @param[in]  name   Registered hook name.
 * @param[out] target Receives the attach target on success.
 *
 * @retval 0       Target resolved.
 * @retval -EINVAL @p name does not match a registered hook, or @p target is NULL.
 */
int ebpf_hook_name_to_target(const char *name, struct ebpf_attach_target *target);

#ifdef __cplusplus
}
#endif

#endif /* ZEPHYR_SUBSYS_EBPF_HOOK_H_ */
