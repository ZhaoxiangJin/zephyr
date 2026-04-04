/*
 * SPDX-FileCopyrightText: Copyright 2026 NXP
 *
 * SPDX-License-Identifier: Apache-2.0
 */

/**
 * @file
 * @brief Internal eBPF hook-to-target translation interfaces.
 */

#ifndef ZEPHYR_SUBSYS_EBPF_HOOK_INTERNAL_H_
#define ZEPHYR_SUBSYS_EBPF_HOOK_INTERNAL_H_

#include <zephyr/ebpf/ebpf_attach_target.h>
#include <zephyr/ebpf/ebpf_hook.h>

#ifdef __cplusplus
extern "C" {
#endif

int ebpf_hook_id_to_target(enum ebpf_hook_id hook_id,
			   struct ebpf_attach_target *target);

int ebpf_hook_name_to_target(const char *name,
			     struct ebpf_attach_target *target);

int ebpf_attach_target_to_hook_id(const struct ebpf_attach_target *target,
				  enum ebpf_hook_id *hook_id);

#ifdef __cplusplus
}
#endif

#endif /* ZEPHYR_SUBSYS_EBPF_HOOK_INTERNAL_H_ */

