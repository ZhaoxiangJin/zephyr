/*
 * SPDX-FileCopyrightText: Copyright 2026 NXP
 *
 * SPDX-License-Identifier: Apache-2.0
 */

/**
 * @file
 * @brief Internal eBPF attachment-target runtime interfaces.
 */

#ifndef ZEPHYR_SUBSYS_EBPF_ATTACH_TARGET_INTERNAL_H_
#define ZEPHYR_SUBSYS_EBPF_ATTACH_TARGET_INTERNAL_H_

#include <stdbool.h>
#include <stdint.h>

#include "../prog/ebpf_prog_internal.h"

#ifdef __cplusplus
extern "C" {
#endif

const char *ebpf_attach_target_name(const struct ebpf_attach_target *target);

bool ebpf_attach_target_is_valid(const struct ebpf_attach_target *target);

bool ebpf_prog_can_attach_target(enum ebpf_prog_type type,
				 const struct ebpf_attach_target *target);

bool ebpf_attach_target_is_active(const struct ebpf_attach_target *target);

int ebpf_attach_targets_init(void);

void ebpf_attach_target_dispatch(const struct ebpf_attach_target *target,
				 void *ctx, uint32_t ctx_size);

void ebpf_attach_target_lock(const struct ebpf_attach_target *target);

void ebpf_attach_target_unlock(const struct ebpf_attach_target *target);

int ebpf_attach_target_enable_prog_locked(const struct ebpf_attach_target *target,
					  struct ebpf_prog *prog,
					  uint32_t session_seq);

void ebpf_attach_target_disable_prog_locked(const struct ebpf_attach_target *target,
					    const struct ebpf_prog *prog);

void ebpf_attach_target_disable_prog_sync_locked(const struct ebpf_attach_target *target,
						 const struct ebpf_prog *prog);

#ifdef __cplusplus
}
#endif

#endif /* ZEPHYR_SUBSYS_EBPF_ATTACH_TARGET_INTERNAL_H_ */

