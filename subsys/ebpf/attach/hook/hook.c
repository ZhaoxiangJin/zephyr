/*
 * SPDX-FileCopyrightText: Copyright 2026 NXP
 *
 * SPDX-License-Identifier: Apache-2.0
 */

#include <errno.h>
#include <stddef.h>
#include <string.h>

#include <zephyr/sys/util.h>

#include "hook.h"

struct ebpf_hook_desc {
	const char *name;
	struct ebpf_attach_target target;
};

static const struct ebpf_hook_desc ebpf_hooks[] = {
	{
		.name = "kernel/thread_switched_in",
		.target = EBPF_ATTACH_TARGET_TRACING(EBPF_TRACING_ATTACH_THREAD_SWITCHED_IN),
	},
	{
		.name = "kernel/thread_switched_out",
		.target = EBPF_ATTACH_TARGET_TRACING(EBPF_TRACING_ATTACH_THREAD_SWITCHED_OUT),
	},
	{
		.name = "kernel/isr_enter",
		.target = EBPF_ATTACH_TARGET_TRACING(EBPF_TRACING_ATTACH_ISR_ENTER),
	},
	{
		.name = "kernel/isr_exit",
		.target = EBPF_ATTACH_TARGET_TRACING(EBPF_TRACING_ATTACH_ISR_EXIT),
	},
	{
		.name = "kernel/idle_enter",
		.target = EBPF_ATTACH_TARGET_TRACING(EBPF_TRACING_ATTACH_IDLE_ENTER),
	},
	{
		.name = "kernel/idle_exit",
		.target = EBPF_ATTACH_TARGET_TRACING(EBPF_TRACING_ATTACH_IDLE_EXIT),
	},
	{
		.name = "pm/state_entry",
		.target = EBPF_ATTACH_TARGET_PM(EBPF_PM_ATTACH_STATE_ENTRY),
	},
	{
		.name = "pm/state_exit",
		.target = EBPF_ATTACH_TARGET_PM(EBPF_PM_ATTACH_STATE_EXIT),
	},
};

int ebpf_hook_name_to_target(const char *name, struct ebpf_attach_target *target)
{
	if (name == NULL || target == NULL) {
		return -EINVAL;
	}

	for (size_t i = 0; i < ARRAY_SIZE(ebpf_hooks); i++) {
		if (strcmp(ebpf_hooks[i].name, name) == 0) {
			*target = ebpf_hooks[i].target;
			return 0;
		}
	}

	return -EINVAL;
}
