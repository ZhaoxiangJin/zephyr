/*
 * SPDX-FileCopyrightText: Copyright 2026 NXP
 *
 * SPDX-License-Identifier: Apache-2.0
 */

#include <errno.h>
#include <stddef.h>
#include <string.h>

#include <zephyr/sys/util.h>

#include "ebpf_hook_internal.h"

struct ebpf_hook_desc {
	enum ebpf_hook_id hook_id;
	const char *name;
	struct ebpf_attach_target target;
	uint32_t ctx_size;
};

static const struct ebpf_hook_desc ebpf_hooks[] = {
	{
		.hook_id = EBPF_HOOK_THREAD_SWITCHED_IN,
		.name = "kernel/thread_switched_in",
		.target = EBPF_ATTACH_TARGET_TRACING(EBPF_TRACING_ATTACH_THREAD_SWITCHED_IN),
		.ctx_size = sizeof(struct ebpf_ctx_thread),
	},
	{
		.hook_id = EBPF_HOOK_THREAD_SWITCHED_OUT,
		.name = "kernel/thread_switched_out",
		.target = EBPF_ATTACH_TARGET_TRACING(EBPF_TRACING_ATTACH_THREAD_SWITCHED_OUT),
		.ctx_size = sizeof(struct ebpf_ctx_thread),
	},
	{
		.hook_id = EBPF_HOOK_ISR_ENTER,
		.name = "kernel/isr_enter",
		.target = EBPF_ATTACH_TARGET_TRACING(EBPF_TRACING_ATTACH_ISR_ENTER),
		.ctx_size = sizeof(struct ebpf_ctx_isr),
	},
	{
		.hook_id = EBPF_HOOK_ISR_EXIT,
		.name = "kernel/isr_exit",
		.target = EBPF_ATTACH_TARGET_TRACING(EBPF_TRACING_ATTACH_ISR_EXIT),
		.ctx_size = sizeof(struct ebpf_ctx_isr),
	},
	{
		.hook_id = EBPF_HOOK_IDLE_ENTER,
		.name = "kernel/idle_enter",
		.target = EBPF_ATTACH_TARGET_TRACING(EBPF_TRACING_ATTACH_IDLE_ENTER),
		.ctx_size = sizeof(struct ebpf_ctx_idle),
	},
	{
		.hook_id = EBPF_HOOK_IDLE_EXIT,
		.name = "kernel/idle_exit",
		.target = EBPF_ATTACH_TARGET_TRACING(EBPF_TRACING_ATTACH_IDLE_EXIT),
		.ctx_size = sizeof(struct ebpf_ctx_idle),
	},
	{
		.hook_id = EBPF_HOOK_PM_STATE_ENTRY,
		.name = "pm/state_entry",
		.target = EBPF_ATTACH_TARGET_PM(EBPF_PM_ATTACH_STATE_ENTRY),
		.ctx_size = sizeof(struct ebpf_ctx_pm),
	},
	{
		.hook_id = EBPF_HOOK_PM_STATE_EXIT,
		.name = "pm/state_exit",
		.target = EBPF_ATTACH_TARGET_PM(EBPF_PM_ATTACH_STATE_EXIT),
		.ctx_size = sizeof(struct ebpf_ctx_pm),
	},
};

static const struct ebpf_hook_desc *ebpf_hook_find(enum ebpf_hook_id hook_id)
{
	for (size_t i = 0; i < ARRAY_SIZE(ebpf_hooks); i++) {
		if (ebpf_hooks[i].hook_id == hook_id) {
			return &ebpf_hooks[i];
		}
	}

	return NULL;
}

static const struct ebpf_hook_desc *ebpf_hook_find_by_name(const char *name)
{
	if (name == NULL) {
		return NULL;
	}

	for (size_t i = 0; i < ARRAY_SIZE(ebpf_hooks); i++) {
		if (strcmp(ebpf_hooks[i].name, name) == 0) {
			return &ebpf_hooks[i];
		}
	}

	return NULL;
}

bool ebpf_hook_id_is_valid(enum ebpf_hook_id hook_id)
{
	return ebpf_hook_find(hook_id) != NULL;
}

const char *ebpf_hook_id_name(enum ebpf_hook_id hook_id)
{
	const struct ebpf_hook_desc *hook = ebpf_hook_find(hook_id);

	return hook != NULL ? hook->name : "invalid";
}

int ebpf_hook_name_to_id(const char *name, enum ebpf_hook_id *hook_id)
{
	const struct ebpf_hook_desc *hook = ebpf_hook_find_by_name(name);

	if (hook == NULL || hook_id == NULL) {
		return -EINVAL;
	}

	*hook_id = hook->hook_id;

	return 0;
}

int ebpf_hook_id_to_target(enum ebpf_hook_id hook_id,
			   struct ebpf_attach_target *target)
{
	const struct ebpf_hook_desc *hook = ebpf_hook_find(hook_id);

	if (hook == NULL || target == NULL) {
		return -EINVAL;
	}

	*target = hook->target;

	return 0;
}

int ebpf_hook_name_to_target(const char *name,
			     struct ebpf_attach_target *target)
{
	const struct ebpf_hook_desc *hook = ebpf_hook_find_by_name(name);

	if (hook == NULL || target == NULL) {
		return -EINVAL;
	}

	*target = hook->target;

	return 0;
}

int ebpf_attach_target_to_hook_id(const struct ebpf_attach_target *target,
				  enum ebpf_hook_id *hook_id)
{
	if (target == NULL || hook_id == NULL) {
		return -EINVAL;
	}

	for (size_t i = 0; i < ARRAY_SIZE(ebpf_hooks); i++) {
		if (ebpf_hooks[i].target.backend == target->backend &&
		    ebpf_hooks[i].target.point == target->point) {
			*hook_id = ebpf_hooks[i].hook_id;
			return 0;
		}
	}

	return -EINVAL;
}

int ebpf_hook_get_info(enum ebpf_hook_id hook_id, struct ebpf_hook_info *info)
{
	const struct ebpf_hook_desc *hook = ebpf_hook_find(hook_id);

	if (hook == NULL || info == NULL) {
		return -EINVAL;
	}

	info->hook_id = hook->hook_id;
	info->name = hook->name;
	info->ctx_size = hook->ctx_size;

	return 0;
}
