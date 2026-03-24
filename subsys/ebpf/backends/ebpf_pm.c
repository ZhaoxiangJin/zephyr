/*
 * SPDX-FileCopyrightText: Copyright 2026 NXP
 *
 * SPDX-License-Identifier: Apache-2.0
 */

#include <zephyr/kernel.h>
#include <zephyr/pm/pm.h>

#include <zephyr/ebpf/ebpf_attach_target.h>

static const struct ebpf_attach_target pm_entry_target =
	EBPF_ATTACH_TARGET_PM(EBPF_PM_ATTACH_STATE_ENTRY);
static const struct ebpf_attach_target pm_exit_target =
	EBPF_ATTACH_TARGET_PM(EBPF_PM_ATTACH_STATE_EXIT);

/** @brief Dispatch a PM state-entry event to attached eBPF programs. */
static void ebpf_pm_state_entry(enum pm_state state, uint8_t substate_id)
{
	if (ebpf_attach_target_is_active(&pm_entry_target)) {
		struct ebpf_ctx_pm ctx = {
			.state = (uint32_t)state,
			.substate_id = substate_id,
			.cpu_id = arch_curr_cpu()->id,
		};

		ebpf_attach_target_dispatch(&pm_entry_target, &ctx, sizeof(ctx));
	}
}

/** @brief Dispatch a PM state-exit event to attached eBPF programs. */
static void ebpf_pm_state_exit(enum pm_state state, uint8_t substate_id)
{
	if (ebpf_attach_target_is_active(&pm_exit_target)) {
		struct ebpf_ctx_pm ctx = {
			.state = (uint32_t)state,
			.substate_id = substate_id,
			.cpu_id = arch_curr_cpu()->id,
		};

		ebpf_attach_target_dispatch(&pm_exit_target, &ctx, sizeof(ctx));
	}
}

static struct pm_notifier ebpf_pm_notifier = {
	.substate_entry = ebpf_pm_state_entry,
	.substate_exit = ebpf_pm_state_exit,
	.report_substate = true,
};

/** @brief Register the PM notifier backend with Zephyr power management. */
static int ebpf_pm_backend_init(void)
{
	pm_notifier_register(&ebpf_pm_notifier);

	return 0;
}

SYS_INIT(ebpf_pm_backend_init, POST_KERNEL, CONFIG_EBPF_BACKEND_INIT_PRIORITY);
