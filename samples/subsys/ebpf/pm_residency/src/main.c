/*
 * SPDX-FileCopyrightText: Copyright 2026 NXP
 *
 * SPDX-License-Identifier: Apache-2.0
 */

/**
 * @file
 * @brief eBPF PM residency profiler sample.
 *
 * Two eBPF programs observe PM notifier entry/exit events and accumulate
 * per-state entry counts and residency time. The application varies its idle
 * window to show how the platform PM policy responds.
 */

#include <zephyr/kernel.h>
#include <zephyr/pm/state.h>

#include <zephyr/ebpf/ebpf_attach_target.h>
#include <zephyr/ebpf/ebpf_helpers.h>
#include <zephyr/ebpf/ebpf_insn.h>
#include <zephyr/ebpf/ebpf_map.h>
#include <zephyr/ebpf/ebpf_prog.h>

#define REPORT_INTERVAL  K_SECONDS(4)
#define NUM_PHASES       4

struct pm_phase {
	const char *label;
	uint32_t sleep_ms;
};

static const struct pm_phase phases[NUM_PHASES] = {
	{ "worker sleep 10 ms", 10 },
	{ "worker sleep 50 ms", 50 },
	{ "worker sleep 200 ms", 200 },
	{ "worker sleep 1000 ms", 1000 },
};

static const char *pm_state_name(enum pm_state state)
{
	switch (state) {
	case PM_STATE_ACTIVE:
		return "active";
	case PM_STATE_RUNTIME_IDLE:
		return "runtime-idle";
	case PM_STATE_SUSPEND_TO_IDLE:
		return "suspend-to-idle";
	case PM_STATE_STANDBY:
		return "standby";
	case PM_STATE_SUSPEND_TO_RAM:
		return "suspend-to-ram";
	case PM_STATE_SUSPEND_TO_DISK:
		return "suspend-to-disk";
	case PM_STATE_SOFT_OFF:
		return "soft-off";
	default:
		return "unknown";
	}
}

static struct ebpf_insn pm_entry_code[] = {
	EBPF_CALL_HELPER(EBPF_HELPER_KTIME_GET_NS),
	EBPF_MOV64_REG(EBPF_REG_R6, EBPF_REG_R0),
	EBPF_LDX_MEM_W(EBPF_REG_R7, EBPF_REG_R1, 0),
	EBPF_STX_MEM_W(EBPF_REG_R10, EBPF_REG_R7, -4),
	EBPF_MOV64_REG(EBPF_REG_R2, EBPF_REG_R10),
	EBPF_ADD64_IMM(EBPF_REG_R2, -4),
	EBPF_MOV64_IMM(EBPF_REG_R1, 0),
	EBPF_CALL_HELPER(EBPF_HELPER_MAP_LOOKUP_ELEM),
	EBPF_JEQ_IMM(EBPF_REG_R0, 0, 1),
	EBPF_STX_MEM_DW(EBPF_REG_R0, EBPF_REG_R6, 0),
	EBPF_MOV64_REG(EBPF_REG_R2, EBPF_REG_R10),
	EBPF_ADD64_IMM(EBPF_REG_R2, -4),
	EBPF_MOV64_IMM(EBPF_REG_R1, 0),
	EBPF_CALL_HELPER(EBPF_HELPER_MAP_LOOKUP_ELEM),
	EBPF_JEQ_IMM(EBPF_REG_R0, 0, 3),
	EBPF_LDX_MEM_DW(EBPF_REG_R8, EBPF_REG_R0, 0),
	EBPF_ADD64_IMM(EBPF_REG_R8, 1),
	EBPF_STX_MEM_DW(EBPF_REG_R0, EBPF_REG_R8, 0),
	EBPF_MOV64_IMM(EBPF_REG_R0, 0),
	EBPF_EXIT_INSN(),
};

static struct ebpf_insn pm_exit_code[] = {
	EBPF_CALL_HELPER(EBPF_HELPER_KTIME_GET_NS),
	EBPF_MOV64_REG(EBPF_REG_R6, EBPF_REG_R0),
	EBPF_LDX_MEM_W(EBPF_REG_R7, EBPF_REG_R1, 0),
	EBPF_STX_MEM_W(EBPF_REG_R10, EBPF_REG_R7, -4),
	EBPF_MOV64_REG(EBPF_REG_R2, EBPF_REG_R10),
	EBPF_ADD64_IMM(EBPF_REG_R2, -4),
	EBPF_MOV64_IMM(EBPF_REG_R1, 0),
	EBPF_CALL_HELPER(EBPF_HELPER_MAP_LOOKUP_ELEM),
	EBPF_JEQ_IMM(EBPF_REG_R0, 0, 10),
	EBPF_LDX_MEM_DW(EBPF_REG_R8, EBPF_REG_R0, 0),
	EBPF_SUB64_REG(EBPF_REG_R6, EBPF_REG_R8),
	EBPF_MOV64_REG(EBPF_REG_R2, EBPF_REG_R10),
	EBPF_ADD64_IMM(EBPF_REG_R2, -4),
	EBPF_MOV64_IMM(EBPF_REG_R1, 0),
	EBPF_CALL_HELPER(EBPF_HELPER_MAP_LOOKUP_ELEM),
	EBPF_JEQ_IMM(EBPF_REG_R0, 0, 3),
	EBPF_LDX_MEM_DW(EBPF_REG_R8, EBPF_REG_R0, 0),
	EBPF_ADD64_REG(EBPF_REG_R8, EBPF_REG_R6),
	EBPF_STX_MEM_DW(EBPF_REG_R0, EBPF_REG_R8, 0),
	EBPF_MOV64_IMM(EBPF_REG_R0, 0),
	EBPF_EXIT_INSN(),
};

EBPF_MAP_DEFINE(entry_ts_map, EBPF_MAP_TYPE_ARRAY,
		sizeof(uint32_t), sizeof(uint64_t), PM_STATE_COUNT);
EBPF_MAP_DEFINE(entry_count_map, EBPF_MAP_TYPE_ARRAY,
		sizeof(uint32_t), sizeof(uint64_t), PM_STATE_COUNT);
EBPF_MAP_DEFINE(residency_map, EBPF_MAP_TYPE_ARRAY,
		sizeof(uint32_t), sizeof(uint64_t), PM_STATE_COUNT);

EBPF_PROG_DEFINE(pm_entry, EBPF_PROG_TYPE_PM,
		 pm_entry_code, ARRAY_SIZE(pm_entry_code));
EBPF_PROG_DEFINE(pm_exit, EBPF_PROG_TYPE_PM,
		 pm_exit_code, ARRAY_SIZE(pm_exit_code));

#define WORKER_STACK_SIZE 1024
#define WORKER_PRIORITY   7

static K_THREAD_STACK_DEFINE(worker_stack, WORKER_STACK_SIZE);
static struct k_thread worker_thread;
static volatile uint32_t worker_sleep_ms = 10;

static void worker_entry(void *p1, void *p2, void *p3)
{
	ARG_UNUSED(p1);
	ARG_UNUSED(p2);
	ARG_UNUSED(p3);

	while (1) {
		k_sleep(K_MSEC(worker_sleep_ms));
	}
}

int main(void)
{
	uint64_t prev_entries[PM_STATE_COUNT] = { 0 };
	uint64_t prev_residency[PM_STATE_COUNT] = { 0 };
	int ret;
	struct ebpf_attach_target pm_entry_target;
	struct ebpf_attach_target pm_exit_target;

	printk("eBPF PM residency profiler\n");
	printk("==========================\n\n");

	pm_entry_code[6].imm = (int32_t)ebpf_map_get_id(&entry_ts_map);
	pm_entry_code[12].imm = (int32_t)ebpf_map_get_id(&entry_count_map);
	pm_exit_code[6].imm = (int32_t)ebpf_map_get_id(&entry_ts_map);
	pm_exit_code[13].imm = (int32_t)ebpf_map_get_id(&residency_map);

	ret = ebpf_prog_attach(&pm_entry,
			EBPF_ATTACH_TARGET_PM(EBPF_PM_ATTACH_STATE_ENTRY));
	if (ret) {
		printk("Failed to attach pm_entry: %d\n", ret);
		return ret;
	}

	ret = ebpf_prog_enable(&pm_entry);
	if (ret) {
		printk("Failed to enable pm_entry: %d\n", ret);
		return ret;
	}

	ret = ebpf_prog_attach(&pm_exit,
			EBPF_ATTACH_TARGET_PM(EBPF_PM_ATTACH_STATE_EXIT));
	if (ret) {
		printk("Failed to attach pm_exit: %d\n", ret);
		return ret;
	}

	ret = ebpf_prog_enable(&pm_exit);
	if (ret) {
		printk("Failed to enable pm_exit: %d\n", ret);
		return ret;
	}

	pm_entry_target = ebpf_prog_get_target(&pm_entry);
	pm_exit_target = ebpf_prog_get_target(&pm_exit);

	printk("Attached programs:\n");
	printk("  %s -> %s\n", pm_entry.name,
		       ebpf_attach_target_name(&pm_entry_target));
	printk("  %s -> %s\n\n", pm_exit.name,
		       ebpf_attach_target_name(&pm_exit_target));

	k_thread_create(&worker_thread, worker_stack, WORKER_STACK_SIZE,
			worker_entry, NULL, NULL, NULL,
			WORKER_PRIORITY, 0, K_NO_WAIT);

	for (int phase = 0; phase < NUM_PHASES; phase++) {
		worker_sleep_ms = phases[phase].sleep_ms;
		k_sleep(REPORT_INTERVAL);

		uint32_t interval_ms = k_ticks_to_ms_floor32(REPORT_INTERVAL.ticks);
		bool any = false;

		printk("[Phase %d] %s\n", phase + 1, phases[phase].label);

		for (uint32_t state = 0; state < PM_STATE_COUNT; state++) {
			uint64_t *entry_ptr = ebpf_map_lookup_elem(&entry_count_map, &state);
			uint64_t *residency_ptr = ebpf_map_lookup_elem(&residency_map, &state);
			uint64_t entries = entry_ptr != NULL ? *entry_ptr : 0;
			uint64_t residency_ns = residency_ptr != NULL ? *residency_ptr : 0;
			uint64_t entry_delta = entries - prev_entries[state];
			uint64_t residency_delta = residency_ns - prev_residency[state];
			uint32_t interval_pct = 0;

			prev_entries[state] = entries;
			prev_residency[state] = residency_ns;

			if (entry_delta == 0 && residency_delta == 0) {
				continue;
			}

			if (interval_ms > 0) {
				interval_pct = (uint32_t)(residency_delta /
					((uint64_t)interval_ms * 10000ULL));
			}
			if (interval_pct > 100) {
				interval_pct = 100;
			}

			printk("  %-16s entries=%4llu  residency=%5llu ms  interval=%u%%\n",
			       pm_state_name((enum pm_state)state),
			       entry_delta,
			       residency_delta / 1000000ULL,
			       interval_pct);
			any = true;
		}

		if (!any) {
			printk("  No PM state transitions observed in this interval\n");
		}

		printk("\n");
	}

	ebpf_prog_disable(&pm_entry);
	ebpf_prog_disable(&pm_exit);
	ebpf_prog_detach(&pm_entry);
	ebpf_prog_detach(&pm_exit);

	printk("eBPF PM residency profiler detached.\n");

	return 0;
}