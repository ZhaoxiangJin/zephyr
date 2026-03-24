/*
 * SPDX-FileCopyrightText: Copyright 2026 NXP
 *
 * SPDX-License-Identifier: Apache-2.0
 */

#include <zephyr/ztest.h>

#include <zephyr/pm/pm.h>

#include <zephyr/ebpf/ebpf_attach_target.h>
#include <zephyr/ebpf/ebpf_insn.h>
#include <zephyr/ebpf/ebpf_prog.h>

static struct pm_notifier *registered_pm_notifier;

void __wrap_pm_notifier_register(struct pm_notifier *notifier)
{
	registered_pm_notifier = notifier;
}

static const struct ebpf_insn exit_prog[] = {
	EBPF_MOV64_IMM(EBPF_REG_R0, 0),
	EBPF_EXIT_INSN(),
};

static void init_pm_prog(struct ebpf_prog *prog, const char *name)
{
	ebpf_prog_init(prog, name, EBPF_PROG_TYPE_PM,
		       exit_prog, ARRAY_SIZE(exit_prog));
}

ZTEST(ebpf_pm, test_pm_backend_registers_notifier)
{
	zassert_not_null(registered_pm_notifier,
			 "PM backend should register a notifier at init");
	zassert_true(registered_pm_notifier->report_substate,
		     "PM backend should request substate notifications");
	zassert_not_null(registered_pm_notifier->substate_entry,
			 "PM backend should provide an entry callback");
	zassert_not_null(registered_pm_notifier->substate_exit,
			 "PM backend should provide an exit callback");
}

ZTEST(ebpf_pm, test_pm_entry_notifier_dispatches_enabled_program)
{
	struct ebpf_prog prog;
	struct ebpf_prog_stats stats;
	int ret;

	init_pm_prog(&prog, "pm_entry_prog");

	ret = ebpf_prog_attach(&prog,
			       EBPF_ATTACH_TARGET_PM(EBPF_PM_ATTACH_STATE_ENTRY));
	zassert_ok(ret, "attach failed: %d", ret);

	ret = ebpf_prog_enable(&prog);
	zassert_ok(ret, "enable failed: %d", ret);

	registered_pm_notifier->substate_entry(PM_STATE_SUSPEND_TO_IDLE, 7U);

	stats = ebpf_prog_get_stats(&prog);
	zassert_equal(stats.run_count, 1U,
		      "PM entry callback should dispatch exactly one run");

	ebpf_prog_disable(&prog);
	ebpf_prog_detach(&prog);
}

ZTEST(ebpf_pm, test_pm_exit_notifier_dispatches_enabled_program)
{
	struct ebpf_prog prog;
	struct ebpf_prog_stats stats;
	int ret;

	init_pm_prog(&prog, "pm_exit_prog");

	ret = ebpf_prog_attach(&prog,
			       EBPF_ATTACH_TARGET_PM(EBPF_PM_ATTACH_STATE_EXIT));
	zassert_ok(ret, "attach failed: %d", ret);

	ret = ebpf_prog_enable(&prog);
	zassert_ok(ret, "enable failed: %d", ret);

	registered_pm_notifier->substate_exit(PM_STATE_SUSPEND_TO_IDLE, 3U);

	stats = ebpf_prog_get_stats(&prog);
	zassert_equal(stats.run_count, 1U,
		      "PM exit callback should dispatch exactly one run");

	ebpf_prog_disable(&prog);
	ebpf_prog_detach(&prog);
}

ZTEST_SUITE(ebpf_pm, NULL, NULL, NULL, NULL, NULL);