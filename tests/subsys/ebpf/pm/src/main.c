/*
 * SPDX-FileCopyrightText: Copyright 2026 NXP
 *
 * SPDX-License-Identifier: Apache-2.0
 */

#include <zephyr/ztest.h>

#include <zephyr/pm/pm.h>

#include "../../../../subsys/ebpf/attach/ebpf_attach_target_internal.h"
#include "../../../../subsys/ebpf/bundle/ebpf_bundle_internal.h"

static struct pm_notifier *registered_pm_notifier;

void __wrap_pm_notifier_register(struct pm_notifier *notifier)
{
	registered_pm_notifier = notifier;
}

static const struct ebpf_insn exit_prog[] = {
	EBPF_MOV64_IMM(EBPF_REG_R0, 0),
	EBPF_EXIT_INSN(),
};

static void fill_pm_spec(struct ebpf_attachment_spec *spec, const char *name,
			 const char *hook_name)
{
	spec->name = name;
	spec->type = EBPF_PROG_TYPE_PM;
	spec->insns = exit_prog;
	spec->insn_cnt = ARRAY_SIZE(exit_prog);
	spec->hook_name = hook_name;
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
	struct ebpf_attach_target target = EBPF_ATTACH_TARGET_PM(EBPF_PM_ATTACH_STATE_ENTRY);
	struct ebpf_attachment_spec spec;
	struct ebpf_bundle *bundle;
	struct ebpf_attachment *attachment;
	int ret;

	fill_pm_spec(&spec, "pm_entry_prog", "pm/state_entry");

	ret = ebpf_bundle_create("pm_entry_bundle", &bundle);
	zassert_ok(ret, "bundle create failed: %d", ret);

	ret = ebpf_bundle_add_attachment(bundle, &spec, &attachment);
	zassert_ok(ret, "add attachment failed: %d", ret);

	ret = ebpf_bundle_enable(bundle);
	zassert_ok(ret, "bundle enable failed: %d", ret);
	zassert_true(ebpf_attach_target_is_active(&target),
		     "PM entry target should become active after enable");

	registered_pm_notifier->substate_entry(PM_STATE_SUSPEND_TO_IDLE, 7U);

	ret = ebpf_bundle_destroy(bundle);
	zassert_ok(ret, "bundle destroy failed: %d", ret);
	zassert_false(ebpf_attach_target_is_active(&target),
		      "PM entry target should be inactive after bundle teardown");
}

ZTEST(ebpf_pm, test_pm_exit_notifier_dispatches_enabled_program)
{
	struct ebpf_attach_target target = EBPF_ATTACH_TARGET_PM(EBPF_PM_ATTACH_STATE_EXIT);
	struct ebpf_attachment_spec spec;
	struct ebpf_bundle *bundle;
	struct ebpf_attachment *attachment;
	int ret;

	fill_pm_spec(&spec, "pm_exit_prog", "pm/state_exit");

	ret = ebpf_bundle_create("pm_exit_bundle", &bundle);
	zassert_ok(ret, "bundle create failed: %d", ret);

	ret = ebpf_bundle_add_attachment(bundle, &spec, &attachment);
	zassert_ok(ret, "add attachment failed: %d", ret);

	ret = ebpf_bundle_enable(bundle);
	zassert_ok(ret, "bundle enable failed: %d", ret);
	zassert_true(ebpf_attach_target_is_active(&target),
		     "PM exit target should become active after enable");

	registered_pm_notifier->substate_exit(PM_STATE_SUSPEND_TO_IDLE, 3U);

	ret = ebpf_bundle_destroy(bundle);
	zassert_ok(ret, "bundle destroy failed: %d", ret);
	zassert_false(ebpf_attach_target_is_active(&target),
		      "PM exit target should be inactive after bundle teardown");
}

ZTEST_SUITE(ebpf_pm, NULL, NULL, NULL, NULL, NULL);