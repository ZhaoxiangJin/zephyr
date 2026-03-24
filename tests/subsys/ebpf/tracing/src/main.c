/*
 * SPDX-FileCopyrightText: Copyright 2026 NXP
 *
 * SPDX-License-Identifier: Apache-2.0
 */

#include <zephyr/ztest.h>
#include <zephyr/kernel.h>
#include <zephyr/ebpf/ebpf_attach_target.h>
#include <zephyr/ebpf/ebpf_insn.h>
#include <zephyr/ebpf/ebpf_prog.h>

static K_SEM_DEFINE(dispatch_started, 0, 1);
static K_SEM_DEFINE(verify_return_entered, 0, 1);
static K_SEM_DEFINE(verify_return_continue, 0, 1);
static K_THREAD_STACK_DEFINE(dispatch_stack, 1024);
static struct k_thread dispatch_thread;
static K_THREAD_STACK_DEFINE(enable_stack, 1024);
static struct k_thread enable_thread;
static bool verify_return_hook_enabled;
static int enable_thread_ret;

static enum ebpf_prog_state prog_state(const struct ebpf_prog *prog)
{
	return ebpf_prog_get_state(prog);
}

static struct ebpf_attach_target prog_target(const struct ebpf_prog *prog)
{
	return ebpf_prog_get_target(prog);
}

static struct ebpf_prog_stats prog_stats(const struct ebpf_prog *prog)
{
	return ebpf_prog_get_stats(prog);
}

int __real_ebpf_verify(const struct ebpf_prog *prog);

static const struct ebpf_insn exit_prog[] = {
	EBPF_MOV64_IMM(EBPF_REG_R0, 0),
	EBPF_EXIT_INSN(),
};

static const struct ebpf_insn busy_loop_prog[] = {
	EBPF_MOV64_IMM(EBPF_REG_R0, 0),
	EBPF_JMP_A(-1),
	EBPF_EXIT_INSN(),
};

static const struct ebpf_insn invalid_prog[] = {
	EBPF_INSN_OP(0xFE, 0, 0, 0, 0),
	EBPF_EXIT_INSN(),
};

static void init_prog(struct ebpf_prog *prog, const char *name)
{
	ebpf_prog_init(prog, name, EBPF_PROG_TYPE_GENERIC,
		       exit_prog, ARRAY_SIZE(exit_prog));
}

static void init_prog_with_type(struct ebpf_prog *prog, const char *name,
				 enum ebpf_prog_type type)
{
	init_prog(prog, name);
	prog->type = type;
}

static void dispatch_thread_entry(void *p1, void *p2, void *p3)
{
	struct ebpf_prog *prog = p1;
	struct ebpf_attach_target *target = p2;

	ARG_UNUSED(p3);

	k_sem_give(&dispatch_started);
	ebpf_attach_target_dispatch(target, prog, sizeof(*prog));
}

int __wrap_ebpf_verify(const struct ebpf_prog *prog)
{
	int ret = __real_ebpf_verify(prog);

	if (ret != 0 || !verify_return_hook_enabled) {
		return ret;
	}

	k_sem_give(&verify_return_entered);
	(void)k_sem_take(&verify_return_continue, K_SECONDS(1));

	return ret;
}

static void enable_thread_entry(void *p1, void *p2, void *p3)
{
	struct ebpf_prog *prog = p1;

	ARG_UNUSED(p2);
	ARG_UNUSED(p3);

	enable_thread_ret = ebpf_prog_enable(prog);
}

ZTEST(ebpf_tracing, test_same_target_accepts_multiple_programs)
{
	struct ebpf_prog prog_a;
	struct ebpf_prog prog_b;
	struct ebpf_attach_target target =
		EBPF_ATTACH_TARGET_TRACING(EBPF_TRACING_ATTACH_THREAD_SWITCHED_IN);
	int ret;

	init_prog(&prog_a, "prog_a");
	init_prog(&prog_b, "prog_b");

	ret = ebpf_prog_attach(&prog_a, target);
	zassert_ok(ret, "first attach failed: %d", ret);

	ret = ebpf_prog_attach(&prog_b, target);
	zassert_ok(ret, "second attach failed: %d", ret);

	ret = ebpf_prog_enable(&prog_a);
	zassert_ok(ret, "enable prog_a failed: %d", ret);
	ret = ebpf_prog_enable(&prog_b);
	zassert_ok(ret, "enable prog_b failed: %d", ret);

	ebpf_prog_disable(&prog_a);
	ebpf_prog_disable(&prog_b);
	ebpf_prog_detach(&prog_a);
	ebpf_prog_detach(&prog_b);
}

ZTEST(ebpf_tracing, test_disable_does_not_bypass_verifier)
{
	struct ebpf_prog prog = {
		0
	};
	int ret;

	ebpf_prog_init(&prog, "invalid_prog", EBPF_PROG_TYPE_GENERIC,
		       invalid_prog, ARRAY_SIZE(invalid_prog));

	ret = ebpf_prog_attach(&prog,
			       EBPF_ATTACH_TARGET_TRACING(EBPF_TRACING_ATTACH_THREAD_SWITCHED_IN));
	zassert_ok(ret, "attach failed: %d", ret);

	ret = ebpf_prog_disable(&prog);
	zassert_ok(ret, "disable failed: %d", ret);
	zassert_equal(prog_state(&prog), EBPF_PROG_STATE_ATTACHED,
		      "disable should leave program attached and unverified");

	ret = ebpf_prog_enable(&prog);
	zassert_equal(ret, -EINVAL, "invalid program should fail verification, got %d", ret);
	zassert_equal(prog_state(&prog), EBPF_PROG_STATE_ATTACHED,
		      "failed enable should keep program attached and unverified");

	ebpf_prog_detach(&prog);
}

ZTEST(ebpf_tracing, test_verify_requires_current_target)
{
	struct ebpf_prog prog;
	int ret;

	init_prog(&prog, "verify_requires_target");

	ret = ebpf_prog_verify(&prog);
	zassert_equal(ret, -ENOENT,
		      "verify without attach should fail, got %d", ret);
	zassert_equal(prog_state(&prog), EBPF_PROG_STATE_DETACHED,
		      "verify failure should keep program detached");
}

ZTEST(ebpf_tracing, test_reattach_starts_new_session)
{
	struct ebpf_prog prog;
	struct ebpf_attach_target target_a =
		EBPF_ATTACH_TARGET_TRACING(EBPF_TRACING_ATTACH_THREAD_SWITCHED_IN);
	struct ebpf_attach_target target_b =
		EBPF_ATTACH_TARGET_TRACING(EBPF_TRACING_ATTACH_IDLE_ENTER);
	int ret;

	init_prog(&prog, "reattach_session_prog");

	ret = ebpf_prog_attach(&prog, target_a);
	zassert_ok(ret, "attach target_a failed: %d", ret);
	ret = ebpf_prog_enable(&prog);
	zassert_ok(ret, "enable target_a failed: %d", ret);
	ebpf_attach_target_dispatch(&target_a, &prog, sizeof(prog));

	ebpf_prog_disable(&prog);
	zassert_equal(prog_state(&prog), EBPF_PROG_STATE_VERIFIED,
		      "disable should preserve verification for current attachment");

	ret = ebpf_prog_detach(&prog);
	zassert_ok(ret, "detach target_a failed: %d", ret);
	zassert_equal(prog_state(&prog), EBPF_PROG_STATE_DETACHED,
		      "detach should end the current attachment");
	zassert_equal(prog_stats(&prog).run_count, 0U,
		      "detach should clear current-attachment run_count");
	zassert_equal(prog_stats(&prog).run_time_ns, 0U,
		      "detach should clear current-attachment run_time_ns");

	ret = ebpf_prog_attach(&prog, target_b);
	zassert_ok(ret, "attach target_b failed: %d", ret);
	zassert_equal(prog_state(&prog), EBPF_PROG_STATE_ATTACHED,
		      "reattach should require verification for the new attachment");
	zassert_equal(prog_stats(&prog).run_count, 0U,
		      "reattach should reset current-attachment run_count");
	zassert_equal(prog_stats(&prog).run_time_ns, 0U,
		      "reattach should reset current-attachment run_time_ns");

	ret = ebpf_prog_enable(&prog);
	zassert_ok(ret, "enable target_b failed: %d", ret);
	ebpf_attach_target_dispatch(&target_b, &prog, sizeof(prog));

	ebpf_prog_disable(&prog);
	ret = ebpf_prog_detach(&prog);
	zassert_ok(ret, "detach target_b failed: %d", ret);

	ret = ebpf_prog_attach(&prog, target_a);
	zassert_ok(ret, "reattach target_a failed: %d", ret);
	zassert_equal(prog_state(&prog), EBPF_PROG_STATE_ATTACHED,
		      "returning to a prior target should start a new attachment");
	zassert_equal(prog_stats(&prog).run_count, 0U,
		      "returning to a prior target should clear current-attachment run_count");
	zassert_equal(prog_stats(&prog).run_time_ns, 0U,
		      "returning to a prior target should clear current-attachment run_time_ns");

	ebpf_prog_detach(&prog);
}

ZTEST(ebpf_tracing, test_detach_only_clears_own_program)
{
	struct ebpf_prog prog_a;
	struct ebpf_prog prog_b;
	struct ebpf_attach_target target =
		EBPF_ATTACH_TARGET_TRACING(EBPF_TRACING_ATTACH_THREAD_SWITCHED_IN);
	int ret;

	init_prog(&prog_a, "prog_a_owner");
	init_prog(&prog_b, "prog_b_owner");

	ret = ebpf_prog_attach(&prog_a, target);
	zassert_ok(ret, "attach failed: %d", ret);

	ret = ebpf_prog_attach(&prog_b, target);
	zassert_ok(ret, "second attach failed: %d", ret);

	ebpf_prog_detach(&prog_b);
	zassert_true(prog_target(&prog_a).backend != EBPF_ATTACH_BACKEND_MAX,
		     "detaching a different program should not detach the owner program");
	zassert_equal(prog_target(&prog_a).backend, target.backend,
		      "detaching a different program should preserve the owner target backend");
	zassert_equal(prog_target(&prog_a).point, target.point,
		      "detaching a different program should preserve the owner target point");

	ebpf_prog_detach(&prog_a);
}

ZTEST(ebpf_tracing, test_prog_type_matches_only_compatible_targets)
{
	struct ebpf_prog sched_prog;
	struct ebpf_prog isr_prog;
	struct ebpf_prog pm_prog;
	int ret;

	init_prog_with_type(&sched_prog, "sched_prog", EBPF_PROG_TYPE_SCHED);
	ret = ebpf_prog_attach(&sched_prog,
			       EBPF_ATTACH_TARGET_TRACING(EBPF_TRACING_ATTACH_THREAD_SWITCHED_IN));
	zassert_ok(ret, "sched attach to thread TP failed: %d", ret);
	ebpf_prog_detach(&sched_prog);

	ret = ebpf_prog_attach(&sched_prog,
			       EBPF_ATTACH_TARGET_TRACING(EBPF_TRACING_ATTACH_THREAD_SWITCHED_OUT));
	zassert_ok(ret, "sched attach to thread-out TP failed: %d", ret);
	ebpf_prog_detach(&sched_prog);

	ret = ebpf_prog_attach(&sched_prog,
			       EBPF_ATTACH_TARGET_TRACING(EBPF_TRACING_ATTACH_ISR_ENTER));
	zassert_equal(ret, -EINVAL,
		      "sched program should reject ISR TP, got %d", ret);

	init_prog_with_type(&isr_prog, "isr_prog", EBPF_PROG_TYPE_ISR);
	ret = ebpf_prog_attach(&isr_prog,
			       EBPF_ATTACH_TARGET_TRACING(EBPF_TRACING_ATTACH_ISR_ENTER));
	zassert_ok(ret, "ISR attach failed: %d", ret);
	ebpf_prog_detach(&isr_prog);

	ret = ebpf_prog_attach(&isr_prog,
			       EBPF_ATTACH_TARGET_TRACING(EBPF_TRACING_ATTACH_THREAD_SWITCHED_IN));
	zassert_equal(ret, -EINVAL,
		      "ISR program should reject sched TP, got %d", ret);

	init_prog_with_type(&pm_prog, "pm_prog", EBPF_PROG_TYPE_PM);
	ret = ebpf_prog_attach(&pm_prog,
			       EBPF_ATTACH_TARGET_PM(EBPF_PM_ATTACH_STATE_ENTRY));
	zassert_ok(ret, "pm attach failed: %d", ret);
	ebpf_prog_detach(&pm_prog);

	ret = ebpf_prog_attach(&pm_prog,
			       EBPF_ATTACH_TARGET_TRACING(EBPF_TRACING_ATTACH_IDLE_ENTER));
	zassert_equal(ret, -EINVAL,
		      "pm program should reject tracing target, got %d", ret);
}

ZTEST(ebpf_tracing, test_dispatch_stats_do_not_cross_sessions)
{
	struct ebpf_prog prog = {
		0
	};
	struct ebpf_attach_target target_a =
		EBPF_ATTACH_TARGET_TRACING(EBPF_TRACING_ATTACH_THREAD_SWITCHED_IN);
	struct ebpf_attach_target target_b =
		EBPF_ATTACH_TARGET_TRACING(EBPF_TRACING_ATTACH_IDLE_ENTER);
	int ret;

	ebpf_prog_init(&prog, "dispatch_session_prog", EBPF_PROG_TYPE_GENERIC,
		       busy_loop_prog, ARRAY_SIZE(busy_loop_prog));

	ret = ebpf_prog_attach(&prog, target_a);
	zassert_ok(ret, "attach target_a failed: %d", ret);

	ret = ebpf_prog_enable(&prog);
	zassert_ok(ret, "enable target_a failed: %d", ret);

	k_thread_create(&dispatch_thread, dispatch_stack, K_THREAD_STACK_SIZEOF(dispatch_stack),
			dispatch_thread_entry, &prog, &target_a, NULL,
			1, 0, K_NO_WAIT);

	zassert_ok(k_sem_take(&dispatch_started, K_SECONDS(1)),
		   "dispatch thread did not start");

	k_sleep(K_MSEC(1));

	ret = ebpf_prog_detach(&prog);
	zassert_ok(ret, "detach during dispatch failed: %d", ret);

	ret = ebpf_prog_attach(&prog, target_b);
	zassert_ok(ret, "attach target_b failed: %d", ret);
	zassert_equal(prog_stats(&prog).run_count, 0U,
		      "new session must not inherit run_count from prior dispatch");
	zassert_equal(prog_stats(&prog).run_time_ns, 0U,
		      "new session must not inherit run_time_ns from prior dispatch");

	ret = ebpf_prog_enable(&prog);
	zassert_ok(ret, "enable target_b failed: %d", ret);

	ebpf_attach_target_dispatch(&target_b, &prog, sizeof(prog));
	zassert_equal(prog_stats(&prog).run_count, 1U,
		      "new session should accumulate only its own dispatch stats");

	k_thread_join(&dispatch_thread, K_SECONDS(1));
	ebpf_prog_disable(&prog);
	ebpf_prog_detach(&prog);
}

ZTEST(ebpf_tracing, test_enable_returns_eagain_if_session_changes_before_commit)
{
	struct ebpf_prog prog;
	struct ebpf_attach_target target_a =
		EBPF_ATTACH_TARGET_TRACING(EBPF_TRACING_ATTACH_THREAD_SWITCHED_IN);
	struct ebpf_attach_target target_b =
		EBPF_ATTACH_TARGET_TRACING(EBPF_TRACING_ATTACH_IDLE_ENTER);
	int ret;

	init_prog(&prog, "enable_session_race_prog");
	enable_thread_ret = 0;
	verify_return_hook_enabled = false;
	while (k_sem_take(&verify_return_entered, K_NO_WAIT) == 0) {
	}
	while (k_sem_take(&verify_return_continue, K_NO_WAIT) == 0) {
	}

	ret = ebpf_prog_attach(&prog, target_a);
	zassert_ok(ret, "attach target_a failed: %d", ret);

	verify_return_hook_enabled = true;
	k_thread_create(&enable_thread, enable_stack, K_THREAD_STACK_SIZEOF(enable_stack),
			enable_thread_entry, &prog, NULL, NULL, 1, 0, K_NO_WAIT);

	zassert_ok(k_sem_take(&verify_return_entered, K_SECONDS(1)),
		   "enable thread did not complete verify before commit");

	ret = ebpf_prog_detach(&prog);
	zassert_ok(ret, "detach during enable failed: %d", ret);

	ret = ebpf_prog_attach(&prog, target_b);
	zassert_ok(ret, "reattach during enable failed: %d", ret);

	k_sem_give(&verify_return_continue);
	k_thread_join(&enable_thread, K_SECONDS(1));
	verify_return_hook_enabled = false;

	zassert_equal(enable_thread_ret, -EAGAIN,
		      "enable should fail with -EAGAIN after session change, got %d",
		      enable_thread_ret);
	zassert_equal(prog_state(&prog), EBPF_PROG_STATE_ATTACHED,
		      "new session should remain attached but not enabled");
	zassert_equal(prog_target(&prog).backend, target_b.backend,
		      "new session should preserve reattached target backend");
	zassert_equal(prog_target(&prog).point, target_b.point,
		      "new session should preserve reattached target point");

	ret = ebpf_prog_enable(&prog);
	zassert_ok(ret, "enable target_b after race failed: %d", ret);

	ebpf_prog_disable(&prog);
	ebpf_prog_detach(&prog);
}

ZTEST_SUITE(ebpf_tracing, NULL, NULL, NULL, NULL, NULL);
