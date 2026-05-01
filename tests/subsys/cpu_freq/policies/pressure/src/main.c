/*
 * Copyright (c) 2026 NXP
 *
 * SPDX-License-Identifier: Apache-2.0
 */

#include <zephyr/kernel.h>
#include <zephyr/ztest.h>
#include <zephyr/logging/log.h>
#include <zephyr/cpu_freq/policy.h>
#include <zephyr/cpu_freq/cpu_freq.h>

LOG_MODULE_REGISTER(cpu_freq_pressure_test, LOG_LEVEL_INF);

#define WAIT_US 100000

extern const struct pstate *soc_pstates[];
extern const size_t soc_pstates_count;

/*
 * P-states must be defined in decreasing load_threshold order.
 */
ZTEST(cpu_freq_pressure, test_pstates_order)
{
	for (int i = 1; i < soc_pstates_count; ++i) {
		zassert_true(soc_pstates[i]->load_threshold <
				     soc_pstates[i - 1]->load_threshold,
			     "P-states must be in decreasing threshold order");
	}
}

/*
 * NULL output pointer is rejected.
 */
ZTEST(cpu_freq_pressure, test_invalid_arg)
{
	zassert_equal(cpu_freq_policy_select_pstate(NULL), -EINVAL,
		      "Expected -EINVAL for NULL pstate_out");
}

/*
 * The policy should always succeed and return one of the configured P-states.
 *
 * When CONFIG_CPU_FREQ_POLICY_PRESSURE_RUNTIME_HISTORY is enabled, the first
 * call seeds the runtime-history baseline (the blend falls back to the
 * snapshot for that call); the second call exercises the blended path.
 */
ZTEST(cpu_freq_pressure, test_select_pstate_basic)
{
	const struct pstate *p = NULL;
	int ret;

#if defined(CONFIG_SMP) && (CONFIG_MP_MAX_NUM_CPUS > 1)
	k_sched_lock();
#endif

	ret = cpu_freq_policy_select_pstate(&p);
	zassert_equal(ret, 0, "first select failed: %d", ret);
	zassert_not_null(p, "first select returned NULL pstate");

	/* Burn some CPU so the runtime-history window has non-idle activity. */
	k_busy_wait(WAIT_US);

	ret = cpu_freq_policy_select_pstate(&p);
	zassert_equal(ret, 0, "second select failed: %d", ret);
	zassert_not_null(p, "second select returned NULL pstate");

#if defined(CONFIG_SMP) && (CONFIG_MP_MAX_NUM_CPUS > 1)
	k_sched_unlock();
#endif

	bool match = false;

	for (size_t i = 0; i < soc_pstates_count; i++) {
		if (p == soc_pstates[i]) {
			match = true;
			break;
		}
	}
	zassert_true(match, "Returned pstate is not part of soc_pstates[]");
}

/*
 * After a period of low CPU load (sleeping), the runtime-history blend should
 * pull the effective pressure down so the policy selects a lower-performance
 * P-state than after a busy-wait window.
 *
 * This test only runs when the runtime-history blend has a non-zero weight.
 */
#if defined(CONFIG_CPU_FREQ_POLICY_PRESSURE_RUNTIME_HISTORY) && \
	(CONFIG_CPU_FREQ_POLICY_PRESSURE_RUNTIME_HISTORY_WEIGHT > 0)
ZTEST(cpu_freq_pressure, test_runtime_history_lowers_pressure)
{
	const struct pstate *busy = NULL;
	const struct pstate *idle = NULL;
	int ret;

#if defined(CONFIG_SMP) && (CONFIG_MP_MAX_NUM_CPUS > 1)
	k_sched_lock();
#endif

	/* Seed history. */
	ret = cpu_freq_policy_select_pstate(&busy);
	zassert_equal(ret, 0, "seed select failed: %d", ret);

	/* Busy window: high non-idle runtime. */
	k_busy_wait(WAIT_US);
	ret = cpu_freq_policy_select_pstate(&busy);
	zassert_equal(ret, 0, "busy select failed: %d", ret);
	zassert_not_null(busy, "busy select returned NULL pstate");

#if defined(CONFIG_SMP) && (CONFIG_MP_MAX_NUM_CPUS > 1)
	k_sched_unlock();
#endif

	/* Idle window: mostly idle runtime. */
	k_sleep(K_USEC(WAIT_US));

#if defined(CONFIG_SMP) && (CONFIG_MP_MAX_NUM_CPUS > 1)
	k_sched_lock();
#endif

	ret = cpu_freq_policy_select_pstate(&idle);
	zassert_equal(ret, 0, "idle select failed: %d", ret);
	zassert_not_null(idle, "idle select returned NULL pstate");

#if defined(CONFIG_SMP) && (CONFIG_MP_MAX_NUM_CPUS > 1)
	k_sched_unlock();
#endif

	zassert_true(idle->load_threshold <= busy->load_threshold,
		     "Idle window should select a P-state with load_threshold "
		     "<= busy window (busy=%d idle=%d)",
		     busy->load_threshold, idle->load_threshold);
}
#endif

ZTEST_SUITE(cpu_freq_pressure, NULL, NULL, NULL, NULL, NULL);
