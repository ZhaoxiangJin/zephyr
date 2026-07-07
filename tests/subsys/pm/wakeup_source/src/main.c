/*
 * Copyright 2026 NXP
 *
 * SPDX-License-Identifier: Apache-2.0
 */

#include <zephyr/ztest.h>
#include <zephyr/device.h>
#include <zephyr/pm/wakeup.h>

/* A real device node marked `wakeup-source;` by the test overlay. */
#define WS_NODE DT_NODELABEL(gpio0)
static const struct device *const ws_dev = DEVICE_DT_GET(WS_NODE);

/* Fake vendor backend: record the last arm/disarm request. */
static int backend_calls;
static bool backend_last_enable;

static int fake_set_wake(const struct wakeup_source *ws, bool enable)
{
	ARG_UNUSED(ws);
	backend_calls++;
	backend_last_enable = enable;
	return 0;
}

/* Driver-style registration for the wakeup-capable node. */
WAKEUP_SOURCE_DT_DEFINE(WS_NODE, fake_set_wake, NULL);

ZTEST(wakeup_source, test_capability_from_devicetree)
{
	/* The node carries `wakeup-source;`, so it must be registered. */
	zassert_true(wakeup_source_is_capable(ws_dev),
		     "device with wakeup-source should be capable");
	zassert_not_null(wakeup_source_get(ws_dev), "source should be registered");
}

ZTEST(wakeup_source, test_enable_arms_backend)
{
	backend_calls = 0;

	zassert_true(wakeup_source_enable(ws_dev, true), "enable should succeed");
	zassert_true(wakeup_source_is_enabled(ws_dev), "should be enabled");
	zassert_equal(backend_calls, 1, "backend armed exactly once");
	zassert_true(backend_last_enable, "backend armed with enable=true");

	zassert_true(wakeup_source_enable(ws_dev, false), "disable should succeed");
	zassert_false(wakeup_source_is_enabled(ws_dev), "should be disabled");
	zassert_equal(backend_calls, 2, "backend disarmed");
	zassert_false(backend_last_enable, "backend disarmed with enable=false");
}

ZTEST(wakeup_source, test_unregistered_device)
{
	/* A device with no registered source is neither capable nor enable-able. */
	zassert_false(wakeup_source_is_capable(NULL), "NULL is not capable");
	zassert_false(wakeup_source_enable(NULL, true), "enabling NULL fails");
}

ZTEST(wakeup_source, test_arm_all_only_enabled)
{
	(void)wakeup_source_enable(ws_dev, false);
	backend_calls = 0;

	/* Disabled source is not (re-)armed by arm_all(). */
	wakeup_source_arm_all();
	zassert_equal(backend_calls, 0, "arm_all skips disabled sources");

	(void)wakeup_source_enable(ws_dev, true);
	backend_calls = 0;
	wakeup_source_arm_all();
	zassert_equal(backend_calls, 1, "arm_all re-arms enabled sources");
}

ZTEST_SUITE(wakeup_source, NULL, NULL, NULL, NULL, NULL);
