/*
 * SPDX-FileCopyrightText: Copyright 2026 NXP
 * SPDX-License-Identifier: Apache-2.0
 */

#include <string.h>
#include <zephyr/pm/device_runtime.h>
#include <zephyr/pm/pm.h>
#include <zephyr/pm/policy.h>
#include <zephyr/ztest.h>
#include "device_system_managed.h"

/* No production DT instances: the test devices below use RAM register blocks. */
#include "wdt_mcux_wwdt.c"

static uint32_t dividers[2] = {1U, 1U};
static uint32_t divider_writes;
static uint32_t init_calls;
static uint32_t feed_calls;
static uint32_t deinit_calls;
static uint32_t status_reads;
static uint32_t callbacks;
static bool gates[2];
static int on_error;
static int off_error;
static bool halt_fails;
static bool feed_from_callback;
static void (*init_hook)(void);

static int clock_index(clock_control_subsys_t subsys)
{
	if ((uint32_t)subsys == MCUX_WWDT0_CLK) {
		return 0;
	}
	if ((uint32_t)subsys == MCUX_WWDT1_CLK) {
		return 1;
	}
	return -EINVAL;
}

static int clock_on(const struct device *dev, clock_control_subsys_t subsys)
{
	int index = clock_index(subsys);

	ARG_UNUSED(dev);
	if (on_error != 0) {
		return on_error;
	}
	if (index < 0) {
		return index;
	}
	gates[index] = true;
	return 0;
}

static int clock_off(const struct device *dev, clock_control_subsys_t subsys)
{
	int index = clock_index(subsys);

	ARG_UNUSED(dev);
	if (off_error != 0) {
		return off_error;
	}
	if (index < 0) {
		return index;
	}
	gates[index] = false;
	return 0;
}

static int clock_rate(const struct device *dev, clock_control_subsys_t subsys, uint32_t *rate)
{
	int index = clock_index(subsys);

	ARG_UNUSED(dev);
	if (index < 0) {
		return index;
	}
	if (dividers[index] == 0U) {
		return -EINVAL;
	}
	*rate = 1000000U / dividers[index];
	return 0;
}

static DEVICE_API(clock_control, clock_api) = {
	.on = clock_on,
	.off = clock_off,
	.get_rate = clock_rate,
};

DEVICE_DEFINE(test_clock, "test_clock", NULL, NULL, NULL, NULL, POST_KERNEL, 60, &clock_api);

void CLOCK_SetClkDiv(enum clock_div_name divider, uint32_t value)
{
	divider_writes++;
	if ((value != 0U) || !halt_fails) {
		dividers[divider] = value;
	}
}

uint32_t CLOCK_GetClkDiv(enum clock_div_name divider)
{
	return dividers[divider];
}

void WWDT_GetDefaultConfig(wwdt_config_t *config)
{
	*config = (wwdt_config_t){
		.enableWwdt = true,
		.timeoutValue = 0xFFFFFFU,
		.windowValue = 0xFFFFFFU,
	};
}

void WWDT_Init(WWDT_Type *base, const wwdt_config_t *config)
{
	init_calls++;
	if (init_hook != NULL) {
		init_hook();
	}
	base->MOD = WWDT_MOD_WDEN_MASK | (config->enableWatchdogReset ? WWDT_MOD_WDRESET_MASK : 0U);
	base->TC = config->timeoutValue;
	base->WINDOW = config->windowValue;
	base->WARNINT = config->warningValue;
	base->TV = base->TC;
}

void WWDT_Deinit(WWDT_Type *base)
{
	ARG_UNUSED(base);
	deinit_calls++;
}

void WWDT_Refresh(WWDT_Type *base)
{
	feed_calls++;
	base->TV = base->TC;
}

uint32_t WWDT_GetStatusFlags(WWDT_Type *base)
{
	status_reads++;
	return base->MOD & (WWDT_MOD_WDTOF_MASK | WWDT_MOD_WDINT_MASK);
}

void WWDT_ClearStatusFlags(WWDT_Type *base, uint32_t flags)
{
	base->MOD &= ~flags;
}

static void test_irq_config(const struct device *dev)
{
	const struct mcux_wwdt_config *config = dev->config;

	irq_enable(config->irq);
}

#define TEST_WWDT(n, clock_id)                                                                     \
	static WWDT_Type registers_##n;                                                            \
	static struct mcux_wwdt_data data_##n;                                                     \
	static const struct mcux_wwdt_config config_##n = {                                        \
		.base = &registers_##n,                                                            \
		.clk_divider = 4U,                                                                 \
		.clock_dev = DEVICE_GET(test_clock),                                               \
		.clock_subsys = (clock_control_subsys_t)clock_id,                                  \
		.irq_config_func = test_irq_config,                                                \
		.irq = 40U + n,                                                                    \
	};                                                                                         \
	PM_DEVICE_DT_DEFINE(DT_NODELABEL(wwdt##n), mcux_wwdt_driver_pm_action);                    \
	DEVICE_DT_DEFINE(DT_NODELABEL(wwdt##n), mcux_wwdt_init,                                    \
			 PM_DEVICE_DT_GET(DT_NODELABEL(wwdt##n)), &data_##n, &config_##n,          \
			 POST_KERNEL, 80, &mcux_wwdt_api)

TEST_WWDT(0, MCUX_WWDT0_CLK);
TEST_WWDT(1, MCUX_WWDT1_CLK);

static const struct device *const dev = DEVICE_DT_GET(DT_NODELABEL(wwdt0));
static const struct device *const other = DEVICE_DT_GET(DT_NODELABEL(wwdt1));

void pm_state_set(enum pm_state state, uint8_t substate_id)
{
	ARG_UNUSED(state);
	ARG_UNUSED(substate_id);
}

void pm_state_exit_post_ops(enum pm_state state, uint8_t substate_id)
{
	ARG_UNUSED(state);
	ARG_UNUSED(substate_id);
}

static void callback(const struct device *wdt, int channel)
{
	zassert_equal(wdt, dev);
	zassert_equal(channel, 0);
	callbacks++;
	if (feed_from_callback) {
		zassert_ok(wdt_feed(wdt, channel));
	}
}

static const struct wdt_timeout_cfg timeout = {
	.window = {.min = 200U, .max = 1000U},
	.flags = WDT_FLAG_RESET_NONE,
	.callback = callback,
};

static void assert_state(const struct device *wdt, enum pm_device_state expected)
{
	enum pm_device_state state;

	zassert_ok(pm_device_state_get(wdt, &state));
	zassert_equal(state, expected);
}

static void assert_constraints(bool held)
{
	zassert_equal(pm_policy_state_lock_is_active(PM_STATE_SUSPEND_TO_IDLE, 0U), held);
	zassert_equal(pm_policy_state_lock_is_active(PM_STATE_STANDBY, 0U), held);
	zassert_equal(pm_policy_state_lock_is_active(PM_STATE_SUSPEND_TO_RAM, 0U), held);
	zassert_false(pm_policy_state_lock_is_active(PM_STATE_RUNTIME_IDLE, 0U));
}

static void reset_instance(const struct device *wdt)
{
	struct mcux_wwdt_data *data = wdt->data;
	const struct mcux_wwdt_config *config = wdt->config;

	/* Model a cold reset, not a supported software stop of a running WWDT. */
	data->started = false;
	data->starting = false;
	*config->base = (WWDT_Type){.TC = 0xFFU, .TV = 0xFFU, .WINDOW = 0xFFFFFFU};
	zassert_ok(pm_device_runtime_disable(wdt));
	memset(data, 0, sizeof(*data));
	wdt->pm_base->state = PM_DEVICE_STATE_ACTIVE;
	atomic_clear_bit(&wdt->pm_base->flags, PM_DEVICE_FLAG_TURN_ON_FAILED);
	zassert_ok(mcux_wwdt_init(wdt));
}

static void before(void *fixture)
{
	ARG_UNUSED(fixture);
	on_error = 0;
	off_error = 0;
	halt_fails = false;
	feed_from_callback = false;
	init_hook = NULL;
	reset_instance(dev);
	reset_instance(other);
	assert_constraints(false);
	init_calls = 0U;
	feed_calls = 0U;
	deinit_calls = 0U;
	divider_writes = 0U;
	callbacks = 0U;
	status_reads = 0U;
}

static void start(const struct device *wdt)
{
	zassert_equal(wdt_install_timeout(wdt, &timeout), 0);
	zassert_ok(wdt_setup(wdt, 0));
}

ZTEST(wwdt_generic, test_setup_requires_installed_timeout)
{
	zassert_equal(wdt_setup(dev, 0), -EINVAL);
	zassert_equal(init_calls, 0U);
	zassert_false(data_0.starting);
}

ZTEST(wwdt_generic, test_setup_and_install_reject_running_instance)
{
	start(dev);
	registers_0.TV = 123U;
	wwdt_config_t saved = data_0.wwdt_config;

	zassert_equal(wdt_setup(dev, 0), -EBUSY);
	zassert_equal(wdt_install_timeout(dev, &timeout), -EBUSY);
	zassert_equal(registers_0.TV, 123U);
	zassert_equal(init_calls, 1U);
	zassert_equal(feed_calls, 0U);
	zassert_mem_equal(&data_0.wwdt_config, &saved, sizeof(saved));
	assert_constraints(false);
}

ZTEST(wwdt_generic, test_second_install_keeps_first_request)
{
	zassert_equal(wdt_install_timeout(dev, &timeout), 0);
	wwdt_config_t saved = data_0.wwdt_config;

	zassert_equal(wdt_install_timeout(dev, &timeout), -ENOMEM);
	zassert_mem_equal(&data_0.wwdt_config, &saved, sizeof(saved));
}

static void check_generic_start_in_progress(void)
{
	zassert_true(data_0.starting);
	zassert_false(irq_is_enabled(config_0.irq));
	zassert_equal(wdt_setup(dev, 0), -EBUSY);
	zassert_equal(wdt_install_timeout(dev, &timeout), -EBUSY);
	zassert_equal(wdt_feed(dev, 0), -EAGAIN);
	zassert_equal(wdt_disable(dev), -EBUSY);
	zassert_equal(mcux_wwdt_driver_pm_action(dev, PM_DEVICE_ACTION_TURN_OFF), -EBUSY);
	zassert_equal(mcux_wwdt_driver_pm_action(dev, PM_DEVICE_ACTION_TURN_ON), -EBUSY);
	zassert_equal(mcux_wwdt_driver_pm_action(dev, PM_DEVICE_ACTION_SUSPEND), -EBUSY);
	zassert_equal(mcux_wwdt_driver_pm_action(dev, PM_DEVICE_ACTION_RESUME), -EBUSY);
	mcux_wwdt_isr(dev);
	zassert_equal(status_reads, 0U);
	zassert_equal(feed_calls, 0U);
}

ZTEST(wwdt_generic, test_start_excludes_control_and_pm)
{
	init_hook = check_generic_start_in_progress;
	start(dev);
	zassert_true(data_0.started);
	zassert_false(data_0.starting);
	zassert_true(irq_is_enabled(config_0.irq));
	assert_constraints(false);
}

ZTEST(wwdt_generic, test_feed_requires_running_channel)
{
	zassert_equal(wdt_feed(dev, 0), -EINVAL);
	zassert_equal(wdt_feed(dev, 1), -EINVAL);
	zassert_equal(wdt_install_timeout(dev, &timeout), 0);
	zassert_equal(wdt_feed(dev, 0), -EINVAL);
	zassert_equal(feed_calls, 0U);
	zassert_ok(wdt_setup(dev, 0));
	zassert_ok(wdt_feed(dev, 0));
	zassert_equal(feed_calls, 1U);
}

ZTEST(wwdt_generic, test_disable_uninstalls_and_preserves_legacy_reuse)
{
	zassert_equal(wdt_disable(dev), -EFAULT);
	zassert_equal(deinit_calls, 0U);
	start(dev);
	zassert_ok(wdt_disable(dev));
	zassert_equal(deinit_calls, 1U);
	zassert_false(data_0.timeout_valid);
	zassert_is_null(data_0.callback);
	zassert_false(irq_is_enabled(config_0.irq));
	zassert_equal(wdt_disable(dev), -EFAULT);
	zassert_equal(wdt_feed(dev, 0), -EINVAL);
	zassert_equal(wdt_setup(dev, 0), -EINVAL);
	mcux_wwdt_isr(dev);
	zassert_equal(status_reads, 0U);
	start(dev);
	zassert_equal(init_calls, 2U);
	zassert_true(irq_is_enabled(config_0.irq));
}

ZTEST(wwdt_generic, test_options_retain_non_mcx_behavior)
{
	zassert_equal(wdt_install_timeout(dev, &timeout), 0);
	zassert_ok(wdt_setup(dev, WDT_OPT_PAUSE_HALTED_BY_DBG));
	zassert_equal(init_calls, 1U);
}

ZTEST(wwdt_generic, test_setup_preserves_disabled_irq)
{
	irq_disable(config_0.irq);
	start(dev);
	zassert_false(irq_is_enabled(config_0.irq));
}

ZTEST(wwdt_generic, test_callback_can_feed_without_recursive_lock)
{
	start(dev);
	feed_from_callback = true;
	registers_0.MOD |= WWDT_MOD_WDINT_MASK;
	mcux_wwdt_isr(dev);
	zassert_equal(callbacks, 1U);
	zassert_equal(status_reads, 1U);
	zassert_equal(feed_calls, 1U);
}

ZTEST(wwdt_generic, test_legacy_power_cycle_restores_running_watchdog)
{
	start(dev);
	zassert_ok(pm_device_action_run(dev, PM_DEVICE_ACTION_SUSPEND));
	zassert_ok(pm_device_action_run(dev, PM_DEVICE_ACTION_TURN_OFF));
	zassert_false(irq_is_enabled(config_0.irq));
	zassert_false(data_0.started);
	registers_0 = (WWDT_Type){.TC = 0xFFU, .TV = 0xFFU};
	init_hook = check_generic_start_in_progress;
	zassert_ok(pm_device_action_run(dev, PM_DEVICE_ACTION_TURN_ON));
	zassert_true(data_0.started);
	zassert_false(data_0.active_before_sleep);
	zassert_equal(init_calls, 2U);
	zassert_true(irq_is_enabled(config_0.irq));
	zassert_ok(pm_device_action_run(dev, PM_DEVICE_ACTION_RESUME));
}

ZTEST(wwdt_generic, test_legacy_power_cycle_does_not_restore_removed_timeout)
{
	start(dev);
	zassert_ok(wdt_disable(dev));
	zassert_ok(pm_device_action_run(dev, PM_DEVICE_ACTION_SUSPEND));
	zassert_ok(pm_device_action_run(dev, PM_DEVICE_ACTION_TURN_OFF));
	zassert_false(data_0.active_before_sleep);
	zassert_ok(pm_device_action_run(dev, PM_DEVICE_ACTION_TURN_ON));
	zassert_ok(pm_device_action_run(dev, PM_DEVICE_ACTION_RESUME));
	zassert_equal(init_calls, 1U);
	zassert_false(data_0.started);
	zassert_equal(wdt_setup(dev, 0), -EINVAL);
}

ZTEST(wwdt_generic, test_setup_requires_active_device)
{
	zassert_equal(wdt_install_timeout(dev, &timeout), 0);
	zassert_ok(pm_device_action_run(dev, PM_DEVICE_ACTION_SUSPEND));
	zassert_equal(wdt_setup(dev, 0), -EBUSY);
	zassert_equal(init_calls, 0U);
	assert_state(dev, PM_DEVICE_STATE_SUSPENDED);
	zassert_ok(pm_device_action_run(dev, PM_DEVICE_ACTION_RESUME));
	zassert_ok(wdt_setup(dev, 0));
}

ZTEST_SUITE(wwdt_generic, NULL, NULL, before, NULL, NULL);
