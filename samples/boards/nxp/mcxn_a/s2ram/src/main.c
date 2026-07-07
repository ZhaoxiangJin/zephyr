/*
 * SPDX-FileCopyrightText: Copyright 2026 NXP
 *
 * SPDX-License-Identifier: Apache-2.0
 */

#include <zephyr/kernel.h>
#include <zephyr/device.h>
#include <zephyr/pm/pm.h>
#include <zephyr/pm/policy.h>
#include <zephyr/pm/device.h>
#if defined(CONFIG_SAMPLE_S2RAM_WAKEUP_BUTTON)
#include <zephyr/input/input.h>
#endif

#define WAKEUP_DELAY_S 3U

#define APP_STACK_SIZE 2048
#define APP_PRIORITY   5

/* Incremented before every suspend. Its value surviving the suspend/resume
 * cycle proves the RAM was retained while the CORE domain was powered down.
 */
static uint32_t cycles;

#define CONSOLE_NODE   DT_CHOSEN(zephyr_console)
#define CONSOLE_PARENT DT_PARENT(CONSOLE_NODE)

static const struct device *const console_dev = DEVICE_DT_GET(CONSOLE_NODE);
#if DT_NODE_HAS_COMPAT(CONSOLE_PARENT, nxp_lp_flexcomm)
#define HAS_FLEXCOMM_PARENT 1
static const struct device *const flexcomm_dev = DEVICE_DT_GET(CONSOLE_PARENT);
#endif

/*
 * Deep Power Down resets every CORE-domain peripheral. On a transparent resume
 * the SoC restores the CPU context and clocks, but the console UART driver has
 * no device pm hooks, so re-initialise it before printing. Three clock gates
 * that Deep Power Down switched off have to be re-opened, bottom up, before the
 * console can drive its pins again:
 *
 *   1. the PORT pin-mux controllers - their gate must be on for the LPUART
 *      pinctrl re-apply (step 3) to actually reach the pad-mux registers,
 *   2. the parent LP_FLEXCOMM - its init re-enables the peripheral clock gate
 *      and re-selects LPUART mode, then
 *   3. the LPUART itself - its init re-applies pinctrl and the baud/format.
 *
 * device_init() is a no-op on an already-initialised device, so clear the
 * initialised flag to force each driver to re-run its init against the reset
 * hardware. (A production driver would do this through a PM_DEVICE_ACTION_RESUME
 * handler instead.) printk keeps working once the LPUART is back: its console
 * output hook still points at the same device.
 */
#define REINIT_DEVICE(dev)				\
	do {						\
		(dev)->state->initialized = false;	\
		(void)device_init(dev);			\
	} while (0)

#define REINIT_PORT(node_id) REINIT_DEVICE(DEVICE_DT_GET(node_id));

static void resume_console(void)
{
	/* Re-open every PORT pin-mux clock gate that Deep Power Down closed. */
	DT_FOREACH_STATUS_OKAY(nxp_port_pinmux, REINIT_PORT)

#ifdef HAS_FLEXCOMM_PARENT
	REINIT_DEVICE(flexcomm_dev);
#endif
	REINIT_DEVICE(console_dev);
}

#if defined(CONFIG_SAMPLE_S2RAM_WAKEUP_BUTTON)
/*
 * The wakeup button is one key of a gpio-keys device. The application selects
 * that device as a wakeup source once with pm_device_wakeup_enable() and then
 * just waits for the key's input event. Everything the NXP silicon needs behind
 * the scenes - routing the pin to the always-on WUU, re-arming it on every
 * suspend, and turning the latched wakeup back into an input event on resume -
 * is done by the gpio-keys driver. The application code is therefore identical
 * to what an STM32 or Nordic target would run.
 */
static const struct device *const button_dev = DEVICE_DT_GET(DT_PARENT(DT_ALIAS(wakeup_button)));

static K_SEM_DEFINE(button_wakeup, 0, 1);

static void button_input_cb(struct input_event *evt, void *user_data)
{
	ARG_UNUSED(user_data);

	if ((evt->type == INPUT_EV_KEY) && (evt->value == 1)) {
		k_sem_give(&button_wakeup);
	}
}
INPUT_CALLBACK_DEFINE(button_dev, button_input_cb, NULL);
#endif /* CONFIG_SAMPLE_S2RAM_WAKEUP_BUTTON */

static void app_thread(void *p1, void *p2, void *p3)
{
	ARG_UNUSED(p1);
	ARG_UNUSED(p2);
	ARG_UNUSED(p3);

	while (cycles < CONFIG_SAMPLE_APP_TEST_CYCLES) {
		cycles++;

#if defined(CONFIG_SAMPLE_S2RAM_WAKEUP_BUTTON)
		printk("Entering suspend-to-RAM (cycle %u/%u); press SW2 to wake\n", cycles,
		       CONFIG_SAMPLE_APP_TEST_CYCLES);
#else
		printk("Entering suspend-to-RAM (cycle %u/%u); wake in %u s\n", cycles,
		       CONFIG_SAMPLE_APP_TEST_CYCLES, WAKEUP_DELAY_S);
#endif

		/* Let the UART finish shifting out the line above before DPD cuts its clock. */
		k_busy_wait(2000);

		pm_state_force(0U, &(struct pm_state_info){PM_STATE_SUSPEND_TO_RAM, 0, 0});
#if defined(CONFIG_SAMPLE_S2RAM_WAKEUP_BUTTON)
		/* Wait for the button press, delivered as a normal input event. */
		k_sem_take(&button_wakeup, K_FOREVER);
#else
		/* The system-timer companion (LPTMR0) wakes the SoC after the sleep;
		 * it arms itself as a WUU wakeup source, so no application action is
		 * needed here.
		 */
		k_sleep(K_SECONDS(WAKEUP_DELAY_S));
#endif

		resume_console();
		printk("Resumed from suspend-to-RAM; retained counter is %u\n", cycles);
	}

	/* All threads are now idle for good, but every PM state is locked, so the
	 * SoC stays awake and the board remains debuggable after the test.
	 */
	printk("Completed %u suspend-to-RAM cycles\n", cycles);
}

K_THREAD_STACK_DEFINE(app_stack, APP_STACK_SIZE);
static struct k_thread app_thread_data;

int main(void)
{
	printk("%s suspend-to-RAM demo\n", CONFIG_BOARD);
	printk("Retained S2RAM cycle counter: %u\n", cycles);

	pm_policy_state_lock_get(PM_STATE_RUNTIME_IDLE, PM_ALL_SUBSTATES);
	pm_policy_state_lock_get(PM_STATE_SUSPEND_TO_IDLE, PM_ALL_SUBSTATES);
	pm_policy_state_lock_get(PM_STATE_STANDBY, PM_ALL_SUBSTATES);
	pm_policy_state_lock_get(PM_STATE_SUSPEND_TO_RAM, PM_ALL_SUBSTATES);

#if defined(CONFIG_SAMPLE_S2RAM_WAKEUP_BUTTON)
	/* Select the button as the wakeup source once. The gpio-keys driver keeps
	 * it armed across every suspend/resume cycle - including on silicon that
	 * clears its wakeup configuration on each wakeup - with no further action.
	 */
	if (!pm_device_wakeup_enable(button_dev, true)) {
		printk("Failed to enable %s as a wakeup source\n", button_dev->name);
		return 0;
	}
#endif

	k_thread_create(&app_thread_data, app_stack, APP_STACK_SIZE, app_thread,
			NULL, NULL, NULL, APP_PRIORITY, 0, K_NO_WAIT);

	return 0;
}
