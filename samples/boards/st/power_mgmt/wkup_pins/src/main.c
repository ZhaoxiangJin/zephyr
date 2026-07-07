/*
 * Copyright (c) 2024 STMicroelectronics
 *
 * SPDX-License-Identifier: Apache-2.0
 */

#include <zephyr/kernel.h>
#include <zephyr/device.h>
#include <zephyr/devicetree.h>
#include <zephyr/drivers/gpio.h>
#include <zephyr/pm/wakeup.h>
#include <zephyr/sys/printk.h>
#include <zephyr/sys/poweroff.h>
#include <zephyr/dt-bindings/gpio/stm32-gpio.h>

#define WAIT_TIME_US 4000000

#define WKUP_SRC_NODE DT_ALIAS(wkup_src)
#if !DT_NODE_HAS_STATUS_OKAY(WKUP_SRC_NODE)
#error "Unsupported board: wkup_src devicetree alias is not defined"
#endif

static const struct gpio_dt_spec button = GPIO_DT_SPEC_GET(WKUP_SRC_NODE, gpios);

static const struct gpio_dt_spec led = GPIO_DT_SPEC_GET(DT_ALIAS(led0), gpios);

/*
 * STM32 wakeup backend for the generic wakeup-source framework: arm/disarm the
 * PWR wake-up pin by (re)configuring the GPIO with the existing STM32_GPIO_WKUP
 * flag - no new API. This is the STM32 analogue of NXP's WUC / TI's IOC
 * backend, behind the same wakeup_source_enable() the application uses.
 */
static int stm32_wkup_set_wake(const struct wakeup_source *ws, bool enable)
{
	const struct gpio_dt_spec *btn = ws->backend_data;

	return gpio_pin_configure_dt(btn, enable ? (GPIO_INPUT | STM32_GPIO_WKUP) : GPIO_INPUT);
}

/* Bound to the button's GPIO controller; the pin to arm is in backend_data. */
static struct wakeup_source button_ws = {
	.name = "wkup-button",
	.set_wake = stm32_wkup_set_wake,
	.backend_data = (void *)&button,
};

int main(void)
{
	printk("\nWake-up button is connected to %s pin %d\n", button.port->name, button.pin);

	__ASSERT_NO_MSG(gpio_is_ready_dt(&led));
	gpio_pin_configure_dt(&led, GPIO_OUTPUT_ACTIVE);
	gpio_pin_set(led.port, led.pin, 1);

	/*
	 * Select the button as the system wakeup source through the portable
	 * framework; the STM32 backend arms the PWR wake-up pin. The same two
	 * lines work on any SoC that provides a wakeup-source backend.
	 */
	button_ws.dev = button.port;
	wakeup_source_register(&button_ws);

	if (!wakeup_source_enable(button.port, true)) {
		printk("Failed to enable %s as a wakeup source\n", button.port->name);
		return 0;
	}

	printk("Will wait %ds before powering the system off\n", (WAIT_TIME_US / 1000000));
	k_busy_wait(WAIT_TIME_US);

	printk("Powering off\n");
	printk("Press the user button to power the system on\n\n");

	sys_poweroff();
	/* Will remain powered off until wake-up or reset button is pressed */

	return 0;
}
