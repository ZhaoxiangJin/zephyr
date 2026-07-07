/*
 * Copyright (c) 2019 Nordic Semiconductor ASA
 * Copyright (c) 2020 Linaro Ltd.
 *
 * SPDX-License-Identifier: Apache-2.0
 */

#include <stdio.h>
#include <zephyr/kernel.h>
#include <zephyr/init.h>
#include <zephyr/device.h>
#include <zephyr/drivers/gpio.h>
#include <zephyr/pm/wakeup.h>
#include <zephyr/sys/poweroff.h>

#include <driverlib/ioc.h>

static const struct gpio_dt_spec sw0_gpio = GPIO_DT_SPEC_GET(DT_ALIAS(sw0), gpios);

#define BUSY_WAIT_S 5U
#define SLEEP_US 2000U
#define SLEEP_S     3U

extern void CC1352R1_LAUNCHXL_shutDownExtFlash(void);

/*
 * TI wakeup backend for the generic wakeup-source framework: arm/disarm a
 * PORT-event wakeup on the button's DIO via driverlib IOC. This is the TI
 * analogue of NXP's WUC backend - a different chip, a different arming call,
 * behind the same wakeup_source_enable() the application uses.
 */
static int ti_ioc_set_wake(const struct wakeup_source *ws, bool enable)
{
	const struct gpio_dt_spec *btn = ws->backend_data;
	uint32_t config = IOCPortConfigureGet(btn->pin);

	if (enable) {
		config |= IOC_WAKE_ON_LOW;
	} else {
		config &= ~IOC_WAKE_ON_LOW;
	}
	IOCPortConfigureSet(btn->pin, IOC_PORT_GPIO, config);

	return 0;
}

/* Bound to the button's GPIO controller; the pin to arm is in backend_data. */
static struct wakeup_source sw0_ws = {
	.name = "sw0",
	.set_wake = ti_ioc_set_wake,
	.backend_data = (void *)&sw0_gpio,
};

int main(void)
{
	uint32_t status;

	printk("\n%s system off demo\n", CONFIG_BOARD);

	/* Shut off external flash to save power */
	CC1352R1_LAUNCHXL_shutDownExtFlash();

	if (!gpio_is_ready_dt(&sw0_gpio)) {
		printk("%s: device not ready.\n", sw0_gpio.port->name);
		return 0;
	}

	gpio_pin_configure_dt(&sw0_gpio, GPIO_INPUT);

	/*
	 * Select the button as the system wakeup source through the portable
	 * framework; the TI IOC backend arms the PORT-event wakeup. The
	 * application no longer calls driverlib directly - the same two lines
	 * work on any SoC with a wakeup-source backend.
	 */
	sw0_ws.dev = sw0_gpio.port;
	wakeup_source_register(&sw0_ws);

	if (!wakeup_source_enable(sw0_gpio.port, true)) {
		printk("Failed to enable %s as a wakeup source\n", sw0_gpio.port->name);
		return 0;
	}

	printk("Busy-wait %u s\n", BUSY_WAIT_S);
	k_busy_wait(BUSY_WAIT_S * USEC_PER_SEC);

	printk("Sleep %u us (IDLE)\n", SLEEP_US);
	k_usleep(SLEEP_US);

	printk("Sleep %u s (STANDBY)\n", SLEEP_S);
	k_sleep(K_SECONDS(SLEEP_S));

	printk("Powering off; press BUTTON1 to restart\n");

	/* Clear GPIO interrupt */
	status = GPIO_getEventMultiDio(GPIO_DIO_ALL_MASK);
	GPIO_clearEventMultiDio(status);

	sys_poweroff();

	return 0;
}
