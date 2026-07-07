/*
 * Copyright 2026 NXP
 *
 * SPDX-License-Identifier: Apache-2.0
 */

/*
 * Generic wakeup-source framework (v1, RFC POC).
 *
 * PM-independent on purpose: this file is built under CONFIG_WAKEUP_SOURCE,
 * not CONFIG_PM / CONFIG_PM_DEVICE, so a board that only ever calls
 * sys_poweroff() can still express a portable wakeup source.
 */

#include <zephyr/pm/wakeup.h>
#include <zephyr/spinlock.h>
#include <zephyr/logging/log.h>

LOG_MODULE_REGISTER(wakeup_source, CONFIG_WAKEUP_SOURCE_LOG_LEVEL);

/* Runtime registry (Linux-style list), guarded for concurrent enable/register. */
static sys_slist_t wakeup_sources = SYS_SLIST_STATIC_INIT(&wakeup_sources);
static struct k_spinlock lock;

/* Bit in wakeup_source.flags. */
#define WS_FLAG_ENABLED 0

void wakeup_source_register(struct wakeup_source *ws)
{
	K_SPINLOCK(&lock) {
		sys_slist_append(&wakeup_sources, &ws->node);
	}
}

void wakeup_source_unregister(struct wakeup_source *ws)
{
	K_SPINLOCK(&lock) {
		(void)sys_slist_find_and_remove(&wakeup_sources, &ws->node);
	}
}

struct wakeup_source *wakeup_source_get(const struct device *dev)
{
	struct wakeup_source *ws;

	if (dev == NULL) {
		return NULL;
	}

	SYS_SLIST_FOR_EACH_CONTAINER(&wakeup_sources, ws, node) {
		if (ws->dev == dev) {
			return ws;
		}
	}

	return NULL;
}

bool wakeup_source_is_capable(const struct device *dev)
{
	return wakeup_source_get(dev) != NULL;
}

bool wakeup_source_is_enabled(const struct device *dev)
{
	struct wakeup_source *ws = wakeup_source_get(dev);

	return (ws != NULL) && atomic_test_bit(&ws->flags, WS_FLAG_ENABLED);
}

bool wakeup_source_enable(const struct device *dev, bool enable)
{
	struct wakeup_source *ws = wakeup_source_get(dev);

	if (ws == NULL) {
		return false;
	}

	if (enable) {
		atomic_set_bit(&ws->flags, WS_FLAG_ENABLED);
	} else {
		atomic_clear_bit(&ws->flags, WS_FLAG_ENABLED);
	}

	/*
	 * Arm the backend eagerly at selection time. This is what makes the
	 * choice effective across sys_poweroff() (no later hook) as well as
	 * suspend. Backend-less sources (wake "for free") just skip this.
	 */
	if (ws->set_wake != NULL) {
		int ret = ws->set_wake(ws, enable);

		if (ret < 0) {
			LOG_WRN("%s: set_wake(%d) failed: %d",
				ws->name != NULL ? ws->name : "wakeup-source", enable, ret);
		}
	}

	return true;
}

void wakeup_source_arm_all(void)
{
	struct wakeup_source *ws;

	SYS_SLIST_FOR_EACH_CONTAINER(&wakeup_sources, ws, node) {
		if ((ws->set_wake != NULL) && atomic_test_bit(&ws->flags, WS_FLAG_ENABLED)) {
			(void)ws->set_wake(ws, true);
		}
	}
}

void wakeup_source_disarm_all(void)
{
	struct wakeup_source *ws;

	SYS_SLIST_FOR_EACH_CONTAINER(&wakeup_sources, ws, node) {
		if ((ws->set_wake != NULL) && atomic_test_bit(&ws->flags, WS_FLAG_ENABLED)) {
			(void)ws->set_wake(ws, false);
		}
	}
}
