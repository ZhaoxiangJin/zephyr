/*
 * Copyright 2026 NXP
 *
 * SPDX-License-Identifier: Apache-2.0
 */

/**
 * @file
 * @brief Generic wakeup-source framework (v1, RFC POC).
 *
 * A portable, vendor-neutral way to declare that a device can wake the system
 * from a low-power or off state, and to select it at run time. It is
 * deliberately independent of device power management (`CONFIG_PM_DEVICE`): a
 * wakeup source is just as relevant to `sys_poweroff()` - which has no device
 * PM at all - as it is to suspend-to-RAM.
 *
 * Layering (see the wakeup-source unification RFC):
 *  - L4 application: wakeup_source_enable(dev, true), then wait for the
 *    device's normal event (input, uart rx, counter alarm). Portable.
 *  - L3 this core: capability + policy + an iterable registry consulted on the
 *    low-power/off boundary; dispatches arming to an optional backend.
 *  - L2 vendor backend (optional): the `set_wake` callback arms a real wakeup
 *    unit (NXP WUU, STM32 PWR wkup pin, ...). Chips that wake "for free" (a
 *    surviving GPIO/EXTI interrupt) provide no backend.
 *
 * Modelled on Linux's wakeup-source framework (drivers/base/power/wakeup.c):
 * a runtime-registered list, sources may be standalone (no owning device), and
 * the hardware arming is delegated to a pluggable per-source backend
 * (cf. `irq_chip.irq_set_wake` / `IRQCHIP_SKIP_SET_WAKE`).
 */

#ifndef ZEPHYR_INCLUDE_PM_WAKEUP_H_
#define ZEPHYR_INCLUDE_PM_WAKEUP_H_

#include <stdbool.h>

#include <zephyr/device.h>
#include <zephyr/devicetree.h>
#include <zephyr/init.h>
#include <zephyr/sys/slist.h>
#include <zephyr/sys/atomic.h>
#include <zephyr/sys/util.h>

#ifdef __cplusplus
extern "C" {
#endif

/**
 * @brief Wakeup source
 * @defgroup wakeup_source_interface Wakeup source
 * @ingroup subsys_pm
 * @{
 */

struct wakeup_source;

/**
 * @brief Optional backend that arms/disarms the hardware wakeup unit.
 *
 * Called with @p enable true when the source becomes an active wakeup source
 * (routing it to an always-on wakeup unit and arming it) and false to undo it.
 * A source whose interrupt survives the low-power state "for free" needs no
 * backend and leaves this NULL.
 *
 * @param ws     the wakeup source
 * @param enable true to arm, false to disarm
 * @return 0 on success, negative errno on failure.
 */
typedef int (*wakeup_source_set_wake_t)(const struct wakeup_source *ws, bool enable);

/** @brief A wakeup source. Kept in RAM: the enabled flag is mutable. */
struct wakeup_source {
	/** Registry list node (internal). */
	sys_snode_t node;

	/** Owning device, or NULL for a standalone (device-less) source. */
	const struct device *dev;

	/** Human-readable name (for shell/stats); may be NULL. */
	const char *name;

	/** Optional vendor arming backend (see @ref wakeup_source_set_wake_t). */
	wakeup_source_set_wake_t set_wake;

	/** Backend private data (e.g. a routing spec); opaque to the core. */
	void *backend_data;

	/** Runtime flags (internal): enabled bit. */
	atomic_t flags;
};

#if defined(CONFIG_WAKEUP_SOURCE) || defined(__DOXYGEN__)

/**
 * @brief Register a wakeup source.
 *
 * Typically called by a device driver at init for a node that carries the
 * `wakeup-source` devicetree property, or by an application for a standalone
 * source. The source starts disabled.
 *
 * @param ws wakeup source to register (storage must outlive registration).
 */
void wakeup_source_register(struct wakeup_source *ws);

/**
 * @brief Unregister a wakeup source.
 *
 * @param ws previously registered wakeup source.
 */
void wakeup_source_unregister(struct wakeup_source *ws);

/**
 * @brief Look up the wakeup source owned by a device.
 *
 * @param dev device to look up.
 * @return the wakeup source, or NULL if @p dev is not a registered source.
 */
struct wakeup_source *wakeup_source_get(const struct device *dev);

/**
 * @brief Select (or deselect) a device as an active wakeup source.
 *
 * This is the portable application entry point. On enable the source's backend
 * (if any) is armed immediately, so the selection is effective even across
 * @ref sys_poweroff, which has no later hook. The choice persists until changed.
 *
 * @param dev    a device previously registered as a wakeup source.
 * @param enable true to make it wake the system, false to stop.
 * @return true if the request was applied, false if @p dev is not a
 *         wakeup-capable/registered source.
 */
bool wakeup_source_enable(const struct device *dev, bool enable);

/**
 * @brief Test whether a device is an enabled wakeup source.
 *
 * @param dev device to query.
 * @return true if @p dev is registered and currently enabled.
 */
bool wakeup_source_is_enabled(const struct device *dev);

/**
 * @brief Test whether a device is registered as a wakeup source at all.
 *
 * @param dev device to query.
 * @return true if @p dev can be used as a wakeup source.
 */
bool wakeup_source_is_capable(const struct device *dev);

/**
 * @brief (Re-)arm every enabled wakeup source's backend.
 *
 * Called on the way into a low-power/off state (from the PM suspend path). It
 * re-arms on every entry, which transparently covers silicon that clears its
 * wakeup configuration on each wakeup reset. Safe to call with no backends.
 */
void wakeup_source_arm_all(void);

/**
 * @brief Disarm every enabled wakeup source's backend.
 */
void wakeup_source_disarm_all(void);

/**
 * @brief Instantiate and auto-register a wakeup source for a devicetree node.
 *
 * Intended to be called unconditionally by the driver that owns @p node_id.
 * It expands to nothing unless the node has the `wakeup-source` property, so a
 * board opts a device in simply by adding `wakeup-source;` to its node. The
 * source is bound to @p node_id 's device and registered at @ref SYS_INIT time.
 *
 * @param node_id  devicetree node identifier of the wakeup-capable device.
 * @param _set_wake optional @ref wakeup_source_set_wake_t backend (or NULL for
 *                  sources that wake "for free" from a surviving interrupt).
 * @param _data    backend private data passed to @p _set_wake (or NULL).
 */
#define WAKEUP_SOURCE_DT_DEFINE(node_id, _set_wake, _data)                                         \
	COND_CODE_1(DT_PROP(node_id, wakeup_source),						\
		    (Z_WAKEUP_SOURCE_DEFINE(node_id, _set_wake, _data);), ())

/** @brief Like WAKEUP_SOURCE_DT_DEFINE() for a `DT_DRV_COMPAT` instance. */
#define WAKEUP_SOURCE_DT_INST_DEFINE(inst, _set_wake, _data)                                       \
	WAKEUP_SOURCE_DT_DEFINE(DT_DRV_INST(inst), _set_wake, _data)

/** @cond INTERNAL_HIDDEN */
#define Z_WAKEUP_SOURCE_DEFINE(node_id, _set_wake, _data)                                          \
	static struct wakeup_source _CONCAT(__wakeup_source_, DT_DEP_ORD(node_id)) = {             \
		.dev = DEVICE_DT_GET(node_id),                                                     \
		.name = DT_NODE_FULL_NAME(node_id),                                                \
		.set_wake = (_set_wake),                                                           \
		.backend_data = (_data),                                                           \
	};                                                                                         \
	static int _CONCAT(__wakeup_source_reg_, DT_DEP_ORD(node_id))(void)                        \
	{                                                                                          \
		wakeup_source_register(&_CONCAT(__wakeup_source_, DT_DEP_ORD(node_id)));           \
		return 0;                                                                          \
	}                                                                                          \
	SYS_INIT(_CONCAT(__wakeup_source_reg_, DT_DEP_ORD(node_id)), POST_KERNEL,                  \
		 CONFIG_WAKEUP_SOURCE_INIT_PRIORITY)
/** @endcond */

#else /* !CONFIG_WAKEUP_SOURCE */

/* Stubs so callers (e.g. the pm_device bridge) link when the framework is off. */
static inline void wakeup_source_register(struct wakeup_source *ws)
{
	ARG_UNUSED(ws);
}

static inline void wakeup_source_unregister(struct wakeup_source *ws)
{
	ARG_UNUSED(ws);
}

static inline struct wakeup_source *wakeup_source_get(const struct device *dev)
{
	ARG_UNUSED(dev);
	return NULL;
}

static inline bool wakeup_source_enable(const struct device *dev, bool enable)
{
	ARG_UNUSED(dev);
	ARG_UNUSED(enable);
	return false;
}

static inline bool wakeup_source_is_enabled(const struct device *dev)
{
	ARG_UNUSED(dev);
	return false;
}

static inline bool wakeup_source_is_capable(const struct device *dev)
{
	ARG_UNUSED(dev);
	return false;
}

static inline void wakeup_source_arm_all(void)
{
}

static inline void wakeup_source_disarm_all(void)
{
}

#define WAKEUP_SOURCE_DT_DEFINE(node_id, _set_wake, _data)
#define WAKEUP_SOURCE_DT_INST_DEFINE(inst, _set_wake, _data)

#endif /* CONFIG_WAKEUP_SOURCE */

/** @} */

#ifdef __cplusplus
}
#endif

#endif /* ZEPHYR_INCLUDE_PM_WAKEUP_H_ */
