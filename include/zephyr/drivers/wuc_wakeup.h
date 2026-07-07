/*
 * Copyright 2026 NXP
 *
 * SPDX-License-Identifier: Apache-2.0
 */

/**
 * @file
 * @brief NXP WUC backend for the generic wakeup-source framework.
 *
 * Glue that lets a device declared as a `wakeup-source` (and routed to a WUU /
 * LLWU line via `wakeup-ctrls`) plug into the portable wakeup-source framework:
 * the @ref wakeup_source_set_wake_t backend arms/disarms that WUC line, so the
 * application only ever calls wakeup_source_enable().
 */

#ifndef ZEPHYR_INCLUDE_DRIVERS_WUC_WAKEUP_H_
#define ZEPHYR_INCLUDE_DRIVERS_WUC_WAKEUP_H_

#include <zephyr/drivers/wuc.h>
#include <zephyr/pm/wakeup.h>

#ifdef __cplusplus
extern "C" {
#endif

/**
 * @brief WUC arming backend for a wakeup source.
 *
 * Use as the @p set_wake callback of a @ref wakeup_source whose
 * @ref wakeup_source.backend_data points at the @ref wuc_dt_spec to arm.
 */
static inline int wuc_wakeup_set_wake(const struct wakeup_source *ws, bool enable)
{
	const struct wuc_dt_spec *spec = ws->backend_data;

	if ((spec == NULL) || (spec->dev == NULL)) {
		return 0;
	}

	return enable ? wuc_enable_wakeup_source_dt(spec) : wuc_disable_wakeup_source_dt(spec);
}

/**
 * @brief Register a devicetree node's device as a WUC-backed wakeup source.
 *
 * For a node that is itself a device and carries both `wakeup-source` and
 * `wakeup-ctrls` (e.g. an LPTMR used as a counter), this binds the device to
 * its WUU/LLWU line. Expands to nothing unless the node has `wakeup-source`.
 *
 * @param node_id devicetree node identifier.
 */
#define WUC_WAKEUP_SOURCE_DT_DEFINE(node_id)                                                        \
	COND_CODE_1(DT_PROP(node_id, wakeup_source), (Z_WUC_WAKEUP_SOURCE_DEFINE(node_id)), ())

/** @cond INTERNAL_HIDDEN */
#define Z_WUC_WAKEUP_SOURCE_DEFINE(node_id)                                                         \
	static const struct wuc_dt_spec _CONCAT(__wuc_ws_spec_, DT_DEP_ORD(node_id)) =              \
		WUC_DT_SPEC_GET_OR(node_id, {0});                                                   \
	WAKEUP_SOURCE_DT_DEFINE(node_id, wuc_wakeup_set_wake,                                       \
				(void *)&_CONCAT(__wuc_ws_spec_, DT_DEP_ORD(node_id)))
/** @endcond */

/** @brief Like WUC_WAKEUP_SOURCE_DT_DEFINE() for a `DT_DRV_COMPAT` instance. */
#define WUC_WAKEUP_SOURCE_DT_INST_DEFINE(inst) WUC_WAKEUP_SOURCE_DT_DEFINE(DT_DRV_INST(inst))

#ifdef __cplusplus
}
#endif

#endif /* ZEPHYR_INCLUDE_DRIVERS_WUC_WAKEUP_H_ */
