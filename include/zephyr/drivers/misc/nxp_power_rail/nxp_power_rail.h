/*
 * Copyright 2026 NXP
 *
 * SPDX-License-Identifier: Apache-2.0
 */

/**
 * they need in devicetree via the ``nxp,power-rails`` phandle-array
 * property and call this API to request / release them at runtime.
 *
 * Each NXP power-rail controller (PMC, SLEEPCON, ...) owns a register
 * block with a flat controller-local identifier namespace. Consumers describe the rails
 * they need in devicetree via the ``nxp,power-rails`` phandle-array
 * property and call this API to assert / release them at runtime.
 */

#ifndef ZEPHYR_INCLUDE_DRIVERS_MISC_NXP_POWER_RAIL_NXP_POWER_RAIL_H_
#define ZEPHYR_INCLUDE_DRIVERS_MISC_NXP_POWER_RAIL_NXP_POWER_RAIL_H_

#include <errno.h>
#include <stdint.h>

#include <zephyr/device.h>
#include <zephyr/devicetree.h>

#ifdef __cplusplus
extern "C" {
#endif

/**
 * @brief NXP power-rail controller driver API.
 *
 * Implemented by concrete controllers (PMC, SLEEPCON). Consumers call
 * the helpers below rather than these function pointers directly.
 */
struct nxp_power_rail_driver_api {
	int (*request)(const struct device *dev, uint16_t id);
	int (*release)(const struct device *dev, uint16_t id);
};

/**
 * @brief NXP power-rail specification.
 *
 * A rail is identified by a controller device plus a 16-bit identifier in
 * that controller's namespace. The interpretation of @ref id is
 * controller-specific:
 *  - PMC: ``pdruncfg_index * 32 + bit_within_register``
 *  - SLEEPCON: bit position within the ``RUNCFG`` register
 */
struct nxp_power_rail_spec {
	/** Controller device. */
	const struct device *dev;
	/** Controller-local rail identifier. */
	uint16_t id;
};

/**
 * @brief Build an ::nxp_power_rail_spec initializer from a devicetree
 *        ``nxp,power-rails`` element.
 *
 * @param node_id Consumer devicetree node identifier.
 * @param idx     Index into ``nxp,power-rails`` (0-based).
 */
#define NXP_POWER_RAIL_DT_SPEC_GET_BY_IDX(node_id, idx)                                            \
	{                                                                                          \
		.dev = DEVICE_DT_GET(DT_PHANDLE_BY_IDX(node_id, nxp_power_rails, idx)),            \
		.id = DT_PHA_BY_IDX(node_id, nxp_power_rails, idx, id),                            \
	}

/** @brief Equivalent to ``NXP_POWER_RAIL_DT_SPEC_GET_BY_IDX(node_id, 0)``. */
#define NXP_POWER_RAIL_DT_SPEC_GET(node_id) NXP_POWER_RAIL_DT_SPEC_GET_BY_IDX(node_id, 0)

/** @brief ``DT_DRV_COMPAT`` variant of NXP_POWER_RAIL_DT_SPEC_GET_BY_IDX(). */
#define NXP_POWER_RAIL_DT_INST_SPEC_GET_BY_IDX(inst, idx)                                          \
	NXP_POWER_RAIL_DT_SPEC_GET_BY_IDX(DT_DRV_INST(inst), idx)

/** @brief ``DT_DRV_COMPAT`` variant of NXP_POWER_RAIL_DT_SPEC_GET(). */
#define NXP_POWER_RAIL_DT_INST_SPEC_GET(inst) NXP_POWER_RAIL_DT_INST_SPEC_GET_BY_IDX(inst, 0)

/**
 * @brief Request a power rail.
 *
 * Calls are reference-counted by the controller driver: the physical
 * rail is released only when the first consumer requests it.
 *
 * @param dev Controller device.
 * @param id Controller-local rail identifier.
 *
 * @retval 0        On success.
 * @retval -ENODEV  @p dev is not ready.
 * @retval -EINVAL  @p id is out of range.
 */
static inline int nxp_power_rail_request(const struct device *dev, uint16_t id)
{
	const struct nxp_power_rail_driver_api *api;

	if (!device_is_ready(dev)) {
		return -ENODEV;
	}
	api = (const struct nxp_power_rail_driver_api *)dev->api;

	return api->request(dev, id);
}

/**
 * @brief Release a previous @ref nxp_power_rail_request request.
 *
 * The physical rail is asserted (powered down) only when the last
 * outstanding request is released.
 *
 * @param dev Controller device.
 * @param id Controller-local rail identifier.
 *
 * @retval 0        On success.
 * @retval -ENODEV  @p dev is not ready.
 * @retval -EINVAL  @p id is out of range.
 */
static inline int nxp_power_rail_release(const struct device *dev, uint16_t id)
{
	const struct nxp_power_rail_driver_api *api;

	if (!device_is_ready(dev)) {
		return -ENODEV;
	}
	api = (const struct nxp_power_rail_driver_api *)dev->api;

	return api->release(dev, id);
}

/** @brief Wrapper around @ref nxp_power_rail_request using a rail spec. */
static inline int nxp_power_rail_request_spec(const struct nxp_power_rail_spec *spec)
{
	return nxp_power_rail_request(spec->dev, spec->id);
}

/** @brief Wrapper around @ref nxp_power_rail_release using a rail spec. */
static inline int nxp_power_rail_release_spec(const struct nxp_power_rail_spec *spec)
{
	return nxp_power_rail_release(spec->dev, spec->id);
}

#ifdef __cplusplus
}
#endif

#endif /* ZEPHYR_INCLUDE_DRIVERS_MISC_NXP_POWER_RAIL_NXP_POWER_RAIL_H_ */
