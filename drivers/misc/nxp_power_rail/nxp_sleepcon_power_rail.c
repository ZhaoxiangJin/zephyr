/*
 * Copyright 2026 NXP
 *
 * SPDX-License-Identifier: Apache-2.0
 */

#define DT_DRV_COMPAT nxp_sleepcon_power_rail_controller

#include <errno.h>

#include <zephyr/device.h>
#include <zephyr/devicetree.h>
#include <zephyr/drivers/misc/nxp_power_rail/nxp_power_rail.h>
#include <zephyr/init.h>
#include <zephyr/kernel.h>
#include <zephyr/sys/__assert.h>
#include <zephyr/sys/sys_io.h>

/* SLEEPCON register map (offsets from DT reg base). */
#define NXP_SLEEPCON_RUNCFG_SET_OFFSET 0x20U
#define NXP_SLEEPCON_RUNCFG_CLR_OFFSET 0x30U

#define NXP_SLEEPCON_NUM_BITS 32U

struct nxp_sleepcon_power_rail_config {
	mm_reg_t base;
};

struct nxp_sleepcon_power_rail_data {
	struct k_spinlock lock;
	uint8_t refcount[NXP_SLEEPCON_NUM_BITS];
};

static int nxp_sleepcon_power_rail_request(const struct device *dev, uint16_t id)
{
	const struct nxp_sleepcon_power_rail_config *config = dev->config;
	struct nxp_sleepcon_power_rail_data *data = dev->data;
	k_spinlock_key_t key;

	if (id >= NXP_SLEEPCON_NUM_BITS) {
		return -EINVAL;
	}

	key = k_spin_lock(&data->lock);
	if (data->refcount[id]++ == 0U) {
		sys_write32(BIT(id), config->base + NXP_SLEEPCON_RUNCFG_CLR_OFFSET);
	}
	k_spin_unlock(&data->lock, key);

	return 0;
}

static int nxp_sleepcon_power_rail_release(const struct device *dev, uint16_t id)
{
	const struct nxp_sleepcon_power_rail_config *config = dev->config;
	struct nxp_sleepcon_power_rail_data *data = dev->data;
	k_spinlock_key_t key;

	if (id >= NXP_SLEEPCON_NUM_BITS) {
		return -EINVAL;
	}

	key = k_spin_lock(&data->lock);
	__ASSERT(data->refcount[id] > 0U,
		 "nxp_sleepcon_power_rail: id %u released without outstanding request", id);
	if ((data->refcount[id] > 0U) && (--data->refcount[id] == 0U)) {
		sys_write32(BIT(id), config->base + NXP_SLEEPCON_RUNCFG_SET_OFFSET);
	}
	k_spin_unlock(&data->lock, key);

	return 0;
}

static const struct nxp_power_rail_driver_api nxp_sleepcon_power_rail_api = {
	.request = nxp_sleepcon_power_rail_request,
	.release = nxp_sleepcon_power_rail_release,
};

static int nxp_sleepcon_power_rail_init(const struct device *dev)
{
	ARG_UNUSED(dev);

	return 0;
}

#define NXP_SLEEPCON_POWER_RAIL_DEFINE(inst)                                                       \
	static const struct nxp_sleepcon_power_rail_config                                         \
		nxp_sleepcon_power_rail_config_##inst = {                                          \
			.base = DT_INST_REG_ADDR(inst),                                            \
	};                                                                                         \
	static struct nxp_sleepcon_power_rail_data nxp_sleepcon_power_rail_data_##inst;            \
                                                                                                   \
	DEVICE_DT_INST_DEFINE(inst, nxp_sleepcon_power_rail_init, NULL,                            \
			      &nxp_sleepcon_power_rail_data_##inst,                                \
			      &nxp_sleepcon_power_rail_config_##inst, PRE_KERNEL_1,                \
			      CONFIG_NXP_POWER_RAIL_INIT_PRIORITY,                                 \
			      &nxp_sleepcon_power_rail_api);

DT_INST_FOREACH_STATUS_OKAY(NXP_SLEEPCON_POWER_RAIL_DEFINE)
