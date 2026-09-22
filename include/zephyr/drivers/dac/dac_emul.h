/**
 * @file
 *
 * @brief Backend API for emulated DAC
 */

/*
 * Copyright (c) 2026 Vaisala Oyj
 *
 * SPDX-License-Identifier: Apache-2.0
 */

#ifndef ZEPHYR_INCLUDE_DRIVER_DAC_DAC_EMUL_H_
#define ZEPHYR_INCLUDE_DRIVER_DAC_DAC_EMUL_H_

#include <zephyr/device.h>
#include <stdbool.h>
#include <stdint.h>

/**
 * @brief Read a previously written value from the driver instance
 *
 * The channel must have been previously configured.
 *
 * @param dev The dac emulator device
 * @param channel The channel number to read
 * @param value The current channel value
 *
 * @retval 0 Success
 * @retval -EINVAL Invalid channel or NULL pointer
 * @retval -ENXIO Channel not configured
 * @retval -EBUSY Could not acquire channel lock
 *
 **/
int dac_emul_value_get(const struct device *dev, uint8_t channel, uint32_t *value);

/**
 * @brief Read whether a channel is currently driving its output
 *
 * A channel starts driving when a value is written to it and stops when
 * dac_channel_stop() is called. The value written last is kept either way, so
 * this reports the output state rather than the output level.
 *
 * @param dev The dac emulator device
 * @param channel The channel number to read
 * @param driving Whether the channel is driving its output
 *
 * @retval 0 Success
 * @retval -EINVAL Invalid channel or NULL pointer
 * @retval -EBUSY Could not acquire channel lock
 *
 **/
int dac_emul_is_driving(const struct device *dev, uint8_t channel, bool *driving);

#endif /* ZEPHYR_INCLUDE_DRIVER_DAC_DAC_EMUL_H_ */
