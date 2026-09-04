/*
 * SPDX-FileCopyrightText: Copyright 2026 NXP
 *
 * SPDX-License-Identifier: Apache-2.0
 */

#ifndef SOC_NXP_IMXRT_IMXRT7XX_CM33_POWER_POWER_MODES_H_
#define SOC_NXP_IMXRT_IMXRT7XX_CM33_POWER_POWER_MODES_H_

#include <stdbool.h>

#ifdef __cplusplus
extern "C" {
#endif

/**
 * @brief Enter deep sleep mode.
 *
 * The set of blocks kept alive across the window is owned by the SoC (see
 * power_domain.h / power_resources.h); there is no caller-supplied mask.
 */
void power_enter_deep_sleep(void);

#if defined(CONFIG_SOC_IMXRT7XX_POWER_DOMAIN_COMPUTE)
/**
 * @brief Enter deep sleep retention (DSR) mode.
 *
 * Similar to deep sleep but with additional power-down and state retention.
 * Only available in the compute power domain.
 */
void power_enter_dsr(void);
#endif

#ifdef __cplusplus
}
#endif

#endif /* SOC_NXP_IMXRT_IMXRT7XX_CM33_POWER_POWER_MODES_H_ */
