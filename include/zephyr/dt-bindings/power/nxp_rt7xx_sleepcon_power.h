/*
 * Copyright 2026 NXP
 *
 * SPDX-License-Identifier: Apache-2.0
 */

#ifndef ZEPHYR_INCLUDE_DT_BINDINGS_POWER_NXP_RT7XX_SLEEPCON_POWER_H_
#define ZEPHYR_INCLUDE_DT_BINDINGS_POWER_NXP_RT7XX_SLEEPCON_POWER_H_

/*
 * Named rail identifiers for use with
 *   nxp,power-rails = <&sleepcon0 NXP_RT7XX_SLEEPCON_*>;
 *
 * The SLEEPCON identifier space is the direct bit position within the
 * single RUNCFG register.
 */

#define NXP_RT7XX_SLEEPCON_SHUT_COMPT_MAINCLK  0
#define NXP_RT7XX_SLEEPCON_SHUT_COMNN_MAINCLK  5
#define NXP_RT7XX_SLEEPCON_SHUT_MEDIA_MAINCLK  6

#endif /* ZEPHYR_INCLUDE_DT_BINDINGS_POWER_NXP_RT7XX_SLEEPCON_POWER_H_ */
