# Copyright 2026 NXP
# SPDX-License-Identifier: Apache-2.0

zephyr_library()

zephyr_library_sources_ifdef(CONFIG_NXP_PMC_POWER_RAIL nxp_pmc_power_rail.c)
zephyr_library_sources_ifdef(CONFIG_NXP_SLEEPCON_POWER_RAIL nxp_sleepcon_power_rail.c)
