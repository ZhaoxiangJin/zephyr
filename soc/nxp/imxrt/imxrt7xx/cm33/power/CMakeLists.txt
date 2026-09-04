# SPDX-FileCopyrightText: Copyright 2026 NXP
# SPDX-License-Identifier: Apache-2.0

zephyr_include_directories(.)

zephyr_sources_ifdef(CONFIG_SOC_MIMXRT7XX_PM_XIP_HANDOVER     power_xip.c)

# Shared low-power entry sequence, used by both domain modules. This directory
# is only added for PM or POWEROFF builds, so it needs no guard of its own.
zephyr_sources(power_common.c)
