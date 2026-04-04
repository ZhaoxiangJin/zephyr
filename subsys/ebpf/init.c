/*
 * SPDX-FileCopyrightText: Copyright 2026 NXP
 *
 * SPDX-License-Identifier: Apache-2.0
 */

#include <zephyr/kernel.h>
#include <zephyr/init.h>
#include <zephyr/logging/log.h>

LOG_MODULE_REGISTER(ebpf_init, CONFIG_EBPF_LOG_LEVEL);

/** @brief Announce eBPF subsystem availability during application startup. */
static int ebpf_init(void)
{
	LOG_INF("eBPF subsystem ready");

	return 0;
}

SYS_INIT(ebpf_init, POST_KERNEL, CONFIG_EBPF_INIT_PRIORITY);
