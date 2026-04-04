/*
 * SPDX-FileCopyrightText: Copyright 2026 NXP
 *
 * SPDX-License-Identifier: Apache-2.0
 */

#include <zephyr/kernel.h>
#include <zephyr/init.h>
#include <zephyr/logging/log.h>

#include "attach/ebpf_attach_target_internal.h"

LOG_MODULE_REGISTER(ebpf_init, CONFIG_EBPF_LOG_LEVEL);

/** @brief Initialize eager eBPF attachment runtime state during application startup. */
static int ebpf_init(void)
{
	LOG_INF("eBPF subsystem initializing");

	ebpf_attach_targets_init();

	LOG_INF("eBPF subsystem ready");

	return 0;
}

SYS_INIT(ebpf_init, POST_KERNEL, CONFIG_EBPF_INIT_PRIORITY);
