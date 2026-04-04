/*
 * SPDX-FileCopyrightText: Copyright 2026 NXP
 *
 * SPDX-License-Identifier: Apache-2.0
 */

#include <stdint.h>

#include <zephyr/ebpf/ebpf_helpers.h>
#include <zephyr/ebpf/ebpf_map.h>
#include <zephyr/ebpf/ebpf_prog.h>

EBPF_MAP(counter_map, EBPF_MAP_TYPE_ARRAY, uint32_t, uint32_t, 1);

EBPF_PROGRAM_SCHED("kernel/thread_switched_in")
int count_thread_switches(void *ctx)
{
	uint32_t key = 0;
	uint32_t *value;

	(void)ctx;

	value = ebpf_map_lookup_elem(&counter_map, &key);
	if (value != 0) {
		*value += 1;
	}

	return 0;
}
