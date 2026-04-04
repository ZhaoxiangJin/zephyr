/*
 * SPDX-FileCopyrightText: Copyright 2026 NXP
 *
 * SPDX-License-Identifier: Apache-2.0
 */

/**
 * @file
 * @brief Private eBPF map layout shared only inside the map subsystem.
 */

#ifndef ZEPHYR_SUBSYS_EBPF_MAP_PRIVATE_H_
#define ZEPHYR_SUBSYS_EBPF_MAP_PRIVATE_H_

#include <zephyr/kernel.h>
#include <zephyr/ebpf/ebpf_map.h>

#ifdef __cplusplus
extern "C" {
#endif

/**
 * @brief Private runtime map object layout.
 *
 * Both the map core and map backend implementations need direct ebpf_map
 * field access, while the rest of the eBPF subsystem should keep treating
 * struct ebpf_map as an opaque handle and use the shared accessors from
 * ebpf_map_internal.h.
 */
struct ebpf_map {
	const char *name;
	enum ebpf_map_type type;
	uint32_t key_size;
	uint32_t value_size;
	uint32_t max_entries;
	void *data;
	struct k_spinlock lock;
	uint32_t runtime_id;
	bool dynamic;
	void *owner;
};

#ifdef __cplusplus
}
#endif

#endif /* ZEPHYR_SUBSYS_EBPF_MAP_PRIVATE_H_ */
