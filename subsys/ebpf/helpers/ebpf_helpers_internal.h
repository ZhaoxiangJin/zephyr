/*
 * SPDX-FileCopyrightText: Copyright 2026 NXP
 *
 * SPDX-License-Identifier: Apache-2.0
 */

/**
 * @file
 * @brief Internal eBPF helper dispatch interfaces.
 */

#ifndef ZEPHYR_SUBSYS_EBPF_HELPERS_INTERNAL_H_
#define ZEPHYR_SUBSYS_EBPF_HELPERS_INTERNAL_H_

#include <stdint.h>

#include <zephyr/ebpf/ebpf_helpers.h>

#ifdef __cplusplus
extern "C" {
#endif

typedef uint64_t (*ebpf_helper_fn)(uint64_t r1, uint64_t r2, uint64_t r3,
				   uint64_t r4, uint64_t r5);

ebpf_helper_fn ebpf_get_helper(uint32_t id);

#ifdef __cplusplus
}
#endif

#endif /* ZEPHYR_SUBSYS_EBPF_HELPERS_INTERNAL_H_ */
