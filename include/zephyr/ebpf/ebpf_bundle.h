/*
 * SPDX-FileCopyrightText: Copyright 2026 NXP
 *
 * SPDX-License-Identifier: Apache-2.0
 */

/**
 * @file
 * @brief Public runtime-owned eBPF bundle access API.
 * @ingroup ebpf
 */

#ifndef ZEPHYR_INCLUDE_EBPF_BUNDLE_H_
#define ZEPHYR_INCLUDE_EBPF_BUNDLE_H_

#include <zephyr/ebpf/ebpf_map.h>

#ifdef __cplusplus
extern "C" {
#endif

struct ebpf_bundle;

/**
 * @brief Find one map owned by a bundle by its stable name.
 *
 * @param[in] bundle Bundle instance.
 * @param[in] name Map name.
 * @return Matching map, or NULL if the bundle or map name is invalid or absent.
 */
struct ebpf_map *ebpf_bundle_find_map(struct ebpf_bundle *bundle, const char *name);

#ifdef __cplusplus
}
#endif

#endif /* ZEPHYR_INCLUDE_EBPF_BUNDLE_H_ */
