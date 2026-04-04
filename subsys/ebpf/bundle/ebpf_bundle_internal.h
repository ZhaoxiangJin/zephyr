/*
 * SPDX-FileCopyrightText: Copyright 2026 NXP
 *
 * SPDX-License-Identifier: Apache-2.0
 */

/**
 * @file
 * @brief Internal runtime-owned eBPF bundle interfaces.
 */

#ifndef ZEPHYR_SUBSYS_EBPF_BUNDLE_INTERNAL_H_
#define ZEPHYR_SUBSYS_EBPF_BUNDLE_INTERNAL_H_

#include <zephyr/ebpf/ebpf_bundle.h>

#include "../map/ebpf_map_internal.h"
#include "../map/ebpf_map_spec_internal.h"
#include "../prog/ebpf_prog_internal.h"
#include "../attach/ebpf_hook_internal.h"

#ifdef __cplusplus
extern "C" {
#endif

struct ebpf_bundle;

struct ebpf_attachment;

/**
 * @brief Attachment description used to add one attachment to a bundle.
 *
 * Callers such as the loader construct this descriptor before passing it to
 * ebpf_bundle_add_attachment(). It describes the attachment to create, but it
 * is not part of the bundle-private runtime object layout.
 */
struct ebpf_bundle_attachment_spec {
	const char *name;
	enum ebpf_prog_type type;
	const struct ebpf_insn *insns;
	uint32_t insn_cnt;
	const char *hook_name;
};

int ebpf_bundle_create(const char *name, struct ebpf_bundle **bundle_out);

int ebpf_bundle_destroy(struct ebpf_bundle *bundle);

int ebpf_bundle_add_map(struct ebpf_bundle *bundle,
			const struct ebpf_map_spec *spec,
			struct ebpf_map **map_out);

int ebpf_bundle_add_attachment(struct ebpf_bundle *bundle,
			       const struct ebpf_bundle_attachment_spec *spec,
			       struct ebpf_attachment **attachment_out);

int ebpf_bundle_enable(struct ebpf_bundle *bundle);

int ebpf_bundle_disable(struct ebpf_bundle *bundle);

#ifdef __cplusplus
}
#endif

#endif /* ZEPHYR_SUBSYS_EBPF_BUNDLE_INTERNAL_H_ */
