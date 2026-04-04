/*
 * SPDX-FileCopyrightText: Copyright 2026 NXP
 *
 * SPDX-License-Identifier: Apache-2.0
 */

/**
 * @file
 * @brief Internal eBPF program image and instance interfaces.
 */

#ifndef ZEPHYR_SUBSYS_EBPF_PROG_INTERNAL_H_
#define ZEPHYR_SUBSYS_EBPF_PROG_INTERNAL_H_

#include <zephyr/kernel.h>

#include "../insn/ebpf_insn.h"
#include <zephyr/ebpf/ebpf_attach_target.h>

#ifdef __cplusplus
extern "C" {
#endif

struct ebpf_prog;

/** @brief Internal eBPF program family selector. */
enum ebpf_prog_type {
	EBPF_PROG_TYPE_GENERIC = 0,
	EBPF_PROG_TYPE_SCHED = 1,
	EBPF_PROG_TYPE_ISR = 2,
	EBPF_PROG_TYPE_PM = 3,
	EBPF_PROG_TYPE_MAX,
};

/** @brief Immutable eBPF program contents shared by verifier and VM. */
struct ebpf_prog_image {
	/** Program name. */
	const char *name;

	/** Program type. */
	enum ebpf_prog_type type;

	/** Pointer to the immutable bytecode array. */
	const struct ebpf_insn *insns;

	/** Number of instructions in @p insns. */
	uint32_t insn_cnt;
};

int ebpf_prog_create(const struct ebpf_prog_image *image, struct ebpf_prog **prog_out);

void ebpf_prog_destroy(struct ebpf_prog *prog);

int ebpf_prog_attach(struct ebpf_prog *prog, struct ebpf_attach_target target);

int ebpf_prog_detach(struct ebpf_prog *prog);

int ebpf_prog_enable(struct ebpf_prog *prog);

int ebpf_prog_disable(struct ebpf_prog *prog);

int ebpf_prog_disable_sync(struct ebpf_prog *prog);

int64_t ebpf_prog_exec_target(const struct ebpf_prog *prog,
			      const struct ebpf_attach_target *target,
			      void *ctx_data, uint32_t ctx_size);

#ifdef __cplusplus
}
#endif

#endif /* ZEPHYR_SUBSYS_EBPF_PROG_INTERNAL_H_ */
