/*
 * SPDX-FileCopyrightText: Copyright 2026 NXP
 *
 * SPDX-License-Identifier: Apache-2.0
 */

/**
 * @brief Internal eBPF VM interfaces.
 */

#ifndef ZEPHYR_SUBSYS_EBPF_VM_H_
#define ZEPHYR_SUBSYS_EBPF_VM_H_

#include "../prog/ebpf_prog_internal.h"

#ifdef __cplusplus
extern "C" {
#endif

/** @brief Bounded map-value region carried by one VM register. */
struct ebpf_vm_map_region {
	/** Start address of the resolved map value. */
	uintptr_t base;

	/** Size in bytes of the resolved map value. */
	uint32_t size;

	/** True when this register currently carries a bounded map-value pointer. */
	bool valid;
};

/** @brief Per-invocation eBPF virtual machine state. */
struct ebpf_vm_ctx {
	/** Architectural register file. */
	uint64_t regs[EBPF_NUM_REGS];

	/** Per-register bounded map-value regions. */
	struct ebpf_vm_map_region map_regions[EBPF_NUM_REGS];

	/** Current program counter. */
	uint32_t pc;

	/** Per-invocation VM stack. */
	uint8_t  stack[CONFIG_EBPF_STACK_SIZE];
};

struct ebpf_attach_target;

/**
 * @brief Execute one eBPF program image against one event context.

 * This convenience entry uses the detached baseline target policy rather than
 * any mutable attachment runtime state.
 *
 * @param[in] prog Program image.
 * @param[in] ctx_data Event context passed in register ``R1``.
 * @param[in] ctx_size Size of @p ctx_data in bytes.
 * @return Program return value from register ``R0``.
 */
int64_t ebpf_vm_exec(const struct ebpf_prog_image *prog, void *ctx_data,
		    uint32_t ctx_size);

/**
 * @brief Execute one eBPF program against one explicit attachment target.
 *
 * This is the race-free internal entry point used by the target dispatcher so
 * verifier and VM policy resolve against the published target snapshot rather
 * than mutable program runtime state.
 *
 * @param[in] prog Program image.
 * @param[in] target Published attachment target for this execution.
 * @param[in] ctx_data Event context passed in register ``R1``.
 * @param[in] ctx_size Size of @p ctx_data in bytes.
 * @return Program return value from register ``R0``.
 */
int64_t ebpf_vm_exec_target(const struct ebpf_prog_image *prog,
			    const struct ebpf_attach_target *target,
			    void *ctx_data, uint32_t ctx_size);

#ifdef __cplusplus
}
#endif

#endif /* ZEPHYR_SUBSYS_EBPF_VM_H_ */
