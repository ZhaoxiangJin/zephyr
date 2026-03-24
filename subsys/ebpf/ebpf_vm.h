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

#include <zephyr/ebpf/ebpf_prog.h>

#ifdef __cplusplus
extern "C" {
#endif

/** @brief Per-invocation eBPF virtual machine state. */
struct ebpf_vm_ctx {
	/** Architectural register file. */
	uint64_t regs[EBPF_NUM_REGS];

	/** Current program counter. */
	uint32_t pc;

	/** Per-invocation VM stack. */
	uint8_t  stack[CONFIG_EBPF_STACK_SIZE];
};

/**
 * @brief Execute one eBPF program against one event context.
 *
 * @param[in] prog Program descriptor.
 * @param[in] ctx_data Event context passed in register ``R1``.
 * @param[in] ctx_size Size of @p ctx_data in bytes.
 * @return Program return value from register ``R0``.
 */
int64_t ebpf_vm_exec(const struct ebpf_prog *prog, void *ctx_data, uint32_t ctx_size);

#ifdef __cplusplus
}
#endif

#endif /* ZEPHYR_SUBSYS_EBPF_VM_H_ */
