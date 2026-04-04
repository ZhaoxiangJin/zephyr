/*
 * SPDX-FileCopyrightText: Copyright 2026 NXP
 *
 * SPDX-License-Identifier: Apache-2.0
 */

/**
 * @file
 * @brief eBPF program authoring section macros.
 * @ingroup ebpf
 */

#ifndef ZEPHYR_INCLUDE_EBPF_PROG_H_
#define ZEPHYR_INCLUDE_EBPF_PROG_H_

#ifdef __cplusplus
extern "C" {
#endif

/** @brief Place one symbol into a named ELF section for the host-side packer. */
#define EBPF_SEC(_name)				__attribute__((section(_name), used))

/** @brief Place one program in a generic hook section. */
#define EBPF_PROGRAM(_hook_name)		EBPF_SEC("ebpf/" _hook_name)

/** @brief Place one program in a scheduler-typed hook section. */
#define EBPF_PROGRAM_SCHED(_hook_name)		EBPF_SEC("ebpf.sched/" _hook_name)

/** @brief Place one program in an ISR-typed hook section. */
#define EBPF_PROGRAM_ISR(_hook_name)		EBPF_SEC("ebpf.isr/" _hook_name)

/** @brief Place one program in a PM-typed hook section. */
#define EBPF_PROGRAM_PM(_hook_name)		EBPF_SEC("ebpf.pm/" _hook_name)

#ifdef __cplusplus
}
#endif

#endif /* ZEPHYR_INCLUDE_EBPF_PROG_H_ */
