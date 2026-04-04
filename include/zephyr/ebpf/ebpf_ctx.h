/*
 * SPDX-FileCopyrightText: Copyright 2026 NXP
 *
 * SPDX-License-Identifier: Apache-2.0
 */

/**
 * @file
 * @brief eBPF event-context layouts visible to restricted-C probes.
 * @ingroup ebpf
 *
 * These structures form the data ABI between the eBPF runtime and probe
 * bytecode: at each attachment point the runtime populates one of these
 * contexts and passes its address in R1 to the program.
 *
 * The matching attachment-point identifiers live in the internal
 * @c subsys/ebpf/attach/target_types.h header and are not part of the
 * application-visible API.
 */

#ifndef ZEPHYR_INCLUDE_EBPF_CTX_H_
#define ZEPHYR_INCLUDE_EBPF_CTX_H_

#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

/**
 * @brief Power-management state identifiers exposed to eBPF programs.
 *
 * These values intentionally match the corresponding enum pm_state values so
 * restricted-C eBPF probes can reason about PM contexts without including the
 * full kernel PM headers.
 */
enum ebpf_pm_state_id {
	EBPF_PM_STATE_ACTIVE = 0,
	EBPF_PM_STATE_RUNTIME_IDLE,
	EBPF_PM_STATE_SUSPEND_TO_IDLE,
	EBPF_PM_STATE_STANDBY,
	EBPF_PM_STATE_SUSPEND_TO_RAM,
	EBPF_PM_STATE_SUSPEND_TO_DISK,
	EBPF_PM_STATE_SOFT_OFF,
	EBPF_PM_STATE_COUNT,
};

/**
 * @brief Context passed to eBPF programs for thread events (via R1).
 */
struct ebpf_ctx_thread {
	/** Opaque thread cookie derived from the associated k_thread pointer. */
	uint64_t thread_cookie;

	/** Thread priority at the time of the event. */
	int32_t  priority;

	/** Event-specific thread state flags. */
	uint32_t flags;
};

/**
 * @brief Context for ISR events.
 */
struct ebpf_ctx_isr {
	/** Interrupt line number. */
	uint32_t irq_num;
};

/**
 * @brief Context for idle-entry and idle-exit tracing events.
 */
struct ebpf_ctx_idle {
	/** CPU index associated with the idle transition. */
	uint32_t cpu_id;
};

/**
 * @brief Context for power-management notifier events.
 */
struct ebpf_ctx_pm {
	/** CPU index associated with the event. */
	uint8_t cpu_id;

	/** Power-management state as an enum pm_state-compatible value. */
	uint32_t state;

	/** SoC-specific PM substate identifier. */
	uint8_t substate_id;
};

#ifdef __cplusplus
}
#endif

#endif /* ZEPHYR_INCLUDE_EBPF_CTX_H_ */
