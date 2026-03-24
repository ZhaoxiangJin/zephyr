/*
 * SPDX-FileCopyrightText: Copyright 2026 NXP
 *
 * SPDX-License-Identifier: Apache-2.0
 */

/**
 * @file
 * @brief eBPF attachment-target definitions and event contexts.
 * @ingroup ebpf
 */

#ifndef ZEPHYR_INCLUDE_EBPF_ATTACH_TARGET_H_
#define ZEPHYR_INCLUDE_EBPF_ATTACH_TARGET_H_

#include <stdint.h>
#include <stdbool.h>

#ifdef __cplusplus
extern "C" {
#endif

/**
 * @brief eBPF attach backends.
 */
enum ebpf_attach_backend {
	EBPF_ATTACH_BACKEND_TRACING = 0,
	EBPF_ATTACH_BACKEND_PM,
	EBPF_ATTACH_BACKEND_MAX,
};

/**
 * @brief Attachment points provided by the tracing backend.
 */
enum ebpf_tracing_attach_point {
	EBPF_TRACING_ATTACH_THREAD_SWITCHED_IN = 0,
	EBPF_TRACING_ATTACH_THREAD_SWITCHED_OUT,

	EBPF_TRACING_ATTACH_ISR_ENTER,
	EBPF_TRACING_ATTACH_ISR_EXIT,

	EBPF_TRACING_ATTACH_IDLE_ENTER,
	EBPF_TRACING_ATTACH_IDLE_EXIT,

	EBPF_TRACING_ATTACH_MAX,
};

/**
 * @brief Attachment points provided by the power-management notifier backend.
 */
enum ebpf_pm_attach_point {
	EBPF_PM_ATTACH_STATE_ENTRY = 0,
	EBPF_PM_ATTACH_STATE_EXIT,
	EBPF_PM_ATTACH_MAX,
};

/**
 * @brief Public description of a concrete eBPF attachment target.
 */
struct ebpf_attach_target {
	/** Backend namespace that owns @p point. */
	enum ebpf_attach_backend backend;

	/**
	 * Backend-specific attachment point identifier.
	 * This field is interpreted differently depending on the backend.
	 * For the tracing backend, it is a value from enum ebpf_tracing_attach_point.
	 * For the PM backend, it is a value from enum ebpf_pm_attach_point.
	 *
	 * Backends may reserve special point values for sentinel targets like
	 * EBPF_ATTACH_TARGET_NONE, which has backend=EBPF_ATTACH_BACKEND_MAX and point=0.
	 * Programs with EBPF_ATTACH_TARGET_NONE are considered detached.
	 */
	uint16_t point;
};

/**
 * @brief Build a concrete attachment target.
 *
 * @param[in] _backend Attach backend.
 * @param[in] _point Backend-specific attachment point.
 */
#define EBPF_ATTACH_TARGET(_backend, _point)	\
	((struct ebpf_attach_target){		\
		.backend = (_backend),		\
		.point = (uint16_t)(_point)	\
	})

/** @brief Sentinel target used for detached programs. */
#define EBPF_ATTACH_TARGET_NONE \
	EBPF_ATTACH_TARGET(EBPF_ATTACH_BACKEND_MAX, (0U))

/**
 * @brief Build a tracing-backend target.
 *
 * @param[in] _point Value from enum ebpf_tracing_attach_point.
 */
#define EBPF_ATTACH_TARGET_TRACING(_point) \
	EBPF_ATTACH_TARGET(EBPF_ATTACH_BACKEND_TRACING, (_point))

/**
 * @brief Build a PM-backend target.
 *
 * @param[in] _point Value from enum ebpf_pm_attach_point.
 */
#define EBPF_ATTACH_TARGET_PM(_point) \
	EBPF_ATTACH_TARGET(EBPF_ATTACH_BACKEND_PM, (_point))

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

	/** Power-management state as an enum pm_state value. */
	uint32_t state;

	/** SoC-specific PM substate identifier. */
	uint8_t substate_id;
};

/**
 * @brief Return a string name for an attach target.
 *
 * @param[in] target Attachment target.
 * @retval name Constant string describing @p target.
 * @retval "none" @p target is EBPF_ATTACH_TARGET_NONE.
 * @retval "invalid" @p target is NULL or unsupported.
 */
const char *ebpf_attach_target_name(const struct ebpf_attach_target *target);

/** @cond INTERNAL_HIDDEN */

/**
 * @brief Check whether a target currently has at least one enabled program.
 *
 * @param[in] target Attachment target.
 * @retval true At least one enabled program is attached to @p target.
 * @retval false @p target is invalid or no enabled program is attached.
 */
bool ebpf_attach_target_is_active(const struct ebpf_attach_target *target);

/**
 * @brief Dispatch one event context to all enabled programs on a target.
 *
 * The target runtime performs fan-out. Each matching program executes in its
 * own fresh VM invocation while optional runtime statistics remain scoped to
 * that program's current attachment.
 *
 * @param[in] target Attachment target.
 * @param[in] ctx Backend-specific event context passed in register ``R1``.
 * @param[in] ctx_size Size of @p ctx in bytes.
 */
void ebpf_attach_target_dispatch(const struct ebpf_attach_target *target,
				 void *ctx, uint32_t ctx_size);

/**
 * @brief Increment the active program count for a target.
 *
 * Called when a program transitions to ENABLED state.
 *
 * @param[in] target Attachment target.
 */
void ebpf_attach_target_inc(const struct ebpf_attach_target *target);

/**
 * @brief Decrement the active program count for a target.
 *
 * Called when a program transitions out of ENABLED state.
 *
 * @param[in] target Attachment target.
 */
void ebpf_attach_target_dec(const struct ebpf_attach_target *target);

/** @endcond */

#ifdef __cplusplus
}
#endif

#endif /* ZEPHYR_INCLUDE_EBPF_ATTACH_TARGET_H_ */
