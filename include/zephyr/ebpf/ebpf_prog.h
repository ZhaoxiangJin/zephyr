/*
 * SPDX-FileCopyrightText: Copyright 2026 NXP
 *
 * SPDX-License-Identifier: Apache-2.0
 */

/**
 * @file
 * @brief eBPF program descriptor and management API.
 *
 * @defgroup ebpf eBPF
 * @since 4.5
 * @version 0.1.0
 * @ingroup os_services
 * @{
 * @ingroup ebpf
 */

#ifndef ZEPHYR_INCLUDE_EBPF_PROG_H_
#define ZEPHYR_INCLUDE_EBPF_PROG_H_

#include <zephyr/kernel.h>
#include <zephyr/sys/iterable_sections.h>

#include <zephyr/ebpf/ebpf_attach_target.h>
#include <zephyr/ebpf/ebpf_insn.h>

#ifdef __cplusplus
extern "C" {
#endif

struct ebpf_prog;

/**
 * @brief Supported eBPF program types.
 *
 * Program type determines which attachment targets are valid and
 * what context structure is passed in register ``R1``.
 */
enum ebpf_prog_type {
	/** Generic program that can attach to any supported eBPF target. */
	EBPF_PROG_TYPE_GENERIC = 0,

	/** Typed program for scheduler-related hooks. */
	EBPF_PROG_TYPE_SCHED   = 1,

	/** Typed program for interrupt-service hooks. */
	EBPF_PROG_TYPE_ISR     = 2,

	/** Typed program for power-management notifier hooks. */
	EBPF_PROG_TYPE_PM      = 3,

	/** Number of supported program types. */
	EBPF_PROG_TYPE_MAX
};

/** @cond INTERNAL_HIDDEN */

/**
 * @brief Internal eBPF program lifecycle state.
 *
 * The runtime tracks whether a program is detached, attached but not yet
 * verified, verified for its current session, or enabled for dispatch.
 */
enum ebpf_prog_state {
	/** Program is not currently attached to any target. */
	EBPF_PROG_STATE_DETACHED = 0,

	/** Program is attached but not yet verified for the current session. */
	EBPF_PROG_STATE_ATTACHED = 1,

	/** Program is verified for its current attachment session. */
	EBPF_PROG_STATE_VERIFIED = 2,

	/** Program is enabled for its current attachment session. */
	EBPF_PROG_STATE_ENABLED  = 3,
};

/**
	 * @brief Execution statistics for one attachment session.
 */
struct ebpf_prog_stats {
	/** Number of completed program executions in this session. */
	uint64_t run_count;

	/** Total execution time accumulated in this session. */
	uint64_t run_time_ns;
};

/**
 * @brief Runtime state for the current attachment session.
 *
 * An attachment begins when a program attaches to one concrete target
 * and ends when that program detaches. Verification, enablement, and
 * execution statistics all belong to that current attachment session.
 */
struct ebpf_prog_runtime {
	/** Protects all runtime fields from concurrent access. */
	struct k_spinlock lock;

	/** Runtime state for the current session. */
	enum ebpf_prog_state state;

	/** Target currently bound to this session, or NONE if detached. */
	struct ebpf_attach_target target;

	/** Monotonic identifier for the current attachment session. */
	uint32_t session_seq;

	/** Execution statistics for the current attachment session. */
	struct ebpf_prog_stats stats;
};

/** @endcond */

/**
 * @brief eBPF program descriptor.
 *
 * Placed in a RAM iterable section so runtime state is mutable.
 * The bytecode pointer itself points to const ROM data.
 */
struct ebpf_prog {
	/** Program name for shell output and diagnostics. */
	const char *name;

	/** Program type. */
	enum ebpf_prog_type type;

	/** Pointer to the immutable bytecode array. */
	const struct ebpf_insn *insns;

	/** Number of instructions in @p insns. */
	uint32_t insn_cnt;

	/** @cond INTERNAL_HIDDEN */

	/** Runtime state for the current attachment session. */
	struct ebpf_prog_runtime runtime;

	/** @endcond */
};

/**
 * @brief Define an eBPF program at compile time.
 *
 * The program starts in DETACHED state and must be attached and enabled
 * at runtime.
 *
 * @param[in] _name C identifier for this program.
 * @param[in] _type Program type.
 * @param[in] _insns Pointer to the instruction array.
 * @param[in] _insn_cnt Number of instructions in @p _insns.
 */
#define EBPF_PROG_DEFINE(_name, _type, _insns, _insn_cnt)	\
	STRUCT_SECTION_ITERABLE(ebpf_prog, _name) = {		\
		.name         = STRINGIFY(_name),		\
		.type         = (_type),			\
		.insns        = (_insns),			\
		.insn_cnt     = (_insn_cnt),			\
		.runtime      = {				\
			.state = EBPF_PROG_STATE_DETACHED,	\
			.target = EBPF_ATTACH_TARGET_NONE,	\
			.session_seq = 0,			\
			.stats = { 0, 0 },			\
		},						\
	}

/** @cond INTERNAL_HIDDEN */

/**
 * @brief Initialize one eBPF program descriptor at runtime.
 *
 * This is primarily useful for tests or dynamically constructed descriptors
 * that are not registered through :c:macro:`EBPF_PROG_DEFINE`.
 * The runtime session starts detached with cleared statistics.
 *
 * @param[out] prog Program descriptor to initialize.
 * @param[in] name Program name.
 * @param[in] type Program type.
 * @param[in] insns Program bytecode.
 * @param[in] insn_cnt Number of instructions in @p insns.
 */
void ebpf_prog_init(struct ebpf_prog *prog, const char *name,
		    enum ebpf_prog_type type,
		    const struct ebpf_insn *insns, uint32_t insn_cnt);

/** @endcond */

/**
 * @brief Attach a program to a concrete eBPF target.
 *
 * A program may be attached to only one target at a time. Each successful
 * attach starts a new attachment session, invalidates any prior verification
 * result, and resets the current-session execution statistics.
 *
 * @param[in,out] prog Program to attach.
 * @param[in] target Concrete attach target.
 * @retval 0 Program attached successfully.
 * @retval -EINVAL @p prog is NULL, @p target is invalid, or the target is not
 *	   compatible with the program type.
 * @retval -EALREADY Program is already attached to a target.
 */
int ebpf_prog_attach(struct ebpf_prog *prog, struct ebpf_attach_target target);

/**
 * @brief Detach a program from its current target.
 *
 * If the program is enabled, it is disabled first. Detaching ends the current
 * attachment session and clears that session's runtime state.
 *
 * @param[in,out] prog Program to detach.
 * @retval 0 Program detached successfully.
 * @retval -EINVAL @p prog is NULL.
 */
int ebpf_prog_detach(struct ebpf_prog *prog);

/**
 * @brief Verify an eBPF program so it can be enabled safely.
 *
 * Verification is scoped to the current attachment session.
 *
 * @param[in,out] prog Program to verify.
 * @retval 0 Program is already verified for its current attachment or
 *	   verifies successfully.
 * @retval -EINVAL @p prog is NULL.
 * @retval -ENOENT Program is not attached to a target.
 * @return Negative errno returned by the verifier otherwise.
 */
int ebpf_prog_verify(struct ebpf_prog *prog);

/**
 * @brief Enable an attached eBPF program.
 *
 * Verification runs automatically the first time a program is enabled.
 *
 * @param[in,out] prog Program to enable.
 * @retval 0 Program enabled successfully.
 * @retval -EINVAL @p prog is NULL.
 * @retval -ENOENT Program is not attached to a target.
 * @return Negative errno returned by the verifier if verification fails.
 */
int ebpf_prog_enable(struct ebpf_prog *prog);

/**
 * @brief Disable an attached eBPF program while preserving attachment.
 *
 * Disabling a program that is not enabled succeeds and leaves the program
 * state unchanged.
 *
 * @param[in,out] prog Program to disable.
 * @retval 0 Program disabled successfully.
 * @retval -EINVAL @p prog is NULL.
 */
int ebpf_prog_disable(struct ebpf_prog *prog);

/**
 * @brief Get one snapshot of the current program state.
 *
 * The returned value is copied while holding the program runtime lock.
 * If @p prog is NULL, the detached state is returned.
 *
 * @param[in] prog Program descriptor.
 * @return Current lifecycle state snapshot.
 */
enum ebpf_prog_state ebpf_prog_get_state(const struct ebpf_prog *prog);

/**
 * @brief Get one snapshot of the current attachment target.
 *
 * The returned value is copied while holding the program runtime lock.
 * If @p prog is NULL, :c:macro:`EBPF_ATTACH_TARGET_NONE` is returned.
 *
 * @param[in] prog Program descriptor.
 * @return Current attachment target snapshot.
 */
struct ebpf_attach_target ebpf_prog_get_target(const struct ebpf_prog *prog);

/**
 * @brief Get one snapshot of the current execution statistics.
 *
 * The returned value is copied while holding the program runtime lock.
 * If @p prog is NULL, zeroed statistics are returned.
 *
 * @param[in] prog Program descriptor.
 * @return Current attachment-session statistics snapshot.
 */
struct ebpf_prog_stats ebpf_prog_get_stats(const struct ebpf_prog *prog);

#ifdef __cplusplus
}
#endif

/** @} */

#endif /* ZEPHYR_INCLUDE_EBPF_PROG_H_ */
