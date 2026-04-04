/*
 * SPDX-FileCopyrightText: Copyright 2026 NXP
 *
 * SPDX-License-Identifier: Apache-2.0
 */

/**
 * @file
 * @brief Internal eBPF program image and instance interfaces.
 *
 * @note Visibility: eBPF subsystem internals only; not exposed to applications.
 */

#ifndef ZEPHYR_SUBSYS_EBPF_PROG_H_
#define ZEPHYR_SUBSYS_EBPF_PROG_H_

#include <zephyr/kernel.h>

#include "../insn/insn.h"
#include "../attach/target/target_types.h"

#ifdef __cplusplus
extern "C" {
#endif

struct ebpf_prog;

/** @brief Internal eBPF program family selector. */
enum ebpf_prog_type {
	EBPF_PROG_TYPE_SCHED = 0,
	EBPF_PROG_TYPE_ISR = 1,
	EBPF_PROG_TYPE_PM = 2,
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

/**
 * @brief Create one program instance from an immutable image.
 *
 * The new instance starts in the DETACHED state. @p image is shallow-copied
 * into the program, so the caller must keep the @p insns buffer alive for the
 * lifetime of the program.
 *
 * @param[in]  image    Immutable program image; must not be NULL.
 * @param[out] prog_out Receives the new program on success.
 *
 * @retval 0        Program created.
 * @retval -EINVAL  @p image or @p prog_out is NULL.
 * @retval -ENOMEM  Allocation failed.
 */
int ebpf_prog_create(const struct ebpf_prog_image *image, struct ebpf_prog **prog_out);

/**
 * @brief Destroy one program instance.
 *
 * The program must already be detached. Passing NULL is a no-op.
 *
 * @param[in,out] prog Program to destroy.
 */
void ebpf_prog_destroy(struct ebpf_prog *prog);

/**
 * @brief Bind one program to an attach target.
 *
 * Transitions DETACHED -> ATTACHED. The program is not yet dispatched from the
 * hook; @ref ebpf_prog_enable must be called to commit it into the live path.
 *
 * @param[in,out] prog   Program to attach.
 * @param         target Attach target describing the hook point.
 *
 * @retval 0         Program attached.
 * @retval -EINVAL   @p prog is NULL, or @p target is invalid or incompatible
 *                   with the program type.
 * @retval -EALREADY @p prog is already attached.
 */
int ebpf_prog_attach(struct ebpf_prog *prog, struct ebpf_attach_target target);

/**
 * @brief Unbind one program from its attach target.
 *
 * Idempotent: returns 0 if the program is already detached. If currently
 * ENABLED, the program is synchronously quiesced before detach.
 *
 * @param[in,out] prog Program to detach.
 *
 * @retval 0        Program detached (or already detached).
 * @retval -EINVAL  @p prog is NULL.
 */
int ebpf_prog_detach(struct ebpf_prog *prog);

/**
 * @brief Verify and enable one attached program on the live dispatch path.
 *
 * Transitions ATTACHED/VERIFIED -> ENABLED. Runs the verifier on first call
 * since attach, then commits the program into the hook's dispatch list.
 *
 * @param[in,out] prog Program to enable.
 *
 * @retval 0        Program enabled (or already enabled for the current attach).
 * @retval -EINVAL  @p prog is NULL.
 * @retval -ENOENT  @p prog is not attached.
 * @retval -EAGAIN  State changed concurrently; retry.
 * @retval -errno   Verifier or backend failure.
 */
int ebpf_prog_enable(struct ebpf_prog *prog);

/**
 * @brief Remove one program from the live dispatch path.
 *
 * Transitions ENABLED -> VERIFIED. Does not wait for running invocations to
 * complete; use @ref ebpf_prog_disable_sync when quiescence is required.
 *
 * @param[in,out] prog Program to disable.
 *
 * @retval 0        Program disabled (or already not enabled).
 * @retval -EINVAL  @p prog is NULL.
 */
int ebpf_prog_disable(struct ebpf_prog *prog);

/**
 * @brief Disable one program and wait for in-flight invocations to drain.
 *
 * Same as @ref ebpf_prog_disable but returns only after all running
 * invocations of @p prog have completed.
 *
 * @param[in,out] prog Program to quiesce.
 *
 * @retval 0        Program disabled and quiesced.
 * @retval -EINVAL  @p prog is NULL.
 */
int ebpf_prog_disable_sync(struct ebpf_prog *prog);

/**
 * @brief Execute one program directly against a target without dispatch.
 *
 * Bypasses attach/enable state and runs @p prog in the VM with the given
 * context. Intended for callers that own the program and manage invocation
 * themselves (e.g. tests, offline evaluation).
 *
 * @param[in]     prog     Program to execute.
 * @param[in]     target   Attach target supplying the execution environment.
 * @param[in,out] ctx_data Context buffer passed to the program.
 * @param         ctx_size Size of @p ctx_data in bytes.
 *
 * @retval -EINVAL @p prog is NULL.
 * @return Program return value, or negative errno from the VM.
 */
int64_t ebpf_prog_exec_target(const struct ebpf_prog *prog,
			      const struct ebpf_attach_target *target,
			      void *ctx_data, uint32_t ctx_size);
#ifdef __cplusplus
}
#endif

#endif /* ZEPHYR_SUBSYS_EBPF_PROG_H_ */
