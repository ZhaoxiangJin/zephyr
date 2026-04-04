/*
 * SPDX-FileCopyrightText: Copyright 2026 NXP
 *
 * SPDX-License-Identifier: Apache-2.0
 */

/**
 * @file
 * @brief Internal eBPF attachment-target runtime interfaces.
 *
 * @note Visibility: eBPF subsystem internals only.
 */

#ifndef ZEPHYR_SUBSYS_EBPF_ATTACH_TARGET_H_
#define ZEPHYR_SUBSYS_EBPF_ATTACH_TARGET_H_

#include <stdbool.h>
#include <stdint.h>

#include "../../prog/prog.h"

#ifdef __cplusplus
extern "C" {
#endif

/**
 * @brief Return a human-readable name for @p target.
 *
 * The returned string is a stable static literal owned by the subsystem and
 * safe to use from any context, including LOG callbacks. Sentinel and
 * malformed targets resolve to @c "none" and @c "invalid" respectively so
 * callers never need to branch on validity before logging.
 *
 * @param[in] target Attachment target; may be NULL.
 *
 * @return Pointer to a NUL-terminated static string.
 */
const char *ebpf_attach_target_name(const struct ebpf_attach_target *target);

/**
 * @brief Check whether @p target currently has at least one enabled program.
 *
 * Intended as a cheap predicate for backend hot paths so that expensive
 * context construction can be skipped when nothing is attached. The check is
 * lock-free and safe to call from ISR context.
 *
 * @param[in] target Attachment target.
 *
 * @retval true  At least one program is currently enabled on @p target.
 * @retval false @p target is invalid or has no enabled programs.
 */
bool ebpf_attach_target_is_active(const struct ebpf_attach_target *target);

/**
 * @brief Invoke every enabled program on @p target with @p ctx.
 *
 * The dispatcher acquires a lock-free snapshot of the current attachments and
 * executes each program in registration order. Safe to call from ISR context.
 * Programs are invoked sequentially; return values are discarded.
 *
 * @param[in] target   Attachment target.
 * @param[in] ctx      Program context buffer passed to every attached program.
 * @param[in] ctx_size Size of @p ctx in bytes.
 */
void ebpf_attach_target_dispatch(const struct ebpf_attach_target *target,
				 void *ctx, uint32_t ctx_size);

/**
 * @brief Acquire the writer mutex that protects @p target.
 *
 * Serialises all enable/disable operations on a single target. Must be paired
 * with @ref ebpf_attach_target_unlock. Callers must not hold any program-level
 * lock when acquiring the target lock (lock order: target → prog).
 *
 * @param[in] target Attachment target.
 */
void ebpf_attach_target_lock(const struct ebpf_attach_target *target);

/**
 * @brief Release the writer mutex acquired by @ref ebpf_attach_target_lock.
 *
 * @param[in] target Attachment target.
 */
void ebpf_attach_target_unlock(const struct ebpf_attach_target *target);

/**
 * @brief Enable @p prog on @p target while holding the target lock.
 *
 * Publishes a new attachment snapshot that includes @p prog with the supplied
 * @p session_seq. If @p prog is already enabled on @p target, its entry is
 * replaced. The caller must hold the target lock via
 * @ref ebpf_attach_target_lock.
 *
 * @param[in] target      Attachment target.
 * @param[in] prog        Program to enable.
 * @param[in] session_seq Monotonic session identifier supplied by the program
 *                        state machine; preserved across snapshots.
 *
 * @retval 0        @p prog is now enabled on @p target.
 * @retval -ENOSPC  @p target already has the maximum number of attachments.
 */
int ebpf_attach_target_enable_prog_locked(const struct ebpf_attach_target *target,
					  struct ebpf_prog *prog,
					  uint32_t session_seq);

/**
 * @brief Disable @p prog on @p target while holding the target lock.
 *
 * Publishes a new snapshot that no longer contains @p prog. The call returns
 * as soon as the snapshot is published; in-flight dispatches observing the
 * previous snapshot may still invoke @p prog until they complete. The caller
 * must hold the target lock.
 *
 * @param[in] target Attachment target.
 * @param[in] prog   Program to disable.
 */
void ebpf_attach_target_disable_prog_locked(const struct ebpf_attach_target *target,
					    const struct ebpf_prog *prog);

/**
 * @brief Disable @p prog on @p target and wait for in-flight dispatches.
 *
 * Like @ref ebpf_attach_target_disable_prog_locked, but blocks until the
 * retired snapshot has no remaining readers. On return, no CPU is executing
 * @p prog through this target and the caller may safely release resources
 * owned by @p prog. The caller must hold the target lock.
 *
 * @param[in] target Attachment target.
 * @param[in] prog   Program to disable synchronously.
 */
void ebpf_attach_target_disable_prog_sync_locked(const struct ebpf_attach_target *target,
						 const struct ebpf_prog *prog);

#ifdef __cplusplus
}
#endif

#endif /* ZEPHYR_SUBSYS_EBPF_ATTACH_TARGET_H_ */

