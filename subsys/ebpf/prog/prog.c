/*
 * SPDX-FileCopyrightText: Copyright 2026 NXP
 *
 * SPDX-License-Identifier: Apache-2.0
 */

#include <string.h>
#include <zephyr/logging/log.h>

#include "../attach/target/target.h"
#include "prog.h"

LOG_MODULE_REGISTER(ebpf_prog, CONFIG_EBPF_LOG_LEVEL);

int ebpf_verify_for_target(const struct ebpf_prog_image *prog,
			   const struct ebpf_attach_target *target);

struct ebpf_prog {
	struct ebpf_prog_image image;
	struct {
		struct k_spinlock lock;
		uint8_t state;
		struct ebpf_attach_target target;
		uint32_t session_seq;
	} runtime;
};

enum ebpf_prog_state {
	EBPF_PROG_STATE_DETACHED = 0,
	EBPF_PROG_STATE_ATTACHED = 1,
	EBPF_PROG_STATE_VERIFIED = 2,
	EBPF_PROG_STATE_ENABLED = 3,
};

int ebpf_prog_create(const struct ebpf_prog_image *image, struct ebpf_prog **prog_out)
{
	if (image == NULL || prog_out == NULL) {
		return -EINVAL;
	}

	struct ebpf_prog *prog;

	prog = k_malloc(sizeof(*prog));
	if (prog == NULL) {
		return -ENOMEM;
	}

	memset(prog, 0, sizeof(*prog));
	prog->image = *image;
	prog->runtime.state = EBPF_PROG_STATE_DETACHED;
	prog->runtime.target = EBPF_ATTACH_TARGET_NONE;
	*prog_out = prog;

	return 0;
}

void ebpf_prog_destroy(struct ebpf_prog *prog)
{
	k_free(prog);
}

/**
 * @brief Check whether a program type may bind to a concrete target.
 *
 * Also validates that @p target names a supported backend point, so callers
 * do not need a separate range check.
 *
 * @param[in] type Program type.
 * @param[in] target Attachment target.
 * @retval true Programs of @p type may attach to @p target.
 * @retval false @p target is NULL, malformed, or incompatible with @p type.
 */
static bool ebpf_prog_can_attach_target(enum ebpf_prog_type type,
					const struct ebpf_attach_target *target)
{
	if (target == NULL) {
		return false;
	}

	switch (type) {
	case EBPF_PROG_TYPE_SCHED:
		return target->backend == EBPF_ATTACH_BACKEND_TRACING &&
		       (target->point == EBPF_TRACING_ATTACH_THREAD_SWITCHED_IN ||
			target->point == EBPF_TRACING_ATTACH_THREAD_SWITCHED_OUT ||
			target->point == EBPF_TRACING_ATTACH_IDLE_ENTER ||
			target->point == EBPF_TRACING_ATTACH_IDLE_EXIT);
	case EBPF_PROG_TYPE_ISR:
		return target->backend == EBPF_ATTACH_BACKEND_TRACING &&
		       (target->point == EBPF_TRACING_ATTACH_ISR_ENTER ||
			target->point == EBPF_TRACING_ATTACH_ISR_EXIT);
	case EBPF_PROG_TYPE_PM:
		return target->backend == EBPF_ATTACH_BACKEND_PM &&
		       target->point < EBPF_PM_ATTACH_MAX;
	default:
		return false;
	}
}

int ebpf_prog_attach(struct ebpf_prog *prog, struct ebpf_attach_target target)
{
	if (prog == NULL) {
		return -EINVAL;
	}

	if (!ebpf_prog_can_attach_target(prog->image.type, &target)) {
		LOG_ERR("Program '%s' type %d incompatible with target backend=%d point=%u",
			prog->image.name, prog->image.type, target.backend, target.point);
		return -EINVAL;
	}

	k_spinlock_key_t key = k_spin_lock(&prog->runtime.lock);

	if (prog->runtime.state != EBPF_PROG_STATE_DETACHED) {
		k_spin_unlock(&prog->runtime.lock, key);
		LOG_WRN("Program '%s' already attached to %s",
			prog->image.name, ebpf_attach_target_name(&prog->runtime.target));
		return -EALREADY;
	}

	prog->runtime.target = target;
	prog->runtime.session_seq++;
	prog->runtime.state = EBPF_PROG_STATE_ATTACHED;

	k_spin_unlock(&prog->runtime.lock, key);

	LOG_DBG("Program '%s' attached to %s", prog->image.name,
		ebpf_attach_target_name(&prog->runtime.target));

	return 0;
}

int ebpf_prog_detach(struct ebpf_prog *prog)
{
	if (prog == NULL) {
		return -EINVAL;
	}

	struct ebpf_attach_target target;

	k_spinlock_key_t key = k_spin_lock(&prog->runtime.lock);

	/* Idempotent: detaching an already-detached program is a no-op. */
	if (prog->runtime.state == EBPF_PROG_STATE_DETACHED) {
		k_spin_unlock(&prog->runtime.lock, key);
		LOG_DBG("Program '%s' already detached", prog->image.name);
		return 0;
	}

	target = prog->runtime.target;

	/* Fast path: if the program is ATTACHED or VERIFIED (not ENABLED),
	 * no backend interaction is needed — just reset the runtime locally.
	 */
	if (prog->runtime.state != EBPF_PROG_STATE_ENABLED) {
		prog->runtime.target = EBPF_ATTACH_TARGET_NONE;
		prog->runtime.session_seq++;
		prog->runtime.state = EBPF_PROG_STATE_DETACHED;
		k_spin_unlock(&prog->runtime.lock, key);
		LOG_DBG("Program '%s' detached", prog->image.name);
		return 0;
	}

	/* Slow path: the program is ENABLED, so the backend must be notified.
	 *
	 * Lock ordering is always: target lock → prog lock. We must release
	 * the prog lock first, acquire the target lock, then re-acquire the
	 * prog lock to avoid ABBA deadlock with paths that lock in the
	 * canonical order (e.g. the target invoking a callback on this prog).
	 */
	k_spin_unlock(&prog->runtime.lock, key);
	ebpf_attach_target_lock(&target);
	key = k_spin_lock(&prog->runtime.lock);

	/* Double-check: the state may have changed while locks were released.
	 * Only call into the backend if the program is still ENABLED on the
	 * same target we captured earlier.
	 */
	if (prog->runtime.state == EBPF_PROG_STATE_ENABLED &&
	    prog->runtime.target.backend == target.backend &&
	    prog->runtime.target.point == target.point) {
		ebpf_attach_target_disable_prog_locked(&prog->runtime.target, prog);
	}

	/* Unconditionally reset runtime: even if another thread already
	 * disabled the program, we still need to move to DETACHED.
	 */
	prog->runtime.target = EBPF_ATTACH_TARGET_NONE;
	prog->runtime.session_seq++;
	prog->runtime.state = EBPF_PROG_STATE_DETACHED;

	/* Release locks in reverse order. */
	k_spin_unlock(&prog->runtime.lock, key);
	ebpf_attach_target_unlock(&target);

	LOG_DBG("Program '%s' detached", prog->image.name);

	return 0;
}

static int ebpf_prog_verify(struct ebpf_prog *prog)
{
	if (prog == NULL) {
		return -EINVAL;
	}

	struct ebpf_attach_target target;

	k_spinlock_key_t key = k_spin_lock(&prog->runtime.lock);

	if (prog->runtime.state == EBPF_PROG_STATE_DETACHED) {
		k_spin_unlock(&prog->runtime.lock, key);
		LOG_ERR("Program '%s' is not attached", prog->image.name);
		return -ENOENT;
	}

	if (prog->runtime.state == EBPF_PROG_STATE_VERIFIED ||
	    prog->runtime.state == EBPF_PROG_STATE_ENABLED) {
		k_spin_unlock(&prog->runtime.lock, key);
		LOG_DBG("Program '%s' already verified for current attachment", prog->image.name);
		return 0;
	}

	/* Capture the current session_seq to detect any session changes during verification. */
	uint32_t session_seq = prog->runtime.session_seq;
	target = prog->runtime.target;

	k_spin_unlock(&prog->runtime.lock, key);

	/* Verification runs without holding the runtime lock. The result is committed
	 * only if the program is still in the same attachment session afterwards.
	 */
	int ret = ebpf_verify_for_target(&prog->image, &target);
	if (ret != 0) {
		LOG_ERR("Verification failed for '%s': %d", prog->image.name, ret);
		return ret;
	}

	key = k_spin_lock(&prog->runtime.lock);
	if (prog->runtime.state == EBPF_PROG_STATE_DETACHED ||
	    prog->runtime.session_seq != session_seq) {
		k_spin_unlock(&prog->runtime.lock, key);
		LOG_DBG("Program '%s' session changed during verify", prog->image.name);
		return -EAGAIN;
	}

	prog->runtime.state = EBPF_PROG_STATE_VERIFIED;
	k_spin_unlock(&prog->runtime.lock, key);

	LOG_DBG("Program '%s' verified", prog->image.name);

	return 0;
}

int ebpf_prog_enable(struct ebpf_prog *prog)
{
	if (prog == NULL) {
		return -EINVAL;
	}

	struct ebpf_attach_target target;

	k_spinlock_key_t key = k_spin_lock(&prog->runtime.lock);

	if (prog->runtime.state == EBPF_PROG_STATE_DETACHED) {
		k_spin_unlock(&prog->runtime.lock, key);
		LOG_ERR("Program '%s' is not attached", prog->image.name);
		return -ENOENT;
	}

	if (prog->runtime.state == EBPF_PROG_STATE_ENABLED) {
		k_spin_unlock(&prog->runtime.lock, key);
		LOG_DBG("Program '%s' already enabled for current attachment", prog->image.name);
		return 0;
	}
	target = prog->runtime.target;

	k_spin_unlock(&prog->runtime.lock, key);

	int ret = ebpf_prog_verify(prog);
	if (ret != 0) {
		LOG_ERR("Enable failed for '%s': %d", prog->image.name, ret);
		return ret;
	}

	ebpf_attach_target_lock(&target);
	key = k_spin_lock(&prog->runtime.lock);
	ret = 0;

	if (prog->runtime.state == EBPF_PROG_STATE_DETACHED ||
	    prog->runtime.target.backend != target.backend ||
	    prog->runtime.target.point != target.point) {
		ret = -EAGAIN;
	} else if (prog->runtime.state == EBPF_PROG_STATE_ENABLED) {
		ret = 0;
	} else if (prog->runtime.state == EBPF_PROG_STATE_VERIFIED) {
		ret = ebpf_attach_target_enable_prog_locked(&prog->runtime.target, prog,
						 prog->runtime.session_seq);
		if (ret == 0) {
			prog->runtime.state = EBPF_PROG_STATE_ENABLED;
		}
	} else if (prog->runtime.state != EBPF_PROG_STATE_ENABLED) {
		ret = -EAGAIN;
	}

	k_spin_unlock(&prog->runtime.lock, key);
	ebpf_attach_target_unlock(&target);
	if (ret != 0) {
		LOG_DBG("Program '%s' state changed during enable", prog->image.name);
		return ret;
	}

	LOG_DBG("Program '%s' enabled", prog->image.name);

	return 0;
}

static int ebpf_prog_disable_internal(struct ebpf_prog *prog,
				      bool wait_for_quiescence)
{
	if (prog == NULL) {
		return -EINVAL;
	}

	struct ebpf_attach_target target;

	k_spinlock_key_t key = k_spin_lock(&prog->runtime.lock);
	if (prog->runtime.state != EBPF_PROG_STATE_ENABLED) {
		k_spin_unlock(&prog->runtime.lock, key);
		LOG_DBG("Program '%s' already not enabled", prog->image.name);
		return 0;
	}
	target = prog->runtime.target;
	k_spin_unlock(&prog->runtime.lock, key);

	ebpf_attach_target_lock(&target);
	key = k_spin_lock(&prog->runtime.lock);
	if (prog->runtime.state != EBPF_PROG_STATE_ENABLED ||
	    prog->runtime.target.backend != target.backend ||
	    prog->runtime.target.point != target.point) {
		k_spin_unlock(&prog->runtime.lock, key);
		ebpf_attach_target_unlock(&target);
		LOG_DBG("Program '%s' state changed before disable commit", prog->image.name);
		return 0;
	}

	if (wait_for_quiescence) {
		ebpf_attach_target_disable_prog_sync_locked(&prog->runtime.target, prog);
	} else {
		ebpf_attach_target_disable_prog_locked(&prog->runtime.target, prog);
	}
	prog->runtime.state = EBPF_PROG_STATE_VERIFIED;

	k_spin_unlock(&prog->runtime.lock, key);
	ebpf_attach_target_unlock(&target);

	LOG_DBG("Program '%s' disabled", prog->image.name);

	return 0;
}

int ebpf_prog_disable(struct ebpf_prog *prog)
{
	return ebpf_prog_disable_internal(prog, false);
}

int ebpf_prog_disable_sync(struct ebpf_prog *prog)
{
	return ebpf_prog_disable_internal(prog, true);
}

int64_t ebpf_prog_exec_target(const struct ebpf_prog *prog,
			      const struct ebpf_attach_target *target,
			      void *ctx_data, uint32_t ctx_size)
{
	if (prog == NULL) {
		return -EINVAL;
	}

	return ebpf_vm_exec_target(&prog->image, target, ctx_data, ctx_size);
}
