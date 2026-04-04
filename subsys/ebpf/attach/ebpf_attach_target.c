/*
 * SPDX-FileCopyrightText: Copyright 2026 NXP
 *
 * SPDX-License-Identifier: Apache-2.0
 */

#include <string.h>

#include <zephyr/kernel.h>
#include <zephyr/sys/atomic.h>

#include "ebpf_attach_target_internal.h"
#include "../vm/ebpf_vm.h"

struct ebpf_dispatch_entry {
	struct ebpf_prog *prog;
	uint32_t session_seq;
};

struct ebpf_target_snapshot {
	atomic_t readers;
	uint16_t attachment_count;
	struct ebpf_dispatch_entry attachments[CONFIG_EBPF_MAX_ATTACHMENTS_PER_TARGET];
};

struct ebpf_target_runtime {
	struct k_mutex lock;
	atomic_ptr_t current_snapshot;
	struct ebpf_target_snapshot snapshots[2];
};

static struct ebpf_target_runtime ebpf_tracing_runtime[EBPF_TRACING_ATTACH_MAX];
static struct ebpf_target_runtime ebpf_pm_runtime[EBPF_PM_ATTACH_MAX];

struct ebpf_backend_desc {
	enum ebpf_attach_backend backend;
	const char * const *point_names;
	uint16_t point_count;
};

/** @brief String names for tracing backend attach points. */
static const char * const ebpf_tracing_target_names[] = {
	"tracing/thread_switched_in",
	"tracing/thread_switched_out",
	"tracing/isr_enter",
	"tracing/isr_exit",
	"tracing/idle_enter",
	"tracing/idle_exit",
};

/** @brief String names for PM backend attach points. */
static const char * const ebpf_pm_target_names[] = {
	"pm/state_entry",
	"pm/state_exit",
};

/** @brief Backend descriptor table used for validation and naming. */
static const struct ebpf_backend_desc ebpf_backends[] = {
	{
		.backend = EBPF_ATTACH_BACKEND_TRACING,
		.point_names = ebpf_tracing_target_names,
		.point_count = ARRAY_SIZE(ebpf_tracing_target_names),
	},
	{
		.backend = EBPF_ATTACH_BACKEND_PM,
		.point_names = ebpf_pm_target_names,
		.point_count = ARRAY_SIZE(ebpf_pm_target_names),
	},
};

/** @brief Look up the descriptor for one attach backend namespace. */
static const struct ebpf_backend_desc *ebpf_backend_desc_find(enum ebpf_attach_backend backend)
{
	for (size_t i = 0; i < ARRAY_SIZE(ebpf_backends); i++) {
		if (ebpf_backends[i].backend == backend) {
			return &ebpf_backends[i];
		}
	}

	return NULL;
}

static struct ebpf_target_runtime *ebpf_target_runtime_find(const struct ebpf_attach_target *target)
{
	if (!ebpf_attach_target_is_valid(target)) {
		return NULL;
	}

	switch (target->backend) {
	case EBPF_ATTACH_BACKEND_TRACING:
		return &ebpf_tracing_runtime[target->point];
	case EBPF_ATTACH_BACKEND_PM:
		return &ebpf_pm_runtime[target->point];
	default:
		return NULL;
	}
}

static void ebpf_target_runtime_init_one(struct ebpf_target_runtime *runtime)
{
	k_mutex_init(&runtime->lock);
	memset(runtime->snapshots, 0, sizeof(runtime->snapshots));
	atomic_ptr_set(&runtime->current_snapshot, &runtime->snapshots[0]);
}

static struct ebpf_target_snapshot *ebpf_target_snapshot_acquire(struct ebpf_target_runtime *runtime)
{
	struct ebpf_target_snapshot *snapshot;

	while (true) {
		snapshot = (struct ebpf_target_snapshot *)atomic_ptr_get(&runtime->current_snapshot);
		atomic_inc(&snapshot->readers);
		if ((struct ebpf_target_snapshot *)atomic_ptr_get(&runtime->current_snapshot) ==
		    snapshot) {
			return snapshot;
		}

		atomic_dec(&snapshot->readers);
	}
}

static void ebpf_target_snapshot_release(struct ebpf_target_snapshot *snapshot)
{
	atomic_dec(&snapshot->readers);
}

static void ebpf_target_snapshot_wait_readers(struct ebpf_target_snapshot *snapshot)
{
	if (snapshot == NULL) {
		return;
	}

	while (atomic_get(&snapshot->readers) != 0) {
		k_yield();
	}
}

static struct ebpf_target_snapshot *ebpf_target_snapshot_publish(struct ebpf_target_runtime *runtime,
							 struct ebpf_target_snapshot *next)
{
	return (struct ebpf_target_snapshot *)atomic_ptr_set(&runtime->current_snapshot, next);
}

static void ebpf_target_snapshot_remove_prog(struct ebpf_target_snapshot *snapshot,
					     const struct ebpf_prog *prog)
{
	for (uint16_t i = 0; i < snapshot->attachment_count;) {
		if (snapshot->attachments[i].prog == prog) {
			snapshot->attachment_count--;
			snapshot->attachments[i] =
				snapshot->attachments[snapshot->attachment_count];
			continue;
		}

		i++;
	}
}

static struct ebpf_target_snapshot *ebpf_target_runtime_prepare_next(struct ebpf_target_runtime *runtime)
{
	struct ebpf_target_snapshot *active;
	struct ebpf_target_snapshot *next;
	size_t copy_size;

	active = (struct ebpf_target_snapshot *)atomic_ptr_get(&runtime->current_snapshot);
	next = (active == &runtime->snapshots[0]) ?
		&runtime->snapshots[1] : &runtime->snapshots[0];

	while (atomic_get(&next->readers) != 0) {
		k_yield();
	}

	next->attachment_count = active->attachment_count;
	copy_size = sizeof(next->attachments[0]) * active->attachment_count;
	if (copy_size > 0U) {
		memcpy(next->attachments, active->attachments, copy_size);
	}

	return next;
}

/** @brief Return true if @p point is a scheduler-related tracing target. */
static bool ebpf_is_sched_tracing_point(uint16_t point)
{
	switch ((enum ebpf_tracing_attach_point)point) {
	case EBPF_TRACING_ATTACH_THREAD_SWITCHED_IN:
	case EBPF_TRACING_ATTACH_THREAD_SWITCHED_OUT:
		return true;
	default:
		return false;
	}
}

/**
 * @brief Check whether a program type may bind to a concrete target.
 *
 * This keeps backend-specific target numbering out of the public program
 * lifecycle code. Compatibility is expressed in terms of the stable program
 * taxonomy and backend namespace owned by the target runtime.
 *
 * @param[in] type Program type.
 * @param[in] target Attachment target.
 * @retval true Programs of @p type may attach to @p target.
 * @retval false @p type and @p target are not compatible.
 */
bool ebpf_prog_can_attach_target(enum ebpf_prog_type type,
				 const struct ebpf_attach_target *target)
{
	switch (type) {
	case EBPF_PROG_TYPE_GENERIC:
		return true;
	case EBPF_PROG_TYPE_SCHED:
		return target->backend == EBPF_ATTACH_BACKEND_TRACING &&
		       ebpf_is_sched_tracing_point(target->point);
	case EBPF_PROG_TYPE_ISR:
		return target->backend == EBPF_ATTACH_BACKEND_TRACING &&
		       (target->point == EBPF_TRACING_ATTACH_ISR_ENTER ||
		       target->point == EBPF_TRACING_ATTACH_ISR_EXIT);
	case EBPF_PROG_TYPE_PM:
		return target->backend == EBPF_ATTACH_BACKEND_PM;
	default:
		return false;
	}
}

/**
 * @brief Check whether an attach target names a supported backend point.
 *
 * This validates both the backend namespace and the point index within that
 * backend.
 *
 * @param[in] target Attachment target to validate.
 * @retval true @p target names a supported backend point.
 * @retval false @p target is NULL or names an unsupported backend point.
 */
bool ebpf_attach_target_is_valid(const struct ebpf_attach_target *target)
{
	if (target == NULL || target->backend >= EBPF_ATTACH_BACKEND_MAX) {
		return false;
	}

	const struct ebpf_backend_desc *backend;

	backend = ebpf_backend_desc_find(target->backend);

	return backend != NULL && target->point < backend->point_count;
}

int ebpf_attach_targets_init(void)
{
	for (size_t i = 0; i < ARRAY_SIZE(ebpf_tracing_runtime); i++) {
		ebpf_target_runtime_init_one(&ebpf_tracing_runtime[i]);
	}

	for (size_t i = 0; i < ARRAY_SIZE(ebpf_pm_runtime); i++) {
		ebpf_target_runtime_init_one(&ebpf_pm_runtime[i]);
	}

	return 0;
}

const char *ebpf_attach_target_name(const struct ebpf_attach_target *target)
{
	const struct ebpf_backend_desc *backend;

	if (target != NULL && target->backend == EBPF_ATTACH_BACKEND_MAX) {
		return "none";
	}

	if (!ebpf_attach_target_is_valid(target)) {
		return "invalid";
	}

	backend = ebpf_backend_desc_find(target->backend);

	return backend->point_names[target->point];
}

bool ebpf_attach_target_is_active(const struct ebpf_attach_target *target)
{
	struct ebpf_target_runtime *runtime;
	struct ebpf_target_snapshot *snapshot;

	if (!ebpf_attach_target_is_valid(target)) {
		return false;
	}

	runtime = ebpf_target_runtime_find(target);
	snapshot = (struct ebpf_target_snapshot *)atomic_ptr_get(&runtime->current_snapshot);

	return snapshot != NULL && snapshot->attachment_count > 0U;
}

void ebpf_attach_target_lock(const struct ebpf_attach_target *target)
{
	struct ebpf_target_runtime *runtime = ebpf_target_runtime_find(target);

	__ASSERT(runtime != NULL, "invalid eBPF target lock request");
	k_mutex_lock(&runtime->lock, K_FOREVER);
}

void ebpf_attach_target_unlock(const struct ebpf_attach_target *target)
{
	struct ebpf_target_runtime *runtime = ebpf_target_runtime_find(target);

	__ASSERT(runtime != NULL, "invalid eBPF target unlock request");
	k_mutex_unlock(&runtime->lock);
}

int ebpf_attach_target_enable_prog_locked(const struct ebpf_attach_target *target,
					struct ebpf_prog *prog,
					uint32_t session_seq)
{
	struct ebpf_target_runtime *runtime = ebpf_target_runtime_find(target);
	struct ebpf_target_snapshot *next;

	__ASSERT(runtime != NULL, "invalid eBPF target enable request");

	next = ebpf_target_runtime_prepare_next(runtime);
	ebpf_target_snapshot_remove_prog(next, prog);
	if (next->attachment_count >= CONFIG_EBPF_MAX_ATTACHMENTS_PER_TARGET) {
		return -ENOSPC;
	}

	next->attachments[next->attachment_count].prog = prog;
	next->attachments[next->attachment_count].session_seq = session_seq;
	next->attachment_count++;
	(void)ebpf_target_snapshot_publish(runtime, next);

	return 0;
}

void ebpf_attach_target_disable_prog_locked(const struct ebpf_attach_target *target,
					 const struct ebpf_prog *prog)
{
	struct ebpf_target_runtime *runtime = ebpf_target_runtime_find(target);
	struct ebpf_target_snapshot *next;

	__ASSERT(runtime != NULL, "invalid eBPF target disable request");

	next = ebpf_target_runtime_prepare_next(runtime);
	ebpf_target_snapshot_remove_prog(next, prog);
	(void)ebpf_target_snapshot_publish(runtime, next);
}

void ebpf_attach_target_disable_prog_sync_locked(const struct ebpf_attach_target *target,
					      const struct ebpf_prog *prog)
{
	struct ebpf_target_runtime *runtime = ebpf_target_runtime_find(target);
	struct ebpf_target_snapshot *next;
	struct ebpf_target_snapshot *retired;

	__ASSERT(runtime != NULL, "invalid eBPF target sync-disable request");

	next = ebpf_target_runtime_prepare_next(runtime);
	ebpf_target_snapshot_remove_prog(next, prog);
	retired = ebpf_target_snapshot_publish(runtime, next);
	ebpf_target_snapshot_wait_readers(retired);
}

void ebpf_attach_target_dispatch(const struct ebpf_attach_target *target,
				 void *ctx, uint32_t ctx_size)
{
	struct ebpf_target_runtime *runtime;
	struct ebpf_target_snapshot *snapshot;

	if (!ebpf_attach_target_is_valid(target)) {
		return;
	}

	runtime = ebpf_target_runtime_find(target);
	snapshot = ebpf_target_snapshot_acquire(runtime);

	for (uint16_t i = 0; i < snapshot->attachment_count; i++) {
		struct ebpf_prog *prog = snapshot->attachments[i].prog;

		int64_t ret = ebpf_prog_exec_target(prog, target, ctx, ctx_size);

		ARG_UNUSED(ret);
	}

	ebpf_target_snapshot_release(snapshot);
}
