/*
 * SPDX-FileCopyrightText: Copyright 2026 NXP
 *
 * SPDX-License-Identifier: Apache-2.0
 */

#include <zephyr/sys/atomic.h>
#include <zephyr/ebpf/ebpf_prog.h>
#include "ebpf_vm.h"

/**
 * Per-target active program counters. Indexed by attach point within
 * each backend. Incremented/decremented from ebpf_attach_target_inc/dec
 * (called by the program lifecycle in ebpf_prog.c).
 */
static atomic_t ebpf_tracing_active[EBPF_TRACING_ATTACH_MAX];
static atomic_t ebpf_pm_active[EBPF_PM_ATTACH_MAX];

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
	if (!ebpf_attach_target_is_valid(target)) {
		return false;
	}

	switch (target->backend) {
	case EBPF_ATTACH_BACKEND_TRACING:
		return atomic_get(&ebpf_tracing_active[target->point]) > 0;
	case EBPF_ATTACH_BACKEND_PM:
		return atomic_get(&ebpf_pm_active[target->point]) > 0;
	default:
		return false;
	}
}

void ebpf_attach_target_inc(const struct ebpf_attach_target *target)
{
	switch (target->backend) {
	case EBPF_ATTACH_BACKEND_TRACING:
		atomic_inc(&ebpf_tracing_active[target->point]);
		break;
	case EBPF_ATTACH_BACKEND_PM:
		atomic_inc(&ebpf_pm_active[target->point]);
		break;
	default:
		break;
	}
}

void ebpf_attach_target_dec(const struct ebpf_attach_target *target)
{
	switch (target->backend) {
	case EBPF_ATTACH_BACKEND_TRACING:
		atomic_dec(&ebpf_tracing_active[target->point]);
		break;
	case EBPF_ATTACH_BACKEND_PM:
		atomic_dec(&ebpf_pm_active[target->point]);
		break;
	default:
		break;
	}
}

void ebpf_attach_target_dispatch(const struct ebpf_attach_target *target,
				 void *ctx, uint32_t ctx_size)
{
	if (!ebpf_attach_target_is_valid(target)) {
		return;
	}

	STRUCT_SECTION_FOREACH(ebpf_prog, prog) {
		uint32_t session_seq;
		k_spinlock_key_t key;

		key = k_spin_lock(&prog->runtime.lock);
		if (prog->runtime.state != EBPF_PROG_STATE_ENABLED ||
		    prog->runtime.target.backend != target->backend ||
		    prog->runtime.target.point != target->point) {
			k_spin_unlock(&prog->runtime.lock, key);
			continue;
		}

		session_seq = prog->runtime.session_seq;
		k_spin_unlock(&prog->runtime.lock, key);

#ifdef CONFIG_EBPF_STATS
		uint32_t start_cycles = k_cycle_get_32();
#endif

		int64_t ret = ebpf_vm_exec(prog, ctx, ctx_size);

		ARG_UNUSED(ret);

#ifdef CONFIG_EBPF_STATS
		uint32_t elapsed = k_cycle_get_32() - start_cycles;

		key = k_spin_lock(&prog->runtime.lock);
		if (prog->runtime.session_seq == session_seq &&
		    prog->runtime.state == EBPF_PROG_STATE_ENABLED &&
		    prog->runtime.target.backend == target->backend &&
		    prog->runtime.target.point == target->point) {
			prog->runtime.stats.run_count++;
			prog->runtime.stats.run_time_ns += k_cyc_to_ns_floor64(elapsed);
		}
		k_spin_unlock(&prog->runtime.lock, key);
#endif
	}
}
