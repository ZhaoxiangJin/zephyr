/*
 * SPDX-FileCopyrightText: Copyright 2026 NXP
 *
 * SPDX-License-Identifier: Apache-2.0
 */

#include <zephyr/sys/util.h>

#include "ebpf_contract.h"

/* Convert helper IDs into the bit positions stored by ebpf_contract::helper_mask. */
#define EBPF_HELPER_MASK(_id) BIT(_id)

/* Detached programs use this baseline until a concrete target is selected. */
#define EBPF_HELPERS_BASE (EBPF_HELPER_MASK(EBPF_HELPER_MAP_LOOKUP_ELEM) |	\
			   EBPF_HELPER_MASK(EBPF_HELPER_KTIME_GET_NS) |		\
			   EBPF_HELPER_MASK(EBPF_HELPER_RINGBUF_OUTPUT))

/* Thread and generic tracing paths currently allow the full helper set. */
#define EBPF_HELPERS_TRACE EBPF_HELPERS_BASE

/* PM and typed ISR paths keep the lower-latency helper subset. */
#define EBPF_HELPERS_LATENCY_SENSITIVE						\
	(EBPF_HELPER_MASK(EBPF_HELPER_MAP_LOOKUP_ELEM) |			\
	 EBPF_HELPER_MASK(EBPF_HELPER_KTIME_GET_NS))

#define EBPF_TARGET_NONE_ENTRY(_type)						\
	{									\
		.prog_type = (_type),						\
		.target = EBPF_ATTACH_TARGET_NONE,				\
		.helper_mask = EBPF_HELPERS_BASE,				\
		.ctx_read_only = true,						\
	}

/* Describe one runtime-enforced policy entry for a concrete attachment. */
#define EBPF_CONTRACT_ENTRY(_type, _target, _mask, _ctx_ro)			\
	{									\
		.prog_type = (_type),						\
		.target = (_target),						\
		.helper_mask = (_mask),						\
		.ctx_read_only = (_ctx_ro),					\
	}

/*
 * Shared contract table.
 *
 * The key is (program type, backend, target point). The table currently owns
 * only the policy enforced in common code: helper allowlists and whether R1's
 * event context is writable. The concrete context layout remains a documented
 * backend-specific target layout rather than a field consumed by verifier/VM
 * logic.
 */
static const struct ebpf_contract ebpf_contracts[] = {
	EBPF_TARGET_NONE_ENTRY(EBPF_PROG_TYPE_GENERIC),
	EBPF_TARGET_NONE_ENTRY(EBPF_PROG_TYPE_SCHED),
	EBPF_TARGET_NONE_ENTRY(EBPF_PROG_TYPE_ISR),
	EBPF_TARGET_NONE_ENTRY(EBPF_PROG_TYPE_PM),

	EBPF_CONTRACT_ENTRY(EBPF_PROG_TYPE_GENERIC,
		EBPF_ATTACH_TARGET_TRACING(EBPF_TRACING_ATTACH_THREAD_SWITCHED_IN),
		EBPF_HELPERS_TRACE, true),
	EBPF_CONTRACT_ENTRY(EBPF_PROG_TYPE_GENERIC,
		EBPF_ATTACH_TARGET_TRACING(EBPF_TRACING_ATTACH_THREAD_SWITCHED_OUT),
		EBPF_HELPERS_TRACE, true),

	EBPF_CONTRACT_ENTRY(EBPF_PROG_TYPE_GENERIC,
		EBPF_ATTACH_TARGET_TRACING(EBPF_TRACING_ATTACH_ISR_ENTER),
		EBPF_HELPERS_TRACE, true),
	EBPF_CONTRACT_ENTRY(EBPF_PROG_TYPE_GENERIC,
		EBPF_ATTACH_TARGET_TRACING(EBPF_TRACING_ATTACH_ISR_EXIT),
		EBPF_HELPERS_TRACE, true),

	EBPF_CONTRACT_ENTRY(EBPF_PROG_TYPE_GENERIC,
		EBPF_ATTACH_TARGET_TRACING(EBPF_TRACING_ATTACH_IDLE_ENTER),
		EBPF_HELPERS_TRACE, true),
	EBPF_CONTRACT_ENTRY(EBPF_PROG_TYPE_GENERIC,
		EBPF_ATTACH_TARGET_TRACING(EBPF_TRACING_ATTACH_IDLE_EXIT),
		EBPF_HELPERS_TRACE, true),

	EBPF_CONTRACT_ENTRY(EBPF_PROG_TYPE_SCHED,
		EBPF_ATTACH_TARGET_TRACING(EBPF_TRACING_ATTACH_THREAD_SWITCHED_IN),
		EBPF_HELPERS_TRACE, true),
	EBPF_CONTRACT_ENTRY(EBPF_PROG_TYPE_SCHED,
		EBPF_ATTACH_TARGET_TRACING(EBPF_TRACING_ATTACH_THREAD_SWITCHED_OUT),
		EBPF_HELPERS_TRACE, true),

	EBPF_CONTRACT_ENTRY(EBPF_PROG_TYPE_ISR,
		EBPF_ATTACH_TARGET_TRACING(EBPF_TRACING_ATTACH_ISR_ENTER),
		EBPF_HELPERS_LATENCY_SENSITIVE, true),
	EBPF_CONTRACT_ENTRY(EBPF_PROG_TYPE_ISR,
		EBPF_ATTACH_TARGET_TRACING(EBPF_TRACING_ATTACH_ISR_EXIT),
		EBPF_HELPERS_LATENCY_SENSITIVE, true),

	EBPF_CONTRACT_ENTRY(EBPF_PROG_TYPE_GENERIC,
		EBPF_ATTACH_TARGET_PM(EBPF_PM_ATTACH_STATE_ENTRY),
		EBPF_HELPERS_LATENCY_SENSITIVE, true),
	EBPF_CONTRACT_ENTRY(EBPF_PROG_TYPE_GENERIC,
		EBPF_ATTACH_TARGET_PM(EBPF_PM_ATTACH_STATE_EXIT),
		EBPF_HELPERS_LATENCY_SENSITIVE, true),
	EBPF_CONTRACT_ENTRY(EBPF_PROG_TYPE_PM,
		EBPF_ATTACH_TARGET_PM(EBPF_PM_ATTACH_STATE_ENTRY),
		EBPF_HELPERS_LATENCY_SENSITIVE, true),
	EBPF_CONTRACT_ENTRY(EBPF_PROG_TYPE_PM,
		EBPF_ATTACH_TARGET_PM(EBPF_PM_ATTACH_STATE_EXIT),
		EBPF_HELPERS_LATENCY_SENSITIVE, true),
};

/* Resolve the runtime policy that matches the current attachment. */
const struct ebpf_contract *ebpf_contract_resolve(enum ebpf_prog_type prog_type,
						  const struct ebpf_attach_target *target)
{
	struct ebpf_attach_target lookup_target = EBPF_ATTACH_TARGET_NONE;

	if (target != NULL) {
		lookup_target = *target;
	}

	for (size_t i = 0; i < ARRAY_SIZE(ebpf_contracts); i++) {
		const struct ebpf_contract *contract = &ebpf_contracts[i];

		if (contract->prog_type != prog_type) {
			continue;
		}

		if (contract->target.backend != lookup_target.backend ||
		    contract->target.point != lookup_target.point) {
			continue;
		}

		return contract;
	}

	return NULL;
}

/* Helper calls outside the allowlist are rejected by shared policy. */
bool ebpf_contract_allows_helper(const struct ebpf_contract *contract,
					 uint32_t helper_id)
{
	if (contract == NULL || helper_id >= EBPF_HELPER_MAX) {
		return false;
	}

	return (contract->helper_mask & EBPF_HELPER_MASK(helper_id)) != 0U;
}
