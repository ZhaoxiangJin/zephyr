/*
 * SPDX-FileCopyrightText: Copyright 2026 NXP
 *
 * SPDX-License-Identifier: Apache-2.0
 */

/**
 * @file
 * @brief Internal eBPF contract resolution interfaces.
 */

#ifndef ZEPHYR_SUBSYS_EBPF_CONTRACT_H_
#define ZEPHYR_SUBSYS_EBPF_CONTRACT_H_

#include <zephyr/sys/util.h>

#include <zephyr/ebpf/ebpf_helpers.h>
#include <zephyr/ebpf/ebpf_prog.h>

#ifdef __cplusplus
extern "C" {
#endif

/**
 * @brief Internal attachment contract enforced by verifier and VM.
 *
 * The contract is intentionally narrow: it contains only the policy that is
 * currently enforced in shared runtime code. The concrete event-context
 * layout is still defined by the resolved attach target and documented in the
 * eBPF subsystem docs.
 */
struct ebpf_contract {
	/** Program family participating in this contract entry. */
	enum ebpf_prog_type prog_type;

	/** Concrete backend target this entry applies to. */
	struct ebpf_attach_target target;

	/** Bitmask of helper IDs that are legal for this attachment. */
	uint32_t helper_mask;

	/** Whether bytecode must treat the event context as read-only input. */
	bool ctx_read_only;
};

/**
 * @brief Resolve the internal contract for a program type and target.
 *
 * @param prog_type Program family being attached.
 * @param target Concrete attach target, or NULL for the detached baseline.
 *
 * @retval non-NULL Matching contract entry.
 * @retval NULL No contract is defined for this combination.
 */
const struct ebpf_contract *ebpf_contract_resolve(enum ebpf_prog_type prog_type,
						  const struct ebpf_attach_target *target);

/**
 * @brief Check whether a helper is allowed by the resolved contract.
 *
 * @param contract Resolved contract entry.
 * @param helper_id Helper ID encoded in a BPF CALL instruction.
 *
 * @retval true The helper is allowed for this attachment.
 * @retval false The helper is not allowed or the input is invalid.
 */
bool ebpf_contract_allows_helper(const struct ebpf_contract *contract,
				 uint32_t helper_id);

#ifdef __cplusplus
}
#endif

#endif /* ZEPHYR_SUBSYS_EBPF_CONTRACT_H_ */
