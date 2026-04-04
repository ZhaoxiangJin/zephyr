/*
 * SPDX-FileCopyrightText: Copyright 2026 NXP
 *
 * SPDX-License-Identifier: Apache-2.0
 */

#include <zephyr/logging/log.h>

#include "attach/ebpf_attach_target_internal.h"
#include "ebpf_contract.h"
#include "helpers/ebpf_helpers_internal.h"
#include "map/ebpf_map_internal.h"

LOG_MODULE_REGISTER(ebpf_verifier, CONFIG_EBPF_LOG_LEVEL);

enum ebpf_reg_kind {
	EBPF_REG_KIND_UNKNOWN = 0,
	EBPF_REG_KIND_SCALAR,
	EBPF_REG_KIND_CTX_PTR,
	EBPF_REG_KIND_STACK_PTR,
	EBPF_REG_KIND_MAP_VALUE_PTR,
};

struct ebpf_reg_state {
	enum ebpf_reg_kind kind;
	bool scalar_is_const;
	uint64_t scalar_const;
	uint32_t map_id;
	uint32_t map_value_size;
	int32_t fixed_off;
};

/* Classify the verifier-visible return kind of one helper call. */
static enum ebpf_reg_kind ebpf_helper_ret_kind(int32_t helper_id)
{
	switch (helper_id) {
	case EBPF_HELPER_MAP_LOOKUP_ELEM:
		return EBPF_REG_KIND_MAP_VALUE_PTR;
	case EBPF_HELPER_KTIME_GET_NS:
		return EBPF_REG_KIND_SCALAR;
	default:
		return EBPF_REG_KIND_UNKNOWN;
	}
}

/* Return true when the register kind denotes a tracked pointer base. */
static bool ebpf_verify_is_ptr_kind(enum ebpf_reg_kind kind)
{
	switch (kind) {
	case EBPF_REG_KIND_CTX_PTR:
	case EBPF_REG_KIND_STACK_PTR:
	case EBPF_REG_KIND_MAP_VALUE_PTR:
		return true;
	default:
		return false;
	}
}

/* Reset one register state to the conservative unknown baseline. */
static void ebpf_verify_reg_state_clear(struct ebpf_reg_state *state)
{
	state->kind = EBPF_REG_KIND_UNKNOWN;
	state->scalar_is_const = false;
	state->scalar_const = 0U;
	state->map_id = 0U;
	state->map_value_size = 0U;
	state->fixed_off = 0;
}

/* Reclassify one register as a scalar and optionally preserve a constant value. */
static void ebpf_verify_reg_state_set_scalar(struct ebpf_reg_state *state,
					     bool is_const, uint64_t value)
{
	ebpf_verify_reg_state_clear(state);
	state->kind = EBPF_REG_KIND_SCALAR;
	state->scalar_is_const = is_const;
	if (is_const) {
		state->scalar_const = value;
	}
}

/* Apply constant pointer arithmetic while keeping the tracked fixed offset in range. */
static int ebpf_verify_adjust_ptr_fixed_off(const struct ebpf_prog_image *prog, uint32_t pc,
					    uint8_t reg, struct ebpf_reg_state *state,
					    int32_t delta)
{
	int64_t next_off = (int64_t)state->fixed_off + delta;

	if (next_off < INT32_MIN || next_off > INT32_MAX) {
		LOG_ERR("Verify '%s' PC=%u: pointer arithmetic on R%u overflows fixed offset",
			prog->name, pc, reg);
		return -EINVAL;
	}

	state->fixed_off = (int32_t)next_off;

	return 0;
}

/* Translate one load/store opcode into the number of bytes it accesses. */
static int ebpf_verify_memory_access_size(uint8_t opcode, uint32_t *size)
{
	switch (opcode) {
	case EBPF_OP_LDX_B: case EBPF_OP_STX_B: case EBPF_OP_ST_B:
		*size = 1U;
		return 0;
	case EBPF_OP_LDX_H: case EBPF_OP_STX_H: case EBPF_OP_ST_H:
		*size = 2U;
		return 0;
	case EBPF_OP_LDX_W: case EBPF_OP_STX_W: case EBPF_OP_ST_W:
		*size = 4U;
		return 0;
	case EBPF_OP_LDX_DW: case EBPF_OP_STX_DW: case EBPF_OP_ST_DW:
		*size = 8U;
		return 0;
	default:
		return -EINVAL;
	}
}

/* Resolve the map referenced by helper calling convention register R1. */
static const struct ebpf_map *ebpf_verify_resolve_helper_map(const struct ebpf_prog_image *prog,
				uint32_t pc, const struct ebpf_reg_state reg_states[EBPF_NUM_REGS])
{
	const struct ebpf_reg_state *map_reg = &reg_states[EBPF_REG_R1];
	uint64_t map_id = map_reg->scalar_const;
	struct ebpf_map *map;

	if (map_reg->kind != EBPF_REG_KIND_SCALAR || !map_reg->scalar_is_const) {
		LOG_ERR("Verify '%s' PC=%u: map_lookup requires a known constant map id in R1",
			prog->name, pc);
		return NULL;
	}

	if (map_id == 0U || map_id > UINT32_MAX) {
		LOG_ERR("Verify '%s' PC=%u: invalid map id %llu in R1",
			prog->name, pc, (unsigned long long)map_id);
		return NULL;
	}

	map = ebpf_map_from_id((uint32_t)map_id);
	if (map == NULL) {
		LOG_ERR("Verify '%s' PC=%u: map id %u is not registered",
			prog->name, pc, (uint32_t)map_id);
		return NULL;
	}

	return map;
}

/** Resolve the target-specific verifier contract for one attached program. */
static const struct ebpf_contract *ebpf_verify_target_contract(const struct ebpf_prog_image *prog,
					       const struct ebpf_attach_target *target)
{
	const struct ebpf_contract *contract;

	/* If no contract exists for this program type and target pair,
	 * later verifier steps have no safe policy to enforce.
	 */
	contract = ebpf_contract_resolve(prog->type, target);
	if (contract == NULL) {
		LOG_ERR("Verify '%s': no contract for type %u on %s",
			prog->name, prog->type, ebpf_attach_target_name(target));
	}

	return contract;
}

/** Return true if @p opcode is handled by the verifier's ALU state updater. */
static bool ebpf_is_alu_opcode(uint8_t opcode)
{
	switch (opcode) {
	case EBPF_OP_ADD64_IMM: case EBPF_OP_ADD64_REG:
	case EBPF_OP_SUB64_IMM: case EBPF_OP_SUB64_REG:
	case EBPF_OP_MUL64_IMM: case EBPF_OP_MUL64_REG:
	case EBPF_OP_DIV64_IMM: case EBPF_OP_DIV64_REG:
	case EBPF_OP_MOD64_IMM: case EBPF_OP_MOD64_REG:
	case EBPF_OP_OR64_IMM:  case EBPF_OP_OR64_REG:
	case EBPF_OP_AND64_IMM: case EBPF_OP_AND64_REG:
	case EBPF_OP_XOR64_IMM: case EBPF_OP_XOR64_REG:
	case EBPF_OP_LSH64_IMM: case EBPF_OP_LSH64_REG:
	case EBPF_OP_RSH64_IMM: case EBPF_OP_RSH64_REG:
	case EBPF_OP_NEG64:
	case EBPF_OP_MOV64_IMM: case EBPF_OP_MOV64_REG:
	case EBPF_OP_ADD_IMM: case EBPF_OP_ADD_REG:
	case EBPF_OP_SUB_IMM: case EBPF_OP_SUB_REG:
	case EBPF_OP_MUL_IMM: case EBPF_OP_MUL_REG:
	case EBPF_OP_DIV_IMM: case EBPF_OP_DIV_REG:
	case EBPF_OP_MOD_IMM: case EBPF_OP_MOD_REG:
	case EBPF_OP_OR_IMM:  case EBPF_OP_OR_REG:
	case EBPF_OP_AND_IMM: case EBPF_OP_AND_REG:
	case EBPF_OP_XOR_IMM: case EBPF_OP_XOR_REG:
	case EBPF_OP_LSH_IMM: case EBPF_OP_LSH_REG:
	case EBPF_OP_RSH_IMM: case EBPF_OP_RSH_REG:
	case EBPF_OP_NEG:
	case EBPF_OP_MOV_IMM: case EBPF_OP_MOV_REG:
		return true;
	default:
		return false;
	}
}

/* Propagate verifier register state through one supported ALU or MOV instruction. */
static int ebpf_verify_update_alu_reg_state(const struct ebpf_prog_image *prog,
					    uint32_t pc,
					    const struct ebpf_insn *insn,
					    struct ebpf_reg_state reg_states[EBPF_NUM_REGS])
{
	uint8_t dst = EBPF_INSN_DST(insn);
	uint8_t src = EBPF_INSN_SRC(insn);
	struct ebpf_reg_state *dst_state = &reg_states[dst];
	const struct ebpf_reg_state *src_state = &reg_states[src];

	switch (insn->opcode) {
	case EBPF_OP_MOV64_IMM:
		ebpf_verify_reg_state_set_scalar(dst_state, true, (uint64_t)(int64_t)insn->imm);
		return 0;
	case EBPF_OP_MOV_IMM:
		ebpf_verify_reg_state_set_scalar(dst_state, true, (uint32_t)insn->imm);
		return 0;
	case EBPF_OP_MOV64_REG:
		*dst_state = *src_state;
		return 0;
	case EBPF_OP_MOV_REG:
		if (src_state->kind == EBPF_REG_KIND_SCALAR &&
		    src_state->scalar_is_const) {
			ebpf_verify_reg_state_set_scalar(dst_state, true,
							 (uint32_t)src_state->scalar_const);
		} else {
			ebpf_verify_reg_state_set_scalar(dst_state, false, 0U);
		}
		return 0;
	case EBPF_OP_ADD64_IMM:
	case EBPF_OP_SUB64_IMM:
		if (ebpf_verify_is_ptr_kind(dst_state->kind)) {
			int32_t delta = (insn->opcode == EBPF_OP_ADD64_IMM) ?
					insn->imm : -insn->imm;

			return ebpf_verify_adjust_ptr_fixed_off(prog, pc, dst, dst_state, delta);
		}

		if (dst_state->kind == EBPF_REG_KIND_SCALAR &&
		    dst_state->scalar_is_const) {
			if (insn->opcode == EBPF_OP_ADD64_IMM) {
				dst_state->scalar_const += (uint64_t)(int64_t)insn->imm;
			} else {
				dst_state->scalar_const -= (uint64_t)(int64_t)insn->imm;
			}
			return 0;
		}

		ebpf_verify_reg_state_set_scalar(dst_state, false, 0U);
		return 0;
	default:
		ebpf_verify_reg_state_set_scalar(dst_state, false, 0U);
		return 0;
	}
}

/* Validate one LDDW pair and materialize its 64-bit immediate into register state. */
static int ebpf_verify_ld_imm64(const struct ebpf_prog_image *prog, uint32_t pc,
				const struct ebpf_insn *insn,
				struct ebpf_reg_state reg_states[EBPF_NUM_REGS])
{
	const struct ebpf_insn *next;
	uint8_t dst = EBPF_INSN_DST(insn);
	uint64_t imm;

	if (insn->opcode != EBPF_OP_LD_IMM_DW) {
		LOG_ERR("Verify '%s' PC=%u: unknown LD opcode 0x%02x",
			prog->name, pc, insn->opcode);
		return -EINVAL;
	}

	if ((pc + 1U) >= prog->insn_cnt) {
		LOG_ERR("Verify '%s' PC=%u: truncated LDDW", prog->name, pc);
		return -EINVAL;
	}

	next = &prog->insns[pc + 1U];
	if (next->opcode != 0U || next->regs != 0U || next->offset != 0) {
		LOG_ERR("Verify '%s' PC=%u: malformed LDDW continuation", prog->name, pc);
		return -EINVAL;
	}

	imm = (uint64_t)(uint32_t)insn->imm |
		((uint64_t)(uint32_t)next->imm << 32);
	ebpf_verify_reg_state_set_scalar(&reg_states[dst], true, imm);

	return 0;
}

/** Return true if @p opcode is one of the load/store forms with explicit width. */
static bool ebpf_is_memory_opcode(uint8_t opcode)
{
	switch (opcode) {
	case EBPF_OP_LDX_B: case EBPF_OP_LDX_H:
	case EBPF_OP_LDX_W: case EBPF_OP_LDX_DW:
	case EBPF_OP_STX_B: case EBPF_OP_STX_H:
	case EBPF_OP_STX_W: case EBPF_OP_STX_DW:
	case EBPF_OP_ST_B:  case EBPF_OP_ST_H:
	case EBPF_OP_ST_W:  case EBPF_OP_ST_DW:
		return true;
	default:
		return false;
	}
}

/**
 * Validate one load/store operand against the tracked pointer base and bounds.
 *
 * This enforces stack bounds, map value bounds, and context write rules, then
 * degrades the destination register to an unknown scalar after a successful load.
 */
static int ebpf_verify_memory_access(const struct ebpf_prog_image *prog, uint32_t pc,
				     const struct ebpf_insn *insn,
				     uint8_t dst, uint8_t src,
				     const struct ebpf_contract *contract,
				     struct ebpf_reg_state reg_states[EBPF_NUM_REGS],
				     int32_t *max_stack_offset)
{
	uint8_t cls = EBPF_INSN_CLASS(insn->opcode);
	bool is_load = cls == EBPF_CLS_LDX;
	uint8_t base_reg = is_load ? src : dst;
	const struct ebpf_reg_state *base_state = &reg_states[base_reg];
	uint32_t access_size;
	int64_t access_off;
	int64_t access_end;

	if (ebpf_verify_memory_access_size(insn->opcode, &access_size) != 0) {
		LOG_ERR("Verify '%s' PC=%u: unknown memory width for opcode 0x%02x",
			prog->name, pc, insn->opcode);
		return -EINVAL;
	}

	if (!ebpf_verify_is_ptr_kind(base_state->kind)) {
		LOG_ERR("Verify '%s' PC=%u: memory base R%u is not a tracked pointer",
			prog->name, pc, base_reg);
		return -EINVAL;
	}

	access_off = (int64_t)base_state->fixed_off + insn->offset;
	access_end = access_off + access_size;

	if (base_state->kind == EBPF_REG_KIND_STACK_PTR) {
		if (access_off < -CONFIG_EBPF_STACK_SIZE || access_end > 0) {
			LOG_ERR("Verify '%s' PC=%u: stack access [%lld, %lld) OOB",
				prog->name, pc, (long long)access_off, (long long)access_end);
			return -EINVAL;
		}

		if (-access_off > *max_stack_offset) {
			*max_stack_offset = (int32_t)(-access_off);
		}
	}

	if (base_state->kind == EBPF_REG_KIND_MAP_VALUE_PTR) {
		if (access_off < 0 || access_end > base_state->map_value_size) {
			LOG_ERR("Verify '%s' PC=%u: map value access [%lld, %lld)"
				" exceeds value size %u for map id %u",
				prog->name, pc, (long long)access_off, (long long)access_end,
				base_state->map_value_size, base_state->map_id);
			return -EINVAL;
		}
	}

	if (!is_load && contract != NULL && contract->ctx_read_only &&
	    base_state->kind == EBPF_REG_KIND_CTX_PTR) {
		LOG_ERR("Verify '%s' PC=%u: writes to context are not allowed",
			prog->name, pc);

		return -EINVAL;
	}

	if (is_load) {
		ebpf_verify_reg_state_set_scalar(&reg_states[dst], false, 0U);
	}

	return 0;
}

/** Return true if @p opcode is one of the jump forms with a relative branch target. */
static bool ebpf_is_jump_opcode(uint8_t opcode)
{
	switch (opcode) {
	case EBPF_OP_JA:
	case EBPF_OP_JEQ_IMM: case EBPF_OP_JEQ_REG:
	case EBPF_OP_JGT_IMM: case EBPF_OP_JGT_REG:
	case EBPF_OP_JGE_IMM: case EBPF_OP_JGE_REG:
	case EBPF_OP_JSET_IMM: case EBPF_OP_JSET_REG:
	case EBPF_OP_JNE_IMM: case EBPF_OP_JNE_REG:
	case EBPF_OP_JLT_IMM: case EBPF_OP_JLT_REG:
	case EBPF_OP_JLE_IMM: case EBPF_OP_JLE_REG:
		return true;
	default:
		return false;
	}
}

/** Validate that a relative branch target lands on a valid instruction index. */
static int ebpf_verify_jump_target(const struct ebpf_prog_image *prog, uint32_t pc,
				   const struct ebpf_insn *insn)
{
	int32_t target = (int32_t)(pc + 1U) + insn->offset;

	if (target < 0 || (uint32_t)target >= prog->insn_cnt) {
		LOG_ERR("Verify '%s' PC=%u: jump target %d OOB",
			prog->name, pc, target);
		return -EINVAL;
	}

	return 0;
}

/** Dispatch verification for the supported non-ALU instruction families. */
static int ebpf_verify_non_alu_opcode(const struct ebpf_prog_image *prog, uint32_t pc,
				      const struct ebpf_insn *insn,
				      uint8_t dst, uint8_t src,
				      const struct ebpf_contract *contract,
				      struct ebpf_reg_state reg_states[EBPF_NUM_REGS],
				      int32_t *max_stack_offset)
{
	uint8_t opcode = insn->opcode;

	if (ebpf_is_memory_opcode(opcode)) {
		return ebpf_verify_memory_access(prog, pc, insn, dst, src,
						 contract, reg_states, max_stack_offset);
	}

	if (ebpf_is_jump_opcode(opcode)) {
		return ebpf_verify_jump_target(prog, pc, insn);
	}

	switch (opcode) {
	case EBPF_OP_CALL:
	{
		const struct ebpf_map *map = NULL;

		if (ebpf_get_helper(insn->imm) == NULL) {
			LOG_ERR("Verify '%s' PC=%u: unknown helper %d",
				prog->name, pc, insn->imm);
			return -EINVAL;
		}

		if (!ebpf_contract_allows_helper(contract, insn->imm)) {
			LOG_ERR("Verify '%s' PC=%u: helper %d not allowed by contract",
				prog->name, pc, insn->imm);
			return -EINVAL;
		}

		if (insn->imm == EBPF_HELPER_MAP_LOOKUP_ELEM) {
			map = ebpf_verify_resolve_helper_map(prog, pc, reg_states);
			if (map == NULL) {
				return -EINVAL;
			}

			ebpf_verify_reg_state_clear(&reg_states[EBPF_REG_R0]);
			reg_states[EBPF_REG_R0].kind = EBPF_REG_KIND_MAP_VALUE_PTR;
			reg_states[EBPF_REG_R0].map_id = ebpf_map_get_id(map);
			reg_states[EBPF_REG_R0].map_value_size = ebpf_map_get_value_size(map);
			reg_states[EBPF_REG_R0].fixed_off = 0;
		} else if (ebpf_helper_ret_kind(insn->imm) == EBPF_REG_KIND_SCALAR) {
			ebpf_verify_reg_state_set_scalar(&reg_states[EBPF_REG_R0],
							 false, 0U);
		} else {
			ebpf_verify_reg_state_clear(&reg_states[EBPF_REG_R0]);
		}

		return 0;
	}
	case EBPF_OP_EXIT:
		return 0;
	default:
		LOG_ERR("Verify '%s' PC=%u: unknown opcode 0x%02x", prog->name, pc, opcode);
		return -EINVAL;
	}
}

/* Run the target-aware verifier over one fully attached eBPF program image. */
int ebpf_verify_for_target(const struct ebpf_prog_image *prog,
			   const struct ebpf_attach_target *target)
{
	const struct ebpf_contract *contract;
	struct ebpf_reg_state reg_states[EBPF_NUM_REGS];

	if (prog == NULL || prog->insns == NULL || prog->insn_cnt == 0) {
		return -EINVAL;
	}

	/* Seed the abstract machine with the standard BPF calling convention. */
	for (size_t i = 0; i < EBPF_NUM_REGS; i++) {
		ebpf_verify_reg_state_clear(&reg_states[i]);
	}

	reg_states[EBPF_REG_R1].kind = EBPF_REG_KIND_CTX_PTR;
	reg_states[EBPF_REG_R10].kind = EBPF_REG_KIND_STACK_PTR;

	/* Reject programs that exceed the configured instruction budget. */
	if (prog->insn_cnt > CONFIG_EBPF_MAX_PROG_INSNS) {
		LOG_ERR("Verify '%s': too many instructions (%u > %u)",
			prog->name, prog->insn_cnt, CONFIG_EBPF_MAX_PROG_INSNS);
		return -E2BIG;
	}

	/* Require an explicit EXIT so control flow cannot fall off the program end. */
	if (prog->insns[prog->insn_cnt - 1].opcode != EBPF_OP_EXIT) {
		LOG_ERR("Verify '%s': last instruction is not EXIT", prog->name);
		return -EINVAL;
	}

	/* Resolve the contract that constrains helper use and context access. */
	contract = ebpf_verify_target_contract(prog, target);
	if (contract == NULL) {
		return -EINVAL;
	}

	int32_t max_stack_offset = 0;

	for (uint32_t i = 0; i < prog->insn_cnt; i++) {
		const struct ebpf_insn *insn = &prog->insns[i];
		uint8_t opcode = insn->opcode;
		uint8_t dst = EBPF_INSN_DST(insn);
		uint8_t src = EBPF_INSN_SRC(insn);

		/* Reject any instruction that encodes a register number outside the ABI. */
		if (dst >= EBPF_NUM_REGS || src >= EBPF_NUM_REGS) {
			LOG_ERR("Verify '%s' PC=%u: invalid register (dst=%u, src=%u)",
				prog->name, i, dst, src);
			return -EINVAL;
		}

		uint8_t cls = EBPF_INSN_CLASS(opcode);

		/* R10 is the read-only frame pointer and must never be overwritten. */
		if (dst == EBPF_REG_R10 && (cls == EBPF_CLS_LD || cls == EBPF_CLS_ALU ||
		    cls == EBPF_CLS_ALU64 || cls == EBPF_CLS_LDX)) {
			LOG_ERR("Verify '%s' PC=%u: R10 used as destination", prog->name, i);
			return -EINVAL;
		}

		if (opcode == EBPF_OP_LD_IMM_DW) {
			if (ebpf_verify_ld_imm64(prog, i, insn, reg_states) != 0) {
				return -EINVAL;
			}
			i++;
			continue;
		}

		/* ALU-class instructions only mutate register state, so they stay on the
		 * fast path handled by ebpf_verify_update_alu_reg_state().
		 */
		if (ebpf_is_alu_opcode(opcode)) {
			if (ebpf_verify_update_alu_reg_state(prog, i, insn, reg_states) != 0) {
				return -EINVAL;
			}
			continue;
		}

		/* All remaining supported opcodes are validated by family-specific helpers. */
		if (ebpf_verify_non_alu_opcode(prog, i, insn, dst, src, contract, reg_states,
					       &max_stack_offset) != 0) {
			return -EINVAL;
		}
	}

	/* Enforce the final stack-depth budget derived from all observed accesses. */
	if (max_stack_offset > CONFIG_EBPF_STACK_SIZE) {
		LOG_ERR("Verify '%s': stack usage %d exceeds limit %d",
			prog->name, max_stack_offset, CONFIG_EBPF_STACK_SIZE);
		return -E2BIG;
	}

	LOG_DBG("Verify '%s': OK (%u insns, %d bytes stack)",
		prog->name, prog->insn_cnt, max_stack_offset);

	return 0;
}
