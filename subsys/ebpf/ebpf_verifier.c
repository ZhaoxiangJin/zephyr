/*
 * SPDX-FileCopyrightText: Copyright 2026 NXP
 *
 * SPDX-License-Identifier: Apache-2.0
 */

#include <zephyr/logging/log.h>

#include <zephyr/ebpf/ebpf_prog.h>
#include <zephyr/ebpf/ebpf_helpers.h>

#include "ebpf_contract.h"

LOG_MODULE_REGISTER(ebpf_verifier, CONFIG_EBPF_LOG_LEVEL);

enum ebpf_reg_kind {
	EBPF_REG_KIND_UNKNOWN = 0,
	EBPF_REG_KIND_SCALAR,
	EBPF_REG_KIND_CTX_PTR,
	EBPF_REG_KIND_STACK_PTR,
	EBPF_REG_KIND_MAP_VALUE_PTR,
};

static void ebpf_verify_reg_kinds_init(enum ebpf_reg_kind reg_kinds[EBPF_NUM_REGS])
{
	for (size_t i = 0; i < EBPF_NUM_REGS; i++) {
		reg_kinds[i] = EBPF_REG_KIND_UNKNOWN;
	}

	reg_kinds[EBPF_REG_R1] = EBPF_REG_KIND_CTX_PTR;
	reg_kinds[EBPF_REG_R10] = EBPF_REG_KIND_STACK_PTR;
}

static enum ebpf_reg_kind ebpf_helper_ret_kind(int32_t helper_id)
{
	switch (helper_id) {
	case EBPF_HELPER_MAP_LOOKUP_ELEM:
		return EBPF_REG_KIND_MAP_VALUE_PTR;
	case EBPF_HELPER_KTIME_GET_NS:
	case EBPF_HELPER_RINGBUF_OUTPUT:
		return EBPF_REG_KIND_SCALAR;
	default:
		return EBPF_REG_KIND_UNKNOWN;
	}
}

static void ebpf_verify_update_alu_reg_kind(const struct ebpf_insn *insn,
					 enum ebpf_reg_kind reg_kinds[EBPF_NUM_REGS])
{
	uint8_t dst = EBPF_INSN_DST(insn);
	uint8_t src = EBPF_INSN_SRC(insn);
	enum ebpf_reg_kind dst_kind = reg_kinds[dst];

	switch (insn->opcode) {
	case EBPF_OP_MOV64_IMM:
	case EBPF_OP_MOV_IMM:
		reg_kinds[dst] = EBPF_REG_KIND_SCALAR;
		return;
	case EBPF_OP_MOV64_REG:
		reg_kinds[dst] = reg_kinds[src];
		return;
	case EBPF_OP_MOV_REG:
		reg_kinds[dst] = EBPF_REG_KIND_SCALAR;
		return;
	case EBPF_OP_ADD64_IMM:
	case EBPF_OP_SUB64_IMM:
		if (dst_kind == EBPF_REG_KIND_CTX_PTR ||
		    dst_kind == EBPF_REG_KIND_STACK_PTR ||
		    dst_kind == EBPF_REG_KIND_MAP_VALUE_PTR) {
			return;
		}
		reg_kinds[dst] = EBPF_REG_KIND_SCALAR;
		return;
	default:
		reg_kinds[dst] = EBPF_REG_KIND_SCALAR;
		return;
	}
}

/** @brief Validate target-aware verifier constraints for one attachment. */
static const struct ebpf_contract *ebpf_verify_target_contract(const struct ebpf_prog *prog)
{
	const struct ebpf_contract *contract;

	/* If the program is not attached to a concrete target,
	 * there are no target-specific constraints to validate.
	 */
	contract = ebpf_contract_resolve(prog->type, &prog->runtime.target);
	if (contract == NULL) {
		LOG_ERR("Verify '%s': no contract for type %u on %s",
			prog->name, prog->type,
			ebpf_attach_target_name(&prog->runtime.target));
	}

	return contract;
}

/** @brief Return true if @p opcode is a supported ALU or ALU64 opcode. */
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

/** @brief Return true if @p opcode is a supported memory-access opcode. */
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
 * @brief Validate one stack- or memory-related operand.
 */
static int ebpf_verify_memory_access(const struct ebpf_prog *prog, uint32_t pc,
				     const struct ebpf_insn *insn,
				     uint8_t dst, uint8_t src,
				     const struct ebpf_contract *contract,
				     enum ebpf_reg_kind reg_kinds[EBPF_NUM_REGS],
				     int32_t *max_stack_offset)
{
	uint8_t cls = EBPF_INSN_CLASS(insn->opcode);
	bool is_load = cls == EBPF_CLS_LDX;
	uint8_t base_reg = is_load ? src : dst;
	bool uses_r10 = base_reg == EBPF_REG_R10;

	if (uses_r10 && insn->offset > 0) {
		LOG_ERR("Verify '%s' PC=%u: positive R10 offset %d invalid",
			prog->name, pc, insn->offset);

		return -EINVAL;
	}

	if (uses_r10 && insn->offset < 0 && (-insn->offset) > *max_stack_offset) {
		*max_stack_offset = -insn->offset;
	}

	if (!is_load && contract != NULL && contract->ctx_read_only &&
	    reg_kinds[base_reg] == EBPF_REG_KIND_CTX_PTR) {
		LOG_ERR("Verify '%s' PC=%u: writes to context are not allowed",
			prog->name, pc);
		return -EINVAL;
	}

	if (is_load) {
		reg_kinds[dst] = EBPF_REG_KIND_SCALAR;
	}

	return 0;
}

/** @brief Return true if @p opcode is a supported conditional or unconditional jump opcode. */
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

/**
 * @brief Validate that a jump target stays within program bounds.
 */
static int ebpf_verify_jump_target(const struct ebpf_prog *prog, uint32_t pc,
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

/**
 * @brief Verify one non-ALU instruction.
 */
static int ebpf_verify_non_alu_opcode(const struct ebpf_prog *prog, uint32_t pc,
				      const struct ebpf_insn *insn,
				      uint8_t dst, uint8_t src,
				      const struct ebpf_contract *contract,
				      enum ebpf_reg_kind reg_kinds[EBPF_NUM_REGS],
				      int32_t *max_stack_offset)
{
	uint8_t opcode = insn->opcode;

	if (ebpf_is_memory_opcode(opcode)) {
		return ebpf_verify_memory_access(prog, pc, insn, dst, src,
					 contract, reg_kinds, max_stack_offset);
	}

	if (ebpf_is_jump_opcode(opcode)) {
		return ebpf_verify_jump_target(prog, pc, insn);
	}

	switch (opcode) {
	case EBPF_OP_CALL:
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

		reg_kinds[EBPF_REG_R0] = ebpf_helper_ret_kind(insn->imm);

		return 0;
	case EBPF_OP_EXIT:
		return 0;
	default:
		LOG_ERR("Verify '%s' PC=%u: unknown opcode 0x%02x", prog->name, pc, opcode);
		return -EINVAL;
	}
}

int ebpf_verify(const struct ebpf_prog *prog)
{
	const struct ebpf_contract *contract;
	enum ebpf_reg_kind reg_kinds[EBPF_NUM_REGS];

	if (prog == NULL || prog->insns == NULL || prog->insn_cnt == 0) {
		return -EINVAL;
	}

	ebpf_verify_reg_kinds_init(reg_kinds);

	/* Check program length within CONFIG_EBPF_MAX_PROG_INSNS */
	if (prog->insn_cnt > CONFIG_EBPF_MAX_PROG_INSNS) {
		LOG_ERR("Verify '%s': too many instructions (%u > %u)",
			prog->name, prog->insn_cnt, CONFIG_EBPF_MAX_PROG_INSNS);
		return -E2BIG;
	}

	/* Check last instruction is EXIT */
	if (prog->insns[prog->insn_cnt - 1].opcode != EBPF_OP_EXIT) {
		LOG_ERR("Verify '%s': last instruction is not EXIT", prog->name);
		return -EINVAL;
	}

	/* Check that the program satisfies target-specific verifier constraints. */
	contract = ebpf_verify_target_contract(prog);
	if (contract == NULL) {
		return -EINVAL;
	}

	int32_t max_stack_offset = 0;

	for (uint32_t i = 0; i < prog->insn_cnt; i++) {
		const struct ebpf_insn *insn = &prog->insns[i];
		uint8_t opcode = insn->opcode;
		uint8_t dst = EBPF_INSN_DST(insn);
		uint8_t src = EBPF_INSN_SRC(insn);

		/* Check register bounds */
		if (dst >= EBPF_NUM_REGS || src >= EBPF_NUM_REGS) {
			LOG_ERR("Verify '%s' PC=%u: invalid register (dst=%u, src=%u)",
				prog->name, i, dst, src);
			return -EINVAL;
		}

		uint8_t cls = EBPF_INSN_CLASS(opcode);

		/* Check R10 is not used as destination for ALU / ALU64 / LDX */
		if (dst == EBPF_REG_R10 && (cls == EBPF_CLS_ALU ||
		    cls == EBPF_CLS_ALU64 || cls == EBPF_CLS_LDX)) {
			LOG_ERR("Verify '%s' PC=%u: R10 used as destination", prog->name, i);
			return -EINVAL;
		}

		/* Skip detailed checks for ALU opcodes, as they are validated
		 * by opcode class and source bits, and their execution semantics
		 * are straightforward (no side effects, no memory access)
		 */
		if (ebpf_is_alu_opcode(opcode)) {
			ebpf_verify_update_alu_reg_kind(insn, reg_kinds);
			continue;
		}

		/* For non-ALU opcodes, perform specific checks based on opcode type */
		if (ebpf_verify_non_alu_opcode(prog, i, insn, dst, src,
					      contract, reg_kinds,
					      &max_stack_offset) != 0) {
			return -EINVAL;
		}
	}

	/* Check Stack depth within CONFIG_EBPF_STACK_SIZE */
	if (max_stack_offset > CONFIG_EBPF_STACK_SIZE) {
		LOG_ERR("Verify '%s': stack usage %d exceeds limit %d",
			prog->name, max_stack_offset, CONFIG_EBPF_STACK_SIZE);
		return -E2BIG;
	}

	LOG_DBG("Verify '%s': OK (%u insns, %d bytes stack)",
		prog->name, prog->insn_cnt, max_stack_offset);

	return 0;
}
