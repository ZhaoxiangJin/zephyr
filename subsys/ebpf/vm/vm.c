/*
 * SPDX-FileCopyrightText: Copyright 2026 NXP
 *
 * SPDX-License-Identifier: Apache-2.0
 */

#include <string.h>

#include <zephyr/logging/log.h>

#include "../attach/target/target.h"
#include "../contract.h"
#include "../helpers/helpers.h"
#include "vm.h"
#include "../map/map.h"

LOG_MODULE_REGISTER(ebpf_vm, CONFIG_EBPF_LOG_LEVEL);

static bool ebpf_vm_region_contains(uintptr_t base, uint32_t region_size,
				    uintptr_t addr, uint32_t size)
{
	uintptr_t offset;

	if (region_size != 0U && (base + (uintptr_t)region_size) < base) {
		return false;
	}

	if (addr < base || size > region_size) {
		return false;
	}

	offset = addr - base;

	return offset <= (uintptr_t)(region_size - size);
}

static void ebpf_vm_clear_map_region(struct ebpf_vm_ctx *vm, uint8_t reg)
{
	vm->map_regions[reg].base = 0U;
	vm->map_regions[reg].size = 0U;
	vm->map_regions[reg].valid = false;
}

static void ebpf_vm_copy_map_region(struct ebpf_vm_ctx *vm, uint8_t dst, uint8_t src)
{
	vm->map_regions[dst] = vm->map_regions[src];
}

static void ebpf_vm_set_map_region(struct ebpf_vm_ctx *vm, uint8_t reg,
				   uintptr_t base, uint32_t size)
{
	vm->map_regions[reg].base = base;
	vm->map_regions[reg].size = size;
	vm->map_regions[reg].valid = true;
}

static void ebpf_vm_update_alu64_map_region(struct ebpf_vm_ctx *vm,
					 const struct ebpf_insn *insn)
{
	uint8_t dst = EBPF_INSN_DST(insn);
	uint8_t src = EBPF_INSN_SRC(insn);

	switch (insn->opcode) {
	case EBPF_OP_MOV64_REG:
		ebpf_vm_copy_map_region(vm, dst, src);
		return;
	case EBPF_OP_ADD64_IMM:
	case EBPF_OP_SUB64_IMM:
		return;
	default:
		ebpf_vm_clear_map_region(vm, dst);
		return;
	}
}

static void ebpf_vm_update_alu32_map_region(struct ebpf_vm_ctx *vm,
					 const struct ebpf_insn *insn)
{
	ebpf_vm_clear_map_region(vm, EBPF_INSN_DST(insn));
}

/**
 * @brief Check that a memory access falls within allowed regions:
 * - the VM stack, or
 * - the context buffer, or
 * - one bounded map value region carried by the base register.
 *
 * The VM does not treat arbitrary register values as implicitly safe
 * pointers. Every runtime dereference must land within one of these
 * explicitly approved memory regions. This whitelist check is the last
 * line of defense when executing bytecode, catching out-of-bounds or
 * forged addresses before the VM dereferences them.
 */
static bool ebpf_vm_mem_check(const struct ebpf_vm_ctx *vm,
			      uint8_t base_reg,
			      uintptr_t addr, uint32_t size,
			      const void *ctx_data, uint32_t ctx_size)
{
	if (base_reg < EBPF_NUM_REGS && vm->map_regions[base_reg].valid) {
		return ebpf_vm_region_contains(vm->map_regions[base_reg].base,
					      vm->map_regions[base_reg].size,
					      addr, size);
	}

	uintptr_t stack_base = (uintptr_t)vm->stack;

	/* Check stack region */
	if (ebpf_vm_region_contains(stack_base, CONFIG_EBPF_STACK_SIZE, addr, size)) {
		return true;
	}

	/* Check context region */
	if (ctx_data != NULL) {
		uintptr_t ctx_base = (uintptr_t)ctx_data;

		if (ebpf_vm_region_contains(ctx_base, ctx_size, addr, size)) {
			return true;
		}
	}

	return false;
}

static bool ebpf_vm_mem_check_store(const struct ebpf_vm_ctx *vm,
				    uint8_t base_reg,
				    uintptr_t addr, uint32_t size,
				    const void *ctx_data, uint32_t ctx_size,
				    const struct ebpf_contract *contract)
{
	if (base_reg < EBPF_NUM_REGS && vm->map_regions[base_reg].valid) {
		return ebpf_vm_region_contains(vm->map_regions[base_reg].base,
					      vm->map_regions[base_reg].size,
					      addr, size);
	}

	uintptr_t stack_base = (uintptr_t)vm->stack;

	if (ebpf_vm_region_contains(stack_base, CONFIG_EBPF_STACK_SIZE, addr, size)) {
		return true;
	}

	if (ctx_data != NULL && contract != NULL && !contract->ctx_read_only) {
		uintptr_t ctx_base = (uintptr_t)ctx_data;

		if (ebpf_vm_region_contains(ctx_base, ctx_size, addr, size)) {
			return true;
		}
	}

	return false;
}

/** @brief Load a scalar value from an address already derived from VM registers. */
static inline int ebpf_vm_load_mem(const struct ebpf_prog_image *prog,
				   struct ebpf_vm_ctx *vm,
				   uint8_t base_reg,
				   uintptr_t addr, uint32_t size,
				   const void *ctx_data, uint32_t ctx_size,
				   uint64_t *value)
{
	if (!ebpf_vm_mem_check(vm, base_reg, addr, size, ctx_data, ctx_size)) {
		LOG_ERR("OOB read in '%s' at PC=%u", prog->name, vm->pc - 1);
		return -EFAULT;
	}

	switch (size) {
	case 1:
		*value = *(uint8_t *)addr;
		return 0;
	case 2:
		*value = *(uint16_t *)addr;
		return 0;
	case 4:
		*value = *(uint32_t *)addr;
		return 0;
	case 8:
		*value = *(uint64_t *)addr;
		return 0;
	default:
		return -EINVAL;
	}
}

/** @brief Store a scalar value to an address already derived from VM registers. */
static inline int ebpf_vm_store_mem(const struct ebpf_prog_image *prog,
				    struct ebpf_vm_ctx *vm,
				    uint8_t base_reg,
				    uintptr_t addr, uint32_t size, uint64_t value,
				    const void *ctx_data, uint32_t ctx_size,
				    const struct ebpf_contract *contract)
{
	if (!ebpf_vm_mem_check_store(vm, base_reg, addr, size,
					     ctx_data, ctx_size, contract)) {
		LOG_ERR("OOB write in '%s' at PC=%u", prog->name, vm->pc - 1);
		return -EFAULT;
	}

	switch (size) {
	case 1:
		*(uint8_t *)addr = (uint8_t)value;
		return 0;
	case 2:
		*(uint16_t *)addr = (uint16_t)value;
		return 0;
	case 4:
		*(uint32_t *)addr = (uint32_t)value;
		return 0;
	case 8:
		*(uint64_t *)addr = value;
		return 0;
	default:
		return -EINVAL;
	}
}

/** @brief Execute one 64-bit ALU instruction. */
static inline int ebpf_vm_exec_alu64(struct ebpf_vm_ctx *vm,
				     const struct ebpf_insn *insn)
{
	uint8_t dst = EBPF_INSN_DST(insn);
	uint8_t src = EBPF_INSN_SRC(insn);
	int ret = 0;

	switch (insn->opcode) {
	case EBPF_OP_ADD64_IMM:
		vm->regs[dst] += (int64_t)insn->imm;
		break;
	case EBPF_OP_ADD64_REG:
		vm->regs[dst] += vm->regs[src];
		break;
	case EBPF_OP_SUB64_IMM:
		vm->regs[dst] -= (int64_t)insn->imm;
		break;
	case EBPF_OP_SUB64_REG:
		vm->regs[dst] -= vm->regs[src];
		break;
	case EBPF_OP_MUL64_IMM:
		vm->regs[dst] *= (int64_t)insn->imm;
		break;
	case EBPF_OP_MUL64_REG:
		vm->regs[dst] *= vm->regs[src];
		break;
	case EBPF_OP_DIV64_IMM:
		if (insn->imm == 0) {
			vm->regs[dst] = 0;
		} else {
			vm->regs[dst] /= (uint64_t)(uint32_t)insn->imm;
		}
		break;
	case EBPF_OP_DIV64_REG:
		if (vm->regs[src] == 0) {
			vm->regs[dst] = 0;
		} else {
			vm->regs[dst] /= vm->regs[src];
		}
		break;
	case EBPF_OP_MOD64_IMM:
		if (insn->imm == 0) {
			vm->regs[dst] = 0;
		} else {
			vm->regs[dst] %= (uint64_t)(uint32_t)insn->imm;
		}
		break;
	case EBPF_OP_MOD64_REG:
		if (vm->regs[src] == 0) {
			vm->regs[dst] = 0;
		} else {
			vm->regs[dst] %= vm->regs[src];
		}
		break;
	case EBPF_OP_OR64_IMM:
		vm->regs[dst] |= (int64_t)insn->imm;
		break;
	case EBPF_OP_OR64_REG:
		vm->regs[dst] |= vm->regs[src];
		break;
	case EBPF_OP_AND64_IMM:
		vm->regs[dst] &= (int64_t)insn->imm;
		break;
	case EBPF_OP_AND64_REG:
		vm->regs[dst] &= vm->regs[src];
		break;
	case EBPF_OP_XOR64_IMM:
		vm->regs[dst] ^= (int64_t)insn->imm;
		break;
	case EBPF_OP_XOR64_REG:
		vm->regs[dst] ^= vm->regs[src];
		break;
	case EBPF_OP_LSH64_IMM:
		vm->regs[dst] <<= (uint32_t)insn->imm;
		break;
	case EBPF_OP_LSH64_REG:
		vm->regs[dst] <<= (uint32_t)vm->regs[src];
		break;
	case EBPF_OP_RSH64_IMM:
		vm->regs[dst] >>= (uint32_t)insn->imm;
		break;
	case EBPF_OP_RSH64_REG:
		vm->regs[dst] >>= (uint32_t)vm->regs[src];
		break;
	case EBPF_OP_NEG64:
		vm->regs[dst] = (uint64_t)(-(int64_t)vm->regs[dst]);
		break;
	case EBPF_OP_MOV64_IMM:
		vm->regs[dst] = (uint64_t)(int64_t)insn->imm;
		break;
	case EBPF_OP_MOV64_REG:
		vm->regs[dst] = vm->regs[src];
		break;
	default:
		ret = -EINVAL;
		break;
	}

	if (ret == 0) {
		ebpf_vm_update_alu64_map_region(vm, insn);
	}

	return ret;
}

/** @brief Execute one 32-bit ALU instruction and zero-extend the result to 64 bits. */
static inline int ebpf_vm_exec_alu32(struct ebpf_vm_ctx *vm,
				     const struct ebpf_insn *insn)
{
	uint8_t dst = EBPF_INSN_DST(insn);
	uint8_t src = EBPF_INSN_SRC(insn);
	int ret = 0;

	switch (insn->opcode) {
	case EBPF_OP_ADD_IMM:
		vm->regs[dst] = (uint32_t)((uint32_t)vm->regs[dst] + (uint32_t)insn->imm);
		break;
	case EBPF_OP_ADD_REG:
		vm->regs[dst] = (uint32_t)((uint32_t)vm->regs[dst] + (uint32_t)vm->regs[src]);
		break;
	case EBPF_OP_SUB_IMM:
		vm->regs[dst] = (uint32_t)((uint32_t)vm->regs[dst] - (uint32_t)insn->imm);
		break;
	case EBPF_OP_SUB_REG:
		vm->regs[dst] = (uint32_t)((uint32_t)vm->regs[dst] - (uint32_t)vm->regs[src]);
		break;
	case EBPF_OP_MUL_IMM:
		vm->regs[dst] = (uint32_t)((uint32_t)vm->regs[dst] * (uint32_t)insn->imm);
		break;
	case EBPF_OP_MUL_REG:
		vm->regs[dst] = (uint32_t)((uint32_t)vm->regs[dst] * (uint32_t)vm->regs[src]);
		break;
	case EBPF_OP_DIV_IMM:
		if (insn->imm == 0) {
			vm->regs[dst] = 0;
		} else {
			vm->regs[dst] = (uint32_t)vm->regs[dst] / (uint32_t)insn->imm;
		}
		break;
	case EBPF_OP_DIV_REG:
		if ((uint32_t)vm->regs[src] == 0) {
			vm->regs[dst] = 0;
		} else {
			vm->regs[dst] = (uint32_t)vm->regs[dst] / (uint32_t)vm->regs[src];
		}
		break;
	case EBPF_OP_MOD_IMM:
		if (insn->imm == 0) {
			vm->regs[dst] = 0;
		} else {
			vm->regs[dst] = (uint32_t)vm->regs[dst] % (uint32_t)insn->imm;
		}
		break;
	case EBPF_OP_MOD_REG:
		if ((uint32_t)vm->regs[src] == 0) {
			vm->regs[dst] = 0;
		} else {
			vm->regs[dst] = (uint32_t)vm->regs[dst] % (uint32_t)vm->regs[src];
		}
		break;
	case EBPF_OP_OR_IMM:
		vm->regs[dst] = (uint32_t)((uint32_t)vm->regs[dst] | (uint32_t)insn->imm);
		break;
	case EBPF_OP_OR_REG:
		vm->regs[dst] = (uint32_t)((uint32_t)vm->regs[dst] | (uint32_t)vm->regs[src]);
		break;
	case EBPF_OP_AND_IMM:
		vm->regs[dst] = (uint32_t)((uint32_t)vm->regs[dst] & (uint32_t)insn->imm);
		break;
	case EBPF_OP_AND_REG:
		vm->regs[dst] = (uint32_t)((uint32_t)vm->regs[dst] & (uint32_t)vm->regs[src]);
		break;
	case EBPF_OP_XOR_IMM:
		vm->regs[dst] = (uint32_t)((uint32_t)vm->regs[dst] ^ (uint32_t)insn->imm);
		break;
	case EBPF_OP_XOR_REG:
		vm->regs[dst] = (uint32_t)((uint32_t)vm->regs[dst] ^ (uint32_t)vm->regs[src]);
		break;
	case EBPF_OP_LSH_IMM:
		vm->regs[dst] = (uint32_t)((uint32_t)vm->regs[dst] << (uint32_t)insn->imm);
		break;
	case EBPF_OP_LSH_REG:
		vm->regs[dst] = (uint32_t)((uint32_t)vm->regs[dst] << (uint32_t)vm->regs[src]);
		break;
	case EBPF_OP_RSH_IMM:
		vm->regs[dst] = (uint32_t)((uint32_t)vm->regs[dst] >> (uint32_t)insn->imm);
		break;
	case EBPF_OP_RSH_REG:
		vm->regs[dst] = (uint32_t)((uint32_t)vm->regs[dst] >> (uint32_t)vm->regs[src]);
		break;
	case EBPF_OP_NEG:
		vm->regs[dst] = (uint32_t)(-(int32_t)vm->regs[dst]);
		break;
	case EBPF_OP_MOV_IMM:
		vm->regs[dst] = (uint32_t)insn->imm;
		break;
	case EBPF_OP_MOV_REG:
		vm->regs[dst] = (uint32_t)vm->regs[src];
		break;
	default:
		ret = -EINVAL;
		break;
	}

	if (ret == 0) {
		ebpf_vm_update_alu32_map_region(vm, insn);
	}

	return ret;
}

/** @brief Execute one memory instruction across LDX, STX, and ST families. */
static inline int ebpf_vm_exec_memory(const struct ebpf_prog_image *prog,
				      struct ebpf_vm_ctx *vm,
				      const struct ebpf_insn *insn,
				      const void *ctx_data, uint32_t ctx_size,
				      const struct ebpf_contract *contract)
{
	uint8_t opcode = insn->opcode;
	uint8_t dst = EBPF_INSN_DST(insn);
	uint8_t src = EBPF_INSN_SRC(insn);
	uint8_t base_reg = (EBPF_INSN_CLASS(opcode) == EBPF_CLS_LDX) ? src : dst;
	uintptr_t addr;
	uint32_t size;
	uint64_t value;

	switch (opcode) {
	case EBPF_OP_LDX_B: case EBPF_OP_STX_B: case EBPF_OP_ST_B:
		size = 1;
		break;
	case EBPF_OP_LDX_H: case EBPF_OP_STX_H: case EBPF_OP_ST_H:
		size = 2;
		break;
	case EBPF_OP_LDX_W: case EBPF_OP_STX_W: case EBPF_OP_ST_W:
		size = 4;
		break;
	case EBPF_OP_LDX_DW: case EBPF_OP_STX_DW: case EBPF_OP_ST_DW:
		size = 8;
		break;
	default:
		return -EINVAL;
	}

	if (EBPF_INSN_CLASS(opcode) == EBPF_CLS_LDX) {
		addr = (uintptr_t)(vm->regs[src] + insn->offset);
		if (ebpf_vm_load_mem(prog, vm, base_reg, addr, size,
					 ctx_data, ctx_size, &value) != 0) {
			return -EFAULT;
		}
		vm->regs[dst] = value;
		ebpf_vm_clear_map_region(vm, dst);
		return 0;
	}

	addr = (uintptr_t)(vm->regs[dst] + insn->offset);
	value = (EBPF_INSN_CLASS(opcode) == EBPF_CLS_ST) ?
		(uint64_t)(int64_t)insn->imm : vm->regs[src];

	return ebpf_vm_store_mem(prog, vm, base_reg, addr, size, value,
				 ctx_data, ctx_size,
				 contract);
}

static inline int ebpf_vm_exec_ld(const struct ebpf_prog_image *prog,
				  struct ebpf_vm_ctx *vm,
				  const struct ebpf_insn *insns,
				  uint32_t insn_cnt,
				  const struct ebpf_insn *insn)
{
	uint8_t dst = EBPF_INSN_DST(insn);
	const struct ebpf_insn *next;
	uint64_t imm;

	if (insn->opcode != EBPF_OP_LD_IMM_DW) {
		return -EINVAL;
	}

	if (vm->pc >= insn_cnt) {
		LOG_ERR("Truncated LDDW in '%s' at PC=%u", prog->name, vm->pc - 1);
		return -EINVAL;
	}

	next = &insns[vm->pc];
	if (next->opcode != 0U || next->regs != 0U || next->offset != 0) {
		LOG_ERR("Malformed LDDW in '%s' at PC=%u", prog->name, vm->pc - 1);
		return -EINVAL;
	}

	imm = (uint64_t)(uint32_t)insn->imm |
		((uint64_t)(uint32_t)next->imm << 32);
	vm->regs[dst] = imm;
	ebpf_vm_clear_map_region(vm, dst);
	vm->pc++;

	return 0;
}

/** @brief Execute one conditional or unconditional jump instruction. */
static inline int ebpf_vm_exec_jump(struct ebpf_vm_ctx *vm,
				    const struct ebpf_insn *insn)
{
	uint8_t dst = EBPF_INSN_DST(insn);
	uint8_t src = EBPF_INSN_SRC(insn);

	switch (insn->opcode) {
	case EBPF_OP_JA:
		vm->pc += insn->offset;
		return 0;
	case EBPF_OP_JEQ_IMM:
		if (vm->regs[dst] == (uint64_t)(int64_t)insn->imm) {
			vm->pc += insn->offset;
		}
		return 0;
	case EBPF_OP_JEQ_REG:
		if (vm->regs[dst] == vm->regs[src]) {
			vm->pc += insn->offset;
		}
		return 0;
	case EBPF_OP_JGT_IMM:
		if (vm->regs[dst] > (uint64_t)(int64_t)insn->imm) {
			vm->pc += insn->offset;
		}
		return 0;
	case EBPF_OP_JGT_REG:
		if (vm->regs[dst] > vm->regs[src]) {
			vm->pc += insn->offset;
		}
		return 0;
	case EBPF_OP_JGE_IMM:
		if (vm->regs[dst] >= (uint64_t)(int64_t)insn->imm) {
			vm->pc += insn->offset;
		}
		return 0;
	case EBPF_OP_JGE_REG:
		if (vm->regs[dst] >= vm->regs[src]) {
			vm->pc += insn->offset;
		}
		return 0;
	case EBPF_OP_JSET_IMM:
		if (vm->regs[dst] & (uint64_t)(int64_t)insn->imm) {
			vm->pc += insn->offset;
		}
		return 0;
	case EBPF_OP_JSET_REG:
		if (vm->regs[dst] & vm->regs[src]) {
			vm->pc += insn->offset;
		}
		return 0;
	case EBPF_OP_JNE_IMM:
		if (vm->regs[dst] != (uint64_t)(int64_t)insn->imm) {
			vm->pc += insn->offset;
		}
		return 0;
	case EBPF_OP_JNE_REG:
		if (vm->regs[dst] != vm->regs[src]) {
			vm->pc += insn->offset;
		}
		return 0;
	case EBPF_OP_JLT_IMM:
		if (vm->regs[dst] < (uint64_t)(int64_t)insn->imm) {
			vm->pc += insn->offset;
		}
		return 0;
	case EBPF_OP_JLT_REG:
		if (vm->regs[dst] < vm->regs[src]) {
			vm->pc += insn->offset;
		}
		return 0;
	case EBPF_OP_JLE_IMM:
		if (vm->regs[dst] <= (uint64_t)(int64_t)insn->imm) {
			vm->pc += insn->offset;
		}
		return 0;
	case EBPF_OP_JLE_REG:
		if (vm->regs[dst] <= vm->regs[src]) {
			vm->pc += insn->offset;
		}
		return 0;
	default:
		return -EINVAL;
	}
}

/** @brief Execute one helper call and place the helper return value in R0. */
static inline int ebpf_vm_exec_call(const struct ebpf_prog_image *prog,
				    struct ebpf_vm_ctx *vm,
				    const struct ebpf_insn *insn,
				    const struct ebpf_attach_target *target)
{
	const struct ebpf_contract *contract;
	struct ebpf_map *lookup_map = NULL;
	ebpf_helper_fn fn = ebpf_get_helper(insn->imm);

	if (fn == NULL) {
		LOG_ERR("Unknown helper %d in '%s'", insn->imm, prog->name);
		return -EINVAL;
	}

	contract = ebpf_contract_resolve(prog->type, target);
	if (contract != NULL && !ebpf_contract_allows_helper(contract, insn->imm)) {
		LOG_ERR("Helper %d is not allowed in '%s' for %s",
			insn->imm, prog->name,
			ebpf_attach_target_name(target));
		return -EPERM;
	}

	if (insn->imm == EBPF_HELPER_MAP_LOOKUP_ELEM) {
		lookup_map = ebpf_map_from_id((uint32_t)vm->regs[EBPF_REG_R1]);
	}

	vm->regs[0] = fn(vm->regs[1], vm->regs[2], vm->regs[3], vm->regs[4], vm->regs[5]);
	ebpf_vm_clear_map_region(vm, EBPF_REG_R0);

	if (insn->imm == EBPF_HELPER_MAP_LOOKUP_ELEM && lookup_map != NULL &&
	    vm->regs[EBPF_REG_R0] != 0U && ebpf_map_get_value_size(lookup_map) != 0U) {
		ebpf_vm_set_map_region(vm, EBPF_REG_R0,
				      (uintptr_t)vm->regs[EBPF_REG_R0],
				      ebpf_map_get_value_size(lookup_map));
	}

	return 0;
}

/** @brief Dispatch one instruction to its handler based on instruction class. */
static inline int ebpf_vm_exec_insn(const struct ebpf_prog_image *prog,
				    struct ebpf_vm_ctx *vm,
				    const struct ebpf_insn *insns,
				    uint32_t insn_cnt,
				    const struct ebpf_insn *insn,
				    const struct ebpf_attach_target *target,
				    const void *ctx_data, uint32_t ctx_size,
				    const struct ebpf_contract *contract)
{
	uint8_t opcode = insn->opcode;
	int ret;

	switch (EBPF_INSN_CLASS(opcode)) {
	case EBPF_CLS_LD:
		ret = ebpf_vm_exec_ld(prog, vm, insns, insn_cnt, insn);
		break;
	case EBPF_CLS_ALU64:
		ret = ebpf_vm_exec_alu64(vm, insn);
		break;
	case EBPF_CLS_ALU:
		ret = ebpf_vm_exec_alu32(vm, insn);
		break;
	case EBPF_CLS_LDX:
	case EBPF_CLS_STX:
	case EBPF_CLS_ST:
		ret = ebpf_vm_exec_memory(prog, vm, insn, ctx_data, ctx_size,
					 contract);
		break;
	case EBPF_CLS_JMP:
		if (opcode == EBPF_OP_CALL) {
			return ebpf_vm_exec_call(prog, vm, insn, target);
		}
		if (opcode == EBPF_OP_EXIT) {
			return 1;
		}
		ret = ebpf_vm_exec_jump(vm, insn);
		break;
	default:
		LOG_ERR("Unknown opcode 0x%02x in '%s' at PC=%u", opcode, prog->name, vm->pc - 1);
		return -EINVAL;
	}

	if (ret == -EINVAL) {
		LOG_ERR("Unknown opcode 0x%02x in '%s' at PC=%u", opcode, prog->name, vm->pc - 1);
	}

	return ret;
}

int64_t ebpf_vm_exec_target(const struct ebpf_prog_image *prog,
			    const struct ebpf_attach_target *target,
			    void *ctx_data, uint32_t ctx_size)
{
	const struct ebpf_contract *contract;
	struct ebpf_vm_ctx vm;
	const struct ebpf_insn *insns = prog->insns;
	uint32_t insn_cnt = prog->insn_cnt;
	uint32_t insn_limit = CONFIG_EBPF_MAX_INSNS_PER_RUN;
	uint32_t insn_executed = 0;

	contract = ebpf_contract_resolve(prog->type, target);

	/* Initialize a fresh VM context for one program invocation.
	 * The VM state is ephemeral:
	 * - registers start at zero,
	 * - R1 receives the event/context pointer, and
	 * - R10 points to the top of the private stack.
	 * - R0 is reserved for return values from helpers and the program exit code.
	 * The caller-provided context buffer is immutable read-only memory from the
	 * eBPF program's perspective. Reads must be bounds-checked against the
	 * context size, and writes to that region are rejected at runtime.
	 * All other memory accesses must be bounds-checked
	 * against the context size. Helper calls may also allow memory access to other
	 * regions such as eBPF maps, but map-derived pointers are restricted to the
	 * specific value object returned by map_lookup_elem.
	 */
	memset(&vm.regs, 0, sizeof(vm.regs));
	memset(&vm.map_regions, 0, sizeof(vm.map_regions));
	vm.regs[EBPF_REG_R1] = (uint64_t)(uintptr_t)ctx_data;
	vm.regs[EBPF_REG_R10] = (uint64_t)(uintptr_t)&vm.stack[CONFIG_EBPF_STACK_SIZE];
	vm.pc = 0;

	/* Main VM execution loop: Instruction Fetch + Execution. */
	while (vm.pc < insn_cnt) {
		int ret;
		uint32_t pc = vm.pc;
		const struct ebpf_insn *insn;

		if (insn_executed >= insn_limit) {
			LOG_WRN("eBPF program '%s' exceeded instruction limit (%u)",
				prog->name, insn_limit);
			return -ECANCELED;
		}

		insn = &insns[pc];

		if (EBPF_INSN_DST(insn) >= EBPF_NUM_REGS ||
		    EBPF_INSN_SRC(insn) >= EBPF_NUM_REGS) {
			LOG_ERR("Invalid register in '%s' at PC=%u",
				prog->name, pc);
			return -EINVAL;
		}

		vm.pc++;
		insn_executed++;

		ret = ebpf_vm_exec_insn(prog, &vm, insns, insn_cnt, insn, target, ctx_data, ctx_size,
				      contract);

		if (ret == 1) {
			return (int64_t)vm.regs[0];
		}

		if (ret != 0) {
			return ret;
		}
	}

	/* Fall through without EXIT */
	return -EINVAL;
}

int64_t ebpf_vm_exec(const struct ebpf_prog_image *prog, void *ctx_data, uint32_t ctx_size)
{
	const struct ebpf_attach_target target = EBPF_ATTACH_TARGET_NONE;

	return ebpf_vm_exec_target(prog, &target, ctx_data, ctx_size);
}
