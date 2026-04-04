/*
 * SPDX-FileCopyrightText: Copyright 2026 NXP
 *
 * SPDX-License-Identifier: Apache-2.0
 */

/**
 * @file
 * @brief Internal eBPF instruction definitions and construction helpers.
 *
 * @note Visibility: eBPF subsystem internals only; not exposed to applications.
 */

#ifndef ZEPHYR_SUBSYS_EBPF_INSN_EBPF_INSN_H_
#define ZEPHYR_SUBSYS_EBPF_INSN_EBPF_INSN_H_

#include <stdint.h>

#include "basic.h"

#ifdef __cplusplus
extern "C" {
#endif

struct ebpf_insn {
	uint8_t opcode;
	uint8_t regs;
	int16_t offset;
	int32_t imm;
};

#define EBPF_REG_R0		0
#define EBPF_REG_R1		1
#define EBPF_REG_R2		2
#define EBPF_REG_R3		3
#define EBPF_REG_R4		4
#define EBPF_REG_R5		5
#define EBPF_REG_R6		6
#define EBPF_REG_R7		7
#define EBPF_REG_R8		8
#define EBPF_REG_R9		9
#define EBPF_REG_R10		10

#define EBPF_NUM_REGS		11

#define EBPF_INSN_OP(_op, _dst, _src, _off, _imm)			\
	((struct ebpf_insn){						\
		.opcode = (_op),					\
		.regs   = ((_dst) & 0xF) | (((_src) & 0xF) << 4),	\
		.offset = (_off),					\
		.imm    = (_imm),					\
	})

#define EBPF_MOV64_REG(dst, src)	EBPF_INSN_OP(EBPF_OP_MOV64_REG, dst, src, 0, 0)
#define EBPF_MOV64_IMM(dst, imm)	EBPF_INSN_OP(EBPF_OP_MOV64_IMM, dst, 0, 0, imm)
#define EBPF_ADD64_REG(dst, src)	EBPF_INSN_OP(EBPF_OP_ADD64_REG, dst, src, 0, 0)
#define EBPF_ADD64_IMM(dst, imm)	EBPF_INSN_OP(EBPF_OP_ADD64_IMM, dst, 0, 0, imm)
#define EBPF_SUB64_REG(dst, src)	EBPF_INSN_OP(EBPF_OP_SUB64_REG, dst, src, 0, 0)
#define EBPF_SUB64_IMM(dst, imm)	EBPF_INSN_OP(EBPF_OP_SUB64_IMM, dst, 0, 0, imm)
#define EBPF_MUL64_REG(dst, src)	EBPF_INSN_OP(EBPF_OP_MUL64_REG, dst, src, 0, 0)
#define EBPF_MUL64_IMM(dst, imm)	EBPF_INSN_OP(EBPF_OP_MUL64_IMM, dst, 0, 0, imm)
#define EBPF_DIV64_REG(dst, src)	EBPF_INSN_OP(EBPF_OP_DIV64_REG, dst, src, 0, 0)
#define EBPF_DIV64_IMM(dst, imm)	EBPF_INSN_OP(EBPF_OP_DIV64_IMM, dst, 0, 0, imm)
#define EBPF_AND64_IMM(dst, imm)	EBPF_INSN_OP(EBPF_OP_AND64_IMM, dst, 0, 0, imm)
#define EBPF_OR64_IMM(dst, imm)		EBPF_INSN_OP(EBPF_OP_OR64_IMM, dst, 0, 0, imm)
#define EBPF_XOR64_IMM(dst, imm)	EBPF_INSN_OP(EBPF_OP_XOR64_IMM, dst, 0, 0, imm)
#define EBPF_LSH64_IMM(dst, imm)	EBPF_INSN_OP(EBPF_OP_LSH64_IMM, dst, 0, 0, imm)
#define EBPF_RSH64_IMM(dst, imm)	EBPF_INSN_OP(EBPF_OP_RSH64_IMM, dst, 0, 0, imm)
#define EBPF_NEG64(dst)			EBPF_INSN_OP(EBPF_OP_NEG64, dst, 0, 0, 0)
#define EBPF_CALL_HELPER(helper_id)	EBPF_INSN_OP(EBPF_OP_CALL, 0, 0, 0, helper_id)
#define EBPF_EXIT_INSN()		EBPF_INSN_OP(EBPF_OP_EXIT, 0, 0, 0, 0)

#define EBPF_LDX_MEM_B(dst, src, off)	EBPF_INSN_OP(EBPF_OP_LDX_B, dst, src, off, 0)
#define EBPF_LDX_MEM_H(dst, src, off)	EBPF_INSN_OP(EBPF_OP_LDX_H, dst, src, off, 0)
#define EBPF_LDX_MEM_W(dst, src, off)	EBPF_INSN_OP(EBPF_OP_LDX_W, dst, src, off, 0)
#define EBPF_LDX_MEM_DW(dst, src, off)	EBPF_INSN_OP(EBPF_OP_LDX_DW, dst, src, off, 0)
#define EBPF_STX_MEM_B(dst, src, off)	EBPF_INSN_OP(EBPF_OP_STX_B, dst, src, off, 0)
#define EBPF_STX_MEM_H(dst, src, off)	EBPF_INSN_OP(EBPF_OP_STX_H, dst, src, off, 0)
#define EBPF_STX_MEM_W(dst, src, off)	EBPF_INSN_OP(EBPF_OP_STX_W, dst, src, off, 0)
#define EBPF_STX_MEM_DW(dst, src, off)	EBPF_INSN_OP(EBPF_OP_STX_DW, dst, src, off, 0)
#define EBPF_ST_MEM_W(dst, off, imm)	EBPF_INSN_OP(EBPF_OP_ST_W, dst, 0, off, imm)

#define EBPF_JMP_A(off)			EBPF_INSN_OP(EBPF_OP_JA, 0, 0, off, 0)
#define EBPF_JEQ_IMM(dst, imm, off)	EBPF_INSN_OP(EBPF_OP_JEQ_IMM, dst, 0, off, imm)
#define EBPF_JEQ_REG(dst, src, off)	EBPF_INSN_OP(EBPF_OP_JEQ_REG, dst, src, off, 0)
#define EBPF_JNE_IMM(dst, imm, off)	EBPF_INSN_OP(EBPF_OP_JNE_IMM, dst, 0, off, imm)
#define EBPF_JGT_IMM(dst, imm, off)	EBPF_INSN_OP(EBPF_OP_JGT_IMM, dst, 0, off, imm)
#define EBPF_JGE_IMM(dst, imm, off)	EBPF_INSN_OP(EBPF_OP_JGE_IMM, dst, 0, off, imm)
#define EBPF_JLT_IMM(dst, imm, off)	EBPF_INSN_OP(EBPF_OP_JLT_IMM, dst, 0, off, imm)
#define EBPF_JLE_IMM(dst, imm, off)	EBPF_INSN_OP(EBPF_OP_JLE_IMM, dst, 0, off, imm)

#define EBPF_INSN_DST(insn)	((insn)->regs & 0x0FU)
#define EBPF_INSN_SRC(insn)	(((insn)->regs >> 4) & 0x0FU)

#ifdef __cplusplus
}
#endif

#endif /* ZEPHYR_SUBSYS_EBPF_INSN_EBPF_INSN_H_ */
