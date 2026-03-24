/*
 * SPDX-FileCopyrightText: Copyright 2026 NXP
 *
 * SPDX-License-Identifier: Apache-2.0
 */

#include <zephyr/ztest.h>
#include <zephyr/kernel.h>

#include <zephyr/ebpf/ebpf_attach_target.h>
#include <zephyr/ebpf/ebpf_helpers.h>
#include <zephyr/ebpf/ebpf_insn.h>
#include <zephyr/ebpf/ebpf_prog.h>

extern int64_t ebpf_vm_exec(const struct ebpf_prog *prog, void *ctx_data,
			    uint32_t ctx_size);

static struct ebpf_prog make_test_prog(const char *name,
				       const struct ebpf_insn *insns,
				       uint32_t insn_cnt)
{
	struct ebpf_prog prog;

	ebpf_prog_init(&prog, name, EBPF_PROG_TYPE_GENERIC, insns, insn_cnt);

	return prog;
}

/* Test: MOV + ADD + EXIT return value */
ZTEST(ebpf_vm, test_mov_add_exit)
{
	static const struct ebpf_insn prog_insns[] = {
		EBPF_MOV64_IMM(EBPF_REG_R0, 10),
		EBPF_ADD64_IMM(EBPF_REG_R0, 32),
		EBPF_EXIT_INSN(),
	};

	struct ebpf_prog test_prog = make_test_prog("test_prog", prog_insns,
						    ARRAY_SIZE(prog_insns));

	int64_t ret = ebpf_vm_exec(&test_prog, NULL, 0);

	zassert_equal(ret, 42, "Expected 42, got %lld", ret);
}

/* Test: SUB instruction */
ZTEST(ebpf_vm, test_sub)
{
	static const struct ebpf_insn prog_insns[] = {
		EBPF_MOV64_IMM(EBPF_REG_R0, 100),
		EBPF_SUB64_IMM(EBPF_REG_R0, 58),
		EBPF_EXIT_INSN(),
	};

	struct ebpf_prog test_sub = make_test_prog("test_sub", prog_insns,
						   ARRAY_SIZE(prog_insns));

	int64_t ret = ebpf_vm_exec(&test_sub, NULL, 0);

	zassert_equal(ret, 42, "Expected 42, got %lld", ret);
}

/* Test: MOV register to register */
ZTEST(ebpf_vm, test_mov_reg)
{
	static const struct ebpf_insn prog_insns[] = {
		EBPF_MOV64_IMM(EBPF_REG_R1, 99),
		EBPF_MOV64_REG(EBPF_REG_R0, EBPF_REG_R1),
		EBPF_EXIT_INSN(),
	};

	struct ebpf_prog test_movreg = make_test_prog("test_movreg", prog_insns,
						      ARRAY_SIZE(prog_insns));

	int64_t ret = ebpf_vm_exec(&test_movreg, NULL, 0);

	zassert_equal(ret, 99, "Expected 99, got %lld", ret);
}

/* Test: MUL instruction */
ZTEST(ebpf_vm, test_mul)
{
	static const struct ebpf_insn prog_insns[] = {
		EBPF_MOV64_IMM(EBPF_REG_R0, 6),
		EBPF_MUL64_IMM(EBPF_REG_R0, 7),
		EBPF_EXIT_INSN(),
	};

	struct ebpf_prog test_mul = make_test_prog("test_mul", prog_insns,
						   ARRAY_SIZE(prog_insns));

	int64_t ret = ebpf_vm_exec(&test_mul, NULL, 0);

	zassert_equal(ret, 42, "Expected 42, got %lld", ret);
}

/* Test: Division by zero returns 0 */
ZTEST(ebpf_vm, test_div_by_zero)
{
	static const struct ebpf_insn prog_insns[] = {
		EBPF_MOV64_IMM(EBPF_REG_R0, 100),
		EBPF_DIV64_IMM(EBPF_REG_R0, 0),
		EBPF_EXIT_INSN(),
	};

	struct ebpf_prog test_div0 = make_test_prog("test_div0", prog_insns,
						    ARRAY_SIZE(prog_insns));

	int64_t ret = ebpf_vm_exec(&test_div0, NULL, 0);

	zassert_equal(ret, 0, "Div by zero should return 0, got %lld", ret);
}

/* Test: AND / OR / XOR */
ZTEST(ebpf_vm, test_bitwise)
{
	static const struct ebpf_insn prog_insns[] = {
		EBPF_MOV64_IMM(EBPF_REG_R0, 0xFF),
		EBPF_AND64_IMM(EBPF_REG_R0, 0x0F),
		/* R0 should be 0x0F = 15 */
		EBPF_OR64_IMM(EBPF_REG_R0, 0x30),
		/* R0 should be 0x3F = 63 */
		EBPF_XOR64_IMM(EBPF_REG_R0, 0x15),
		/* R0 should be 0x2A = 42 */
		EBPF_EXIT_INSN(),
	};

	struct ebpf_prog test_bits = make_test_prog("test_bits", prog_insns,
						    ARRAY_SIZE(prog_insns));

	int64_t ret = ebpf_vm_exec(&test_bits, NULL, 0);

	zassert_equal(ret, 42, "Expected 42, got %lld", ret);
}

/* Test: Conditional jump (JEQ) */
ZTEST(ebpf_vm, test_jeq)
{
	static const struct ebpf_insn prog_insns[] = {
		EBPF_MOV64_IMM(EBPF_REG_R0, 0),
		EBPF_MOV64_IMM(EBPF_REG_R1, 5),
		/* if R1 == 5, skip next insn */
		EBPF_JEQ_IMM(EBPF_REG_R1, 5, 1),
		EBPF_MOV64_IMM(EBPF_REG_R0, 99),  /* should be skipped */
		EBPF_MOV64_IMM(EBPF_REG_R0, 42),  /* should execute */
		EBPF_EXIT_INSN(),
	};

	struct ebpf_prog test_jeq = make_test_prog("test_jeq", prog_insns,
						   ARRAY_SIZE(prog_insns));

	int64_t ret = ebpf_vm_exec(&test_jeq, NULL, 0);

	zassert_equal(ret, 42, "Expected 42, got %lld", ret);
}

/* Test: JNE (not equal) */
ZTEST(ebpf_vm, test_jne)
{
	static const struct ebpf_insn prog_insns[] = {
		EBPF_MOV64_IMM(EBPF_REG_R0, 0),
		EBPF_MOV64_IMM(EBPF_REG_R1, 5),
		/* if R1 != 10, skip next insn */
		EBPF_JNE_IMM(EBPF_REG_R1, 10, 1),
		EBPF_MOV64_IMM(EBPF_REG_R0, 99),  /* should be skipped */
		EBPF_MOV64_IMM(EBPF_REG_R0, 1),
		EBPF_EXIT_INSN(),
	};

	struct ebpf_prog test_jne = make_test_prog("test_jne", prog_insns,
						   ARRAY_SIZE(prog_insns));

	int64_t ret = ebpf_vm_exec(&test_jne, NULL, 0);

	zassert_equal(ret, 1, "Expected 1, got %lld", ret);
}

/* Test: Memory store/load via stack (R10) */
ZTEST(ebpf_vm, test_stack_memory)
{
	static const struct ebpf_insn prog_insns[] = {
		/* Store 42 to stack at [R10-4] */
		EBPF_ST_MEM_W(EBPF_REG_R10, -4, 42),
		/* Load from stack [R10-4] into R0 */
		EBPF_LDX_MEM_W(EBPF_REG_R0, EBPF_REG_R10, -4),
		EBPF_EXIT_INSN(),
	};

	struct ebpf_prog test_stack = make_test_prog("test_stack", prog_insns,
						     ARRAY_SIZE(prog_insns));

	int64_t ret = ebpf_vm_exec(&test_stack, NULL, 0);

	zassert_equal(ret, 42, "Expected 42, got %lld", ret);
}

/* Test: Context read (R1 points to context data) */
ZTEST(ebpf_vm, test_context_read)
{
	struct test_ctx {
		uint32_t value;
	} ctx = { .value = 123 };

	static const struct ebpf_insn prog_insns[] = {
		/* R1 = ctx pointer, read ctx->value (offset 0) */
		EBPF_LDX_MEM_W(EBPF_REG_R0, EBPF_REG_R1, 0),
		EBPF_EXIT_INSN(),
	};

	struct ebpf_prog test_ctx_prog = make_test_prog("test_ctx", prog_insns,
						        ARRAY_SIZE(prog_insns));

	int64_t ret = ebpf_vm_exec(&test_ctx_prog, &ctx, sizeof(ctx));

	zassert_equal(ret, 123, "Expected 123, got %lld", ret);
}

/* Test: CALL helper (ktime_get_ns returns non-zero) */
ZTEST(ebpf_vm, test_call_helper)
{
	static const struct ebpf_insn prog_insns[] = {
		EBPF_CALL_HELPER(EBPF_HELPER_KTIME_GET_NS),
		/* R0 now has timestamp, should be > 0 */
		EBPF_EXIT_INSN(),
	};

	struct ebpf_prog test_call = make_test_prog("test_call", prog_insns,
						    ARRAY_SIZE(prog_insns));

	int64_t ret = ebpf_vm_exec(&test_call, NULL, 0);

	zassert_true(ret >= 0, "ktime_get_ns should return >= 0, got %lld", ret);
}

ZTEST(ebpf_vm, test_ktime_helper_tracks_64bit_cycle_clock)
{
	ebpf_helper_fn fn = ebpf_get_helper(EBPF_HELPER_KTIME_GET_NS);
	uint64_t before;
	uint64_t value;
	uint64_t after;

	zassert_not_null(fn, "ktime helper should be registered");

	before = k_cyc_to_ns_floor64(k_cycle_get_64());
	value = fn(0, 0, 0, 0, 0);
	after = k_cyc_to_ns_floor64(k_cycle_get_64());

	zassert_true(value >= before,
		     "helper timestamp should not be behind current 64-bit clock");
	zassert_true(value <= after,
		     "helper timestamp should not be ahead of current 64-bit clock");
}

/* Test: Unknown opcode returns error */
ZTEST(ebpf_vm, test_unknown_opcode)
{
	static const struct ebpf_insn prog_insns[] = {
		EBPF_INSN_OP(0xFE, 0, 0, 0, 0), /* Invalid opcode */
		EBPF_EXIT_INSN(),
	};

	struct ebpf_prog test_bad_op = make_test_prog("test_bad_op", prog_insns,
						      ARRAY_SIZE(prog_insns));

	int64_t ret = ebpf_vm_exec(&test_bad_op, NULL, 0);

	zassert_equal(ret, -EINVAL, "Expected -EINVAL, got %lld", ret);
}

ZTEST(ebpf_vm, test_runtime_bounds_check_rejects_wrapped_region)
{
	static const struct ebpf_insn prog_insns[] = {
		EBPF_LDX_MEM_W(EBPF_REG_R0, EBPF_REG_R1, 0),
		EBPF_EXIT_INSN(),
	};
	struct ebpf_prog prog = make_test_prog("test_wrapped_region",
					      prog_insns,
					      ARRAY_SIZE(prog_insns));
	void *ctx = (void *)(uintptr_t)(UINTPTR_MAX - 1U);
	int64_t ret = ebpf_vm_exec(&prog, ctx, sizeof(uint32_t));

	zassert_equal(ret, -EFAULT, "wrapped region should be rejected, got %lld", ret);
}

ZTEST(ebpf_vm, test_runtime_rejects_context_write)
{
	struct test_ctx {
		uint32_t value;
	} ctx = { .value = 123 };
	static const struct ebpf_insn prog_insns[] = {
		EBPF_ST_MEM_W(EBPF_REG_R1, 0, 99),
		EBPF_EXIT_INSN(),
	};
	struct ebpf_prog prog = make_test_prog("ctx_write_runtime_reject",
					      prog_insns,
					      ARRAY_SIZE(prog_insns));
	int64_t ret = ebpf_vm_exec(&prog, &ctx, sizeof(ctx));

	zassert_equal(ret, -EFAULT,
		      "context writes should be rejected at runtime, got %lld", ret);
	zassert_equal(ctx.value, 123U,
		      "runtime-rejected context writes must not modify the caller buffer");
}

ZTEST(ebpf_vm, test_runtime_rejects_helper_disallowed_by_contract)
{
	static const struct ebpf_insn prog_insns[] = {
		EBPF_CALL_HELPER(EBPF_HELPER_RINGBUF_OUTPUT),
		EBPF_EXIT_INSN(),
	};
	struct ebpf_prog prog = make_test_prog("pm_ringbuf_runtime_reject",
					      prog_insns,
					      ARRAY_SIZE(prog_insns));
	struct ebpf_ctx_pm ctx = { 0 };
	int64_t ret;

	prog.type = EBPF_PROG_TYPE_PM;
	zassert_ok(ebpf_prog_attach(&prog,
				  EBPF_ATTACH_TARGET_PM(EBPF_PM_ATTACH_STATE_ENTRY)),
		   "PM attach should succeed");

	ret = ebpf_vm_exec(&prog, &ctx, sizeof(ctx));
	if (ebpf_get_helper(EBPF_HELPER_RINGBUF_OUTPUT) == NULL) {
		zassert_equal(ret, -EINVAL,
		      "missing ringbuf helper should still be reported as unknown");
	} else {
		zassert_equal(ret, -EPERM,
		      "PM contract should reject ringbuf helper at runtime, got %lld", ret);
	}

	ebpf_prog_detach(&prog);
}

ZTEST_SUITE(ebpf_vm, NULL, NULL, NULL, NULL, NULL);
