/*
 * SPDX-FileCopyrightText: Copyright 2026 NXP
 *
 * SPDX-License-Identifier: Apache-2.0
 */

#include <zephyr/ztest.h>

#include <zephyr/ebpf/ebpf_attach_target.h>
#include <zephyr/ebpf/ebpf_helpers.h>
#include <zephyr/ebpf/ebpf_insn.h>
#include <zephyr/ebpf/ebpf_prog.h>

extern int ebpf_verify(const struct ebpf_prog *prog);

ZTEST(ebpf_verifier, test_positive_r10_offset_is_rejected)
{
	static const struct ebpf_insn prog_insns[] = {
		EBPF_ST_MEM_W(EBPF_REG_R10, 4, 1),
		EBPF_EXIT_INSN(),
	};
	struct ebpf_prog prog = {
		.name = "bad_r10_offset",
		.type = EBPF_PROG_TYPE_GENERIC,
		.insns = prog_insns,
		.insn_cnt = ARRAY_SIZE(prog_insns),
	};

	zassert_equal(ebpf_verify(&prog), -EINVAL,
		      "positive R10 offset should be rejected");
}

ZTEST(ebpf_verifier, test_negative_r10_offset_is_accepted)
{
	static const struct ebpf_insn prog_insns[] = {
		EBPF_ST_MEM_W(EBPF_REG_R10, -4, 1),
		EBPF_EXIT_INSN(),
	};
	struct ebpf_prog prog = {
		.name = "good_r10_offset",
		.type = EBPF_PROG_TYPE_GENERIC,
		.insns = prog_insns,
		.insn_cnt = ARRAY_SIZE(prog_insns),
	};

	zassert_ok(ebpf_verify(&prog), "negative R10 offset should pass");
}

ZTEST(ebpf_verifier, test_context_write_is_rejected)
{
	static const struct ebpf_insn prog_insns[] = {
		EBPF_ST_MEM_W(EBPF_REG_R1, 0, 1),
		EBPF_EXIT_INSN(),
	};
	struct ebpf_prog prog = {
		.name = "ctx_write_rejected",
		.type = EBPF_PROG_TYPE_GENERIC,
		.insns = prog_insns,
		.insn_cnt = ARRAY_SIZE(prog_insns),
	};

	zassert_equal(ebpf_verify(&prog), -EINVAL,
		      "writes through the context pointer should be rejected");
}

ZTEST(ebpf_verifier, test_context_write_via_derived_pointer_is_rejected)
{
	static const struct ebpf_insn prog_insns[] = {
		EBPF_MOV64_REG(EBPF_REG_R2, EBPF_REG_R1),
		EBPF_ADD64_IMM(EBPF_REG_R2, 0),
		EBPF_ST_MEM_W(EBPF_REG_R2, 0, 1),
		EBPF_EXIT_INSN(),
	};
	struct ebpf_prog prog = {
		.name = "ctx_write_derived_rejected",
		.type = EBPF_PROG_TYPE_GENERIC,
		.insns = prog_insns,
		.insn_cnt = ARRAY_SIZE(prog_insns),
	};

	zassert_equal(ebpf_verify(&prog), -EINVAL,
		      "writes through a derived context pointer should be rejected");
}

ZTEST(ebpf_verifier, test_context_read_via_derived_pointer_is_accepted)
{
	static const struct ebpf_insn prog_insns[] = {
		EBPF_MOV64_REG(EBPF_REG_R2, EBPF_REG_R1),
		EBPF_ADD64_IMM(EBPF_REG_R2, 0),
		EBPF_LDX_MEM_W(EBPF_REG_R0, EBPF_REG_R2, 0),
		EBPF_EXIT_INSN(),
	};
	struct ebpf_prog prog = {
		.name = "ctx_read_derived_ok",
		.type = EBPF_PROG_TYPE_GENERIC,
		.insns = prog_insns,
		.insn_cnt = ARRAY_SIZE(prog_insns),
	};

	zassert_ok(ebpf_verify(&prog),
		   "reads through a derived context pointer should pass");
}

ZTEST(ebpf_verifier, test_pm_contract_rejects_ringbuf_helper)
{
	static const struct ebpf_insn prog_insns[] = {
		EBPF_CALL_HELPER(EBPF_HELPER_RINGBUF_OUTPUT),
		EBPF_EXIT_INSN(),
	};
	struct ebpf_prog prog;

	ebpf_prog_init(&prog, "pm_ringbuf_rejected", EBPF_PROG_TYPE_PM,
			       prog_insns, ARRAY_SIZE(prog_insns));
	zassert_ok(ebpf_prog_attach(&prog,
				  EBPF_ATTACH_TARGET_PM(EBPF_PM_ATTACH_STATE_ENTRY)),
		   "PM attach should succeed");

	zassert_equal(ebpf_verify(&prog), -EINVAL,
		      "PM contract should reject ringbuf helper");

	ebpf_prog_detach(&prog);
}

ZTEST(ebpf_verifier, test_isr_contract_rejects_ringbuf_helper)
{
	static const struct ebpf_insn prog_insns[] = {
		EBPF_CALL_HELPER(EBPF_HELPER_RINGBUF_OUTPUT),
		EBPF_EXIT_INSN(),
	};
	struct ebpf_prog prog;

	ebpf_prog_init(&prog, "isr_ringbuf_rejected", EBPF_PROG_TYPE_ISR,
			       prog_insns, ARRAY_SIZE(prog_insns));
	zassert_ok(ebpf_prog_attach(&prog,
				  EBPF_ATTACH_TARGET_TRACING(EBPF_TRACING_ATTACH_ISR_ENTER)),
		   "ISR attach should succeed");

	zassert_equal(ebpf_verify(&prog), -EINVAL,
		      "ISR contract should reject ringbuf helper");

	ebpf_prog_detach(&prog);
}

ZTEST(ebpf_verifier, test_tracing_contract_accepts_ringbuf_helper)
{
	static const struct ebpf_insn prog_insns[] = {
		EBPF_CALL_HELPER(EBPF_HELPER_RINGBUF_OUTPUT),
		EBPF_EXIT_INSN(),
	};
	struct ebpf_prog prog;

	ebpf_prog_init(&prog, "tracing_ringbuf_ok", EBPF_PROG_TYPE_GENERIC,
			       prog_insns, ARRAY_SIZE(prog_insns));
	zassert_ok(ebpf_prog_attach(&prog,
				  EBPF_ATTACH_TARGET_TRACING(EBPF_TRACING_ATTACH_THREAD_SWITCHED_IN)),
		   "Tracing attach should succeed");

	if (ebpf_get_helper(EBPF_HELPER_RINGBUF_OUTPUT) == NULL) {
		zassert_equal(ebpf_verify(&prog), -EINVAL,
			      "verify should fail when ringbuf helper support is compiled out");
	} else {
		zassert_ok(ebpf_verify(&prog),
			   "tracing generic contract should allow ringbuf helper");
	}

	ebpf_prog_detach(&prog);
}

ZTEST_SUITE(ebpf_verifier, NULL, NULL, NULL, NULL, NULL);
