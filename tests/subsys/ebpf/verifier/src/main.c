/*
 * SPDX-FileCopyrightText: Copyright 2026 NXP
 *
 * SPDX-License-Identifier: Apache-2.0
 */

#include <zephyr/ztest.h>

#include "../../../../subsys/ebpf/prog/ebpf_prog_internal.h"
#include "../../../../subsys/ebpf/map/ebpf_map_internal.h"
#include "../../../../subsys/ebpf/map/ebpf_map_spec_internal.h"

extern int ebpf_verify_for_target(const struct ebpf_prog_image *prog,
					 const struct ebpf_attach_target *target);

static int ebpf_verify(const struct ebpf_prog_image *prog)
{
	const struct ebpf_attach_target target = EBPF_ATTACH_TARGET_NONE;

	return ebpf_verify_for_target(prog, &target);
}

static struct ebpf_map *test_bounds_map;

static void *ebpf_verifier_setup(void)
{
	const struct ebpf_map_spec spec = {
		.name = "test_bounds_map",
		.type = EBPF_MAP_TYPE_ARRAY,
		.key_size = sizeof(uint32_t),
		.value_size = sizeof(uint32_t),
		.max_entries = 2,
	};
	int ret;

	ret = ebpf_map_create(&spec, &test_bounds_map);
	zassert_ok(ret, "failed to create verifier bounds map: %d", ret);

	return NULL;
}

static void ebpf_verifier_teardown(void *fixture)
{
	ARG_UNUSED(fixture);

	if (test_bounds_map != NULL) {
		zassert_ok(ebpf_map_destroy(test_bounds_map), "failed to destroy verifier bounds map");
		test_bounds_map = NULL;
	}
}

ZTEST(ebpf_verifier, test_positive_r10_offset_is_rejected)
{
	static const struct ebpf_insn prog_insns[] = {
		EBPF_ST_MEM_W(EBPF_REG_R10, 4, 1),
		EBPF_EXIT_INSN(),
	};
	struct ebpf_prog_image prog = {
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
	struct ebpf_prog_image prog = {
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
	struct ebpf_prog_image prog = {
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
	struct ebpf_prog_image prog = {
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
	struct ebpf_prog_image prog = {
		.name = "ctx_read_derived_ok",
		.type = EBPF_PROG_TYPE_GENERIC,
		.insns = prog_insns,
		.insn_cnt = ARRAY_SIZE(prog_insns),
	};

	zassert_ok(ebpf_verify(&prog),
		   "reads through a derived context pointer should pass");
}

ZTEST(ebpf_verifier, test_map_lookup_requires_constant_registered_map_id)
{
	static const struct ebpf_insn prog_insns[] = {
		EBPF_MOV64_REG(EBPF_REG_R1, EBPF_REG_R2),
		EBPF_CALL_HELPER(EBPF_HELPER_MAP_LOOKUP_ELEM),
		EBPF_EXIT_INSN(),
	};
	struct ebpf_prog_image prog = {
		.name = "map_lookup_nonconst_id",
		.type = EBPF_PROG_TYPE_GENERIC,
		.insns = prog_insns,
		.insn_cnt = ARRAY_SIZE(prog_insns),
	};

	zassert_equal(ebpf_verify(&prog), -EINVAL,
		      "map_lookup should require a known constant registered map id");
}

ZTEST(ebpf_verifier, test_map_value_access_stays_within_single_entry)
{
	static struct ebpf_insn prog_insns[] = {
		EBPF_MOV64_IMM(EBPF_REG_R1, 0),
		EBPF_CALL_HELPER(EBPF_HELPER_MAP_LOOKUP_ELEM),
		EBPF_LDX_MEM_W(EBPF_REG_R0, EBPF_REG_R0, 4),
		EBPF_EXIT_INSN(),
	};
	struct ebpf_prog_image prog = {
		.name = "map_value_oob_rejected",
		.type = EBPF_PROG_TYPE_GENERIC,
		.insns = prog_insns,
		.insn_cnt = ARRAY_SIZE(prog_insns),
	};

	prog_insns[0].imm = (int32_t)ebpf_map_get_id(test_bounds_map);

	zassert_equal(ebpf_verify(&prog), -EINVAL,
		      "map value accesses must stay within the resolved single entry");
}

ZTEST(ebpf_verifier, test_map_value_access_with_fixed_offset_within_entry_passes)
{
	static struct ebpf_insn prog_insns[] = {
		EBPF_MOV64_IMM(EBPF_REG_R1, 0),
		EBPF_CALL_HELPER(EBPF_HELPER_MAP_LOOKUP_ELEM),
		EBPF_ADD64_IMM(EBPF_REG_R0, 1),
		EBPF_LDX_MEM_B(EBPF_REG_R0, EBPF_REG_R0, 2),
		EBPF_EXIT_INSN(),
	};
	struct ebpf_prog_image prog = {
		.name = "map_value_in_bounds_ok",
		.type = EBPF_PROG_TYPE_GENERIC,
		.insns = prog_insns,
		.insn_cnt = ARRAY_SIZE(prog_insns),
	};

	prog_insns[0].imm = (int32_t)ebpf_map_get_id(test_bounds_map);

	zassert_ok(ebpf_verify(&prog),
		   "in-bounds map value accesses should remain accepted");
}

ZTEST_SUITE(ebpf_verifier, NULL, ebpf_verifier_setup, NULL, NULL, ebpf_verifier_teardown);
