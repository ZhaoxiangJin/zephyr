/*
 * SPDX-FileCopyrightText: Copyright 2026 NXP
 *
 * SPDX-License-Identifier: Apache-2.0
 */

#include <zephyr/ztest.h>

#include "../../../../subsys/ebpf/bundle/ebpf_bundle_internal.h"
#include "../../../../subsys/ebpf/map/ebpf_map_internal.h"
#include "../../../../subsys/ebpf/map/ebpf_map_spec_internal.h"

extern int64_t ebpf_vm_exec(const struct ebpf_prog_image *prog, void *ctx_data,
			    uint32_t ctx_size);

static struct ebpf_map *test_array_map;
static struct ebpf_map *test_oob_array_map;

static void *ebpf_maps_setup(void)
{
	const struct ebpf_map_spec array_spec = {
		.name = "test_array_map",
		.type = EBPF_MAP_TYPE_ARRAY,
		.key_size = sizeof(uint32_t),
		.value_size = sizeof(uint32_t),
		.max_entries = 1,
	};
	const struct ebpf_map_spec oob_array_spec = {
		.name = "test_oob_array_map",
		.type = EBPF_MAP_TYPE_ARRAY,
		.key_size = sizeof(uint32_t),
		.value_size = sizeof(uint32_t),
		.max_entries = 2,
	};
	int ret;

	ret = ebpf_map_create(&array_spec, &test_array_map);
	zassert_ok(ret, "failed to create array map: %d", ret);
	ret = ebpf_map_create(&oob_array_spec, &test_oob_array_map);
	zassert_ok(ret, "failed to create oob array map: %d", ret);
	return NULL;
}

static void ebpf_maps_teardown(void *fixture)
{
	ARG_UNUSED(fixture);

	if (test_oob_array_map != NULL) {
		zassert_ok(ebpf_map_destroy(test_oob_array_map), "failed to destroy oob array map");
		test_oob_array_map = NULL;
	}
	if (test_array_map != NULL) {
		zassert_ok(ebpf_map_destroy(test_array_map), "failed to destroy array map");
		test_array_map = NULL;
	}
}

ZTEST(ebpf_maps, test_map_handle_lookup_and_bounds)
{
	static struct ebpf_insn prog_insns[] = {
		EBPF_ST_MEM_W(EBPF_REG_R10, -4, 0),
		EBPF_MOV64_REG(EBPF_REG_R2, EBPF_REG_R10),
		EBPF_ADD64_IMM(EBPF_REG_R2, -4),
		EBPF_MOV64_IMM(EBPF_REG_R1, 0),
		EBPF_CALL_HELPER(EBPF_HELPER_MAP_LOOKUP_ELEM),
		EBPF_JEQ_IMM(EBPF_REG_R0, 0, 3),
		EBPF_LDX_MEM_W(EBPF_REG_R1, EBPF_REG_R0, 0),
		EBPF_ADD64_IMM(EBPF_REG_R1, 1),
		EBPF_STX_MEM_W(EBPF_REG_R0, EBPF_REG_R1, 0),
		EBPF_MOV64_IMM(EBPF_REG_R0, 0),
		EBPF_EXIT_INSN(),
	};
	struct ebpf_prog_image prog = {
		.name = "maps_bounds_prog",
		.type = EBPF_PROG_TYPE_GENERIC,
		.insns = prog_insns,
		.insn_cnt = ARRAY_SIZE(prog_insns),
	};
	uint32_t key = 0;
	uint32_t zero = 0U;
	uint32_t *value;
	int64_t ret;

	zassert_ok(ebpf_map_update_elem(test_array_map, &key, &zero, 0),
		   "failed to reset array map");
	zassert_not_equal(ebpf_map_get_id(test_array_map), 0U, "map id should be assigned");
	prog_insns[3].imm = (int32_t)ebpf_map_get_id(test_array_map);

	ret = ebpf_vm_exec(&prog, NULL, 0);
	zassert_equal(ret, 0, "expected VM success, got %lld", ret);

	value = ebpf_map_lookup_elem(test_array_map, &key);
	zassert_not_null(value, "array map lookup failed");
	zassert_equal(*value, 1U, "expected counter increment, got %u", *value);
}

ZTEST(ebpf_maps, test_map_value_runtime_bounds_reject_adjacent_entry_write)
{
	static struct ebpf_insn prog_insns[] = {
		EBPF_ST_MEM_W(EBPF_REG_R10, -4, 0),
		EBPF_MOV64_REG(EBPF_REG_R2, EBPF_REG_R10),
		EBPF_ADD64_IMM(EBPF_REG_R2, -4),
		EBPF_MOV64_IMM(EBPF_REG_R1, 0),
		EBPF_CALL_HELPER(EBPF_HELPER_MAP_LOOKUP_ELEM),
		EBPF_ST_MEM_W(EBPF_REG_R0, 4, 99),
		EBPF_MOV64_IMM(EBPF_REG_R0, 0),
		EBPF_EXIT_INSN(),
	};
	struct ebpf_prog_image prog = {
		.name = "maps_adjacent_entry_write_rejected",
		.type = EBPF_PROG_TYPE_GENERIC,
		.insns = prog_insns,
		.insn_cnt = ARRAY_SIZE(prog_insns),
	};
	uint32_t key0 = 0U;
	uint32_t key1 = 1U;
	uint32_t value0 = 11U;
	uint32_t value1 = 22U;
	uint32_t *entry0;
	uint32_t *entry1;
	int64_t ret;

	zassert_ok(ebpf_map_update_elem(test_oob_array_map, &key0, &value0, 0),
		   "failed to seed first array entry");
	zassert_ok(ebpf_map_update_elem(test_oob_array_map, &key1, &value1, 0),
		   "failed to seed second array entry");

	prog_insns[3].imm = (int32_t)ebpf_map_get_id(test_oob_array_map);

	ret = ebpf_vm_exec(&prog, NULL, 0);
	zassert_equal(ret, -EFAULT,
		      "adjacent-entry write should fail with -EFAULT, got %lld", ret);

	entry0 = ebpf_map_lookup_elem(test_oob_array_map, &key0);
	entry1 = ebpf_map_lookup_elem(test_oob_array_map, &key1);
	zassert_not_null(entry0, "first array entry lookup failed");
	zassert_not_null(entry1, "second array entry lookup failed");
	zassert_equal(*entry0, value0,
		      "runtime-rejected write must not modify the source entry");
	zassert_equal(*entry1, value1,
		      "runtime-rejected write must not modify the adjacent entry");
}

ZTEST(ebpf_maps, test_bundle_owned_runtime_map_lifecycle)
{
	static struct ebpf_insn prog_insns[] = {
		EBPF_ST_MEM_W(EBPF_REG_R10, -4, 0),
		EBPF_MOV64_REG(EBPF_REG_R2, EBPF_REG_R10),
		EBPF_ADD64_IMM(EBPF_REG_R2, -4),
		EBPF_MOV64_IMM(EBPF_REG_R1, 0),
		EBPF_CALL_HELPER(EBPF_HELPER_MAP_LOOKUP_ELEM),
		EBPF_JEQ_IMM(EBPF_REG_R0, 0, 3),
		EBPF_LDX_MEM_W(EBPF_REG_R1, EBPF_REG_R0, 0),
		EBPF_ADD64_IMM(EBPF_REG_R1, 1),
		EBPF_STX_MEM_W(EBPF_REG_R0, EBPF_REG_R1, 0),
		EBPF_MOV64_IMM(EBPF_REG_R0, 0),
		EBPF_EXIT_INSN(),
	};
	struct ebpf_map_spec spec = {
		.name = "bundle_dyn_array",
		.type = EBPF_MAP_TYPE_ARRAY,
		.key_size = sizeof(uint32_t),
		.value_size = sizeof(uint32_t),
		.max_entries = 1,
	};
	struct ebpf_bundle *bundle;
	struct ebpf_map *map;
	struct ebpf_prog_image prog = {
		.name = "bundle_dyn_map_prog",
		.type = EBPF_PROG_TYPE_GENERIC,
		.insns = prog_insns,
		.insn_cnt = ARRAY_SIZE(prog_insns),
	};
	uint32_t key = 0U;
	uint32_t *value;
	uint32_t map_id;
	int64_t exec_ret;
	int ret;

	ret = ebpf_bundle_create("maps_bundle", &bundle);
	zassert_ok(ret, "bundle create failed: %d", ret);

	ret = ebpf_bundle_add_map(bundle, &spec, &map);
	zassert_ok(ret, "bundle add map failed: %d", ret);

	map_id = ebpf_map_get_id(map);
	zassert_not_equal(map_id, 0U, "dynamic map should receive a runtime id");
	zassert_equal(ebpf_map_from_id(map_id), map,
		      "dynamic map id should resolve to the created map");
	zassert_equal(ebpf_map_destroy(map), -EBUSY,
		      "bundle-owned dynamic map must reject direct destroy");

	prog_insns[3].imm = (int32_t)map_id;
	exec_ret = ebpf_vm_exec(&prog, NULL, 0);
	zassert_equal(exec_ret, 0, "expected VM success, got %lld", exec_ret);

	value = ebpf_map_lookup_elem(map, &key);
	zassert_not_null(value, "dynamic map lookup failed");
	zassert_equal(*value, 1U, "expected dynamic map counter increment, got %u", *value);

	ret = ebpf_bundle_destroy(bundle);
	zassert_ok(ret, "bundle destroy failed: %d", ret);
	zassert_is_null(ebpf_map_from_id(map_id),
		       "dynamic map id should be invalid after bundle destroy");
}

ZTEST_SUITE(ebpf_maps, NULL, ebpf_maps_setup, NULL, NULL, ebpf_maps_teardown);
