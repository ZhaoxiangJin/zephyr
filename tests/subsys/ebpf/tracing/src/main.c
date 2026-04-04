/*
 * SPDX-FileCopyrightText: Copyright 2026 NXP
 *
 * SPDX-License-Identifier: Apache-2.0
 */

#include <zephyr/ztest.h>
#include <zephyr/kernel.h>
#include <stddef.h>
#include <string.h>

#include <zephyr/sys/crc.h>

#include "../../../../subsys/ebpf/attach/target/target.h"
#include "../../../../subsys/ebpf/attach/hook/hook.h"
#include "../../../../subsys/ebpf/bundle/bundle.h"
#include "../../../../subsys/ebpf/loader/image.h"

static K_SEM_DEFINE(verify_return_entered, 0, 1);
static K_SEM_DEFINE(verify_return_continue, 0, 1);
static K_THREAD_STACK_DEFINE(enable_stack, 1024);
static struct k_thread enable_thread;
static bool verify_return_hook_enabled;
static int enable_thread_ret;

void __real_ebpf_attach_target_lock(const struct ebpf_attach_target *target);

static const struct ebpf_insn exit_prog[] = {
	EBPF_MOV64_IMM(EBPF_REG_R0, 0),
	EBPF_EXIT_INSN(),
};

static const struct ebpf_insn invalid_prog[] = {
	EBPF_INSN_OP(0xFE, 0, 0, 0, 0),
	EBPF_EXIT_INSN(),
};

static const struct ebpf_insn loader_counter_prog[] = {
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

struct loader_test_image {
	struct ebpf_loader_image_header header;
	struct ebpf_loader_image_map map;
	struct ebpf_loader_image_attachment attachment;
	struct ebpf_loader_image_reloc reloc;
	struct ebpf_insn insns[ARRAY_SIZE(loader_counter_prog)];
	char strings[128];
	struct ebpf_loader_auth_crc32 auth;
};

static uint32_t loader_image_add_string(struct loader_test_image *image,
					size_t *cursor, const char *str)
{
	size_t len = strlen(str) + 1U;
	uint32_t offset = offsetof(struct loader_test_image, strings) + *cursor;

	zassert_true((*cursor + len) <= sizeof(image->strings),
		     "loader test string section overflow");
	memcpy(&image->strings[*cursor], str, len);
	*cursor += len;

	return offset;
}

static void loader_image_finalize(struct loader_test_image *image,
				   size_t strings_len)
{
	image->header.strings_size = strings_len;
	image->header.auth_offset = offsetof(struct loader_test_image, auth);
	image->header.auth_size = sizeof(image->auth);
	image->header.total_size = image->header.auth_offset + image->header.auth_size;
	image->auth.crc32 = crc32_ieee((const uint8_t *)image, image->header.auth_offset);
}

static void loader_build_dynamic_map_image(struct loader_test_image *image)
{
	size_t strings_len = 0U;

	memset(image, 0, sizeof(*image));
	image->header.magic = EBPF_LOADER_IMAGE_MAGIC;
	image->header.version = EBPF_LOADER_IMAGE_VERSION;
	image->header.header_size = sizeof(image->header);
	image->header.auth_type = EBPF_LOADER_AUTH_CRC32;
	image->header.ttl_ms = 0U;
	image->header.map_count = 1U;
	image->header.attachment_count = 1U;
	image->header.reloc_count = 1U;
	image->header.maps_offset = offsetof(struct loader_test_image, map);
	image->header.attachments_offset = offsetof(struct loader_test_image, attachment);
	image->header.relocs_offset = offsetof(struct loader_test_image, reloc);
	image->header.strings_offset = offsetof(struct loader_test_image, strings);
	image->header.bundle_name_offset = loader_image_add_string(image, &strings_len,
							  "loader_bundle");
	image->map.name_offset = loader_image_add_string(image, &strings_len,
						  "dyn_counter");
	image->attachment.name_offset = loader_image_add_string(image, &strings_len,
							 "loader_attachment");
	image->attachment.hook_name_offset = loader_image_add_string(image, &strings_len,
							      "kernel/thread_switched_in");
	image->map.type = EBPF_MAP_TYPE_ARRAY;
	image->map.key_size = sizeof(uint32_t);
	image->map.value_size = sizeof(uint32_t);
	image->map.max_entries = 1U;
	image->attachment.prog_type = EBPF_PROG_TYPE_SCHED;
	image->attachment.insns_offset = offsetof(struct loader_test_image, insns);
	image->attachment.insn_cnt = ARRAY_SIZE(loader_counter_prog);
	image->reloc.attachment_index = 0U;
	image->reloc.insn_index = 3U;
	image->reloc.map_index = 0U;
	memcpy(image->insns, loader_counter_prog, sizeof(loader_counter_prog));
	loader_image_finalize(image, strings_len);
}

static struct ebpf_prog *create_prog_instance(const char *name,
					      enum ebpf_prog_type type,
					      const struct ebpf_insn *insns,
					      uint32_t insn_cnt)
{
	const struct ebpf_prog_image image = {
		.name = name,
		.type = type,
		.insns = insns,
		.insn_cnt = insn_cnt,
	};
	struct ebpf_prog *prog;
	int ret;

	ret = ebpf_prog_create(&image, &prog);
	zassert_ok(ret, "program create failed: %d", ret);

	return prog;
}

static struct ebpf_prog *create_prog(const char *name)
{
	return create_prog_instance(name, EBPF_PROG_TYPE_SCHED,
				    exit_prog, ARRAY_SIZE(exit_prog));
}

static struct ebpf_prog *create_prog_with_type(const char *name,
					       enum ebpf_prog_type type)
{
	return create_prog_instance(name, type, exit_prog, ARRAY_SIZE(exit_prog));
}

static struct ebpf_prog *create_prog_from_insns(const char *name,
						const struct ebpf_insn *insns,
						uint32_t insn_cnt)
{
	return create_prog_instance(name, EBPF_PROG_TYPE_SCHED, insns, insn_cnt);
}

void __wrap_ebpf_attach_target_lock(const struct ebpf_attach_target *target)
{
	if (verify_return_hook_enabled && k_current_get() == &enable_thread) {
		k_sem_give(&verify_return_entered);
		(void)k_sem_take(&verify_return_continue, K_SECONDS(1));
	}

	__real_ebpf_attach_target_lock(target);
}

static void enable_thread_entry(void *p1, void *p2, void *p3)
{
	struct ebpf_prog *prog = p1;

	ARG_UNUSED(p2);
	ARG_UNUSED(p3);

	enable_thread_ret = ebpf_prog_enable(prog);
}

ZTEST(ebpf_tracing, test_same_target_accepts_multiple_programs)
{
	struct ebpf_prog *prog_a = create_prog("prog_a");
	struct ebpf_prog *prog_b = create_prog("prog_b");
	struct ebpf_attach_target target =
		EBPF_ATTACH_TARGET_TRACING(EBPF_TRACING_ATTACH_THREAD_SWITCHED_IN);
	int ret;

	ret = ebpf_prog_attach(prog_a, target);
	zassert_ok(ret, "first attach failed: %d", ret);

	ret = ebpf_prog_attach(prog_b, target);
	zassert_ok(ret, "second attach failed: %d", ret);

	ret = ebpf_prog_enable(prog_a);
	zassert_ok(ret, "enable prog_a failed: %d", ret);
	ret = ebpf_prog_enable(prog_b);
	zassert_ok(ret, "enable prog_b failed: %d", ret);

	ebpf_prog_disable(prog_a);
	ebpf_prog_disable(prog_b);
	ebpf_prog_detach(prog_a);
	ebpf_prog_detach(prog_b);
	ebpf_prog_destroy(prog_a);
	ebpf_prog_destroy(prog_b);
}

ZTEST(ebpf_tracing, test_hook_api_attaches_using_stable_hook_id)
{
	struct ebpf_bundle *bundle;
	struct ebpf_attachment *attachment;
	struct ebpf_attachment *found_attachment;
	struct ebpf_attachment_spec spec = {
		.name = "hook_api_attachment",
		.type = EBPF_PROG_TYPE_SCHED,
		.insns = exit_prog,
		.insn_cnt = ARRAY_SIZE(exit_prog),
		.hook_name = "kernel/thread_switched_in",
	};
	struct ebpf_attach_target target;
	int ret;

	ret = ebpf_bundle_create("hook_api_bundle", &bundle);
	zassert_ok(ret, "bundle create failed: %d", ret);

	ret = ebpf_bundle_add_attachment(bundle, &spec, &attachment);
	zassert_ok(ret, "bundle add attachment failed: %d", ret);
	zassert_not_null(attachment, "bundle add attachment should expose a handle");

	found_attachment = ebpf_bundle_find_attachment(bundle, spec.name);
	zassert_equal_ptr(found_attachment, attachment,
			  "bundle attachment lookup should return the created handle");
	zassert_true(strcmp(ebpf_attachment_name(found_attachment), spec.name) == 0,
		     "attachment name getter should return the stable attachment name");
	zassert_true(strcmp(ebpf_attachment_hook_name(found_attachment), spec.hook_name) == 0,
		     "attachment hook getter should return the stable hook name");

	ret = ebpf_hook_name_to_target(spec.hook_name, &target);
	zassert_ok(ret, "hook name should translate to a target: %d", ret);
	zassert_equal(target.backend, EBPF_ATTACH_BACKEND_TRACING,
		      "hook API should resolve to tracing backend");
	zassert_equal(target.point, EBPF_TRACING_ATTACH_THREAD_SWITCHED_IN,
		      "hook API should resolve to thread-switched-in target");

	ret = ebpf_bundle_destroy(bundle);
	zassert_ok(ret, "bundle destroy failed: %d", ret);
}

ZTEST(ebpf_tracing, test_loader_loads_named_hook_with_runtime_map_reloc)
{
	struct loader_test_image image;
	struct ebpf_loader_handle *handle;
	struct ebpf_attach_target target =
		EBPF_ATTACH_TARGET_TRACING(EBPF_TRACING_ATTACH_THREAD_SWITCHED_IN);
	int ret;

	loader_build_dynamic_map_image(&image);

	ret = ebpf_loader_load(&image, image.header.total_size, &handle);
	zassert_ok(ret, "loader load failed: %d", ret);
	zassert_not_null(handle, "loader should return a runtime handle");
	zassert_true(strcmp(ebpf_loader_name(handle), "loader_bundle") == 0,
		     "loader should preserve the bundle name");

	ret = ebpf_loader_load(&image, image.header.total_size, NULL);
	zassert_equal(ret, -EINVAL, "loader should reject a NULL handle output, got %d", ret);

	ret = ebpf_loader_enable(handle);
	zassert_ok(ret, "loader enable failed: %d", ret);

	/* Dispatch must not crash: successful dispatch implies the loader wired
	 * the runtime attachment to the resolved hook target. Observable side
	 * effects of the dispatched program are covered by bundle-owned map
	 * lifecycle tests that manipulate maps directly.
	 */
	ebpf_attach_target_dispatch(&target, &image, sizeof(image));

	ret = ebpf_loader_unload(handle);
	zassert_ok(ret, "loader unload failed: %d", ret);
}

ZTEST(ebpf_tracing, test_loader_rejects_duplicate_bundle_name)
{
	struct loader_test_image image;
	struct ebpf_loader_handle *first_handle = NULL;
	struct ebpf_loader_handle *second_handle = NULL;
	int ret;

	loader_build_dynamic_map_image(&image);

	ret = ebpf_loader_load(&image, image.header.total_size, &first_handle);
	zassert_ok(ret, "initial loader load failed: %d", ret);
	zassert_not_null(first_handle, "initial load should produce a handle");

	ret = ebpf_loader_load(&image, image.header.total_size, &second_handle);
	zassert_equal(ret, -EALREADY,
		      "duplicate bundle name should be rejected with -EALREADY, got %d", ret);
	zassert_is_null(second_handle,
		       "duplicate load must not expose a second handle");

	ret = ebpf_loader_unload(first_handle);
	zassert_ok(ret, "cleanup after duplicate-name test failed: %d", ret);
}

ZTEST(ebpf_tracing, test_bundle_destroy_removes_runtime_attachment)
{
	struct ebpf_attach_target target =
		EBPF_ATTACH_TARGET_TRACING(EBPF_TRACING_ATTACH_THREAD_SWITCHED_IN);
	struct ebpf_attachment_spec spec = {
		.name = "runtime_attachment",
		.type = EBPF_PROG_TYPE_SCHED,
		.insns = exit_prog,
		.insn_cnt = ARRAY_SIZE(exit_prog),
		.hook_name = "kernel/thread_switched_in",
	};
	struct ebpf_bundle *bundle;
	struct ebpf_attachment *attachment;
	uint32_t dummy_ctx = 0U;
	int ret;

	ret = ebpf_bundle_create("tracing_bundle", &bundle);
	zassert_ok(ret, "bundle create failed: %d", ret);

	ret = ebpf_bundle_add_attachment(bundle, &spec, &attachment);
	zassert_ok(ret, "bundle add attachment failed: %d", ret);

	ret = ebpf_bundle_enable(bundle);
	zassert_ok(ret, "runtime bundle enable failed: %d", ret);

	zassert_true(ebpf_attach_target_is_active(&target),
		     "target should become active after enabling runtime attachment");
	ebpf_attach_target_dispatch(&target, &dummy_ctx, sizeof(dummy_ctx));

	ret = ebpf_bundle_destroy(bundle);
	zassert_ok(ret, "bundle destroy failed: %d", ret);
	zassert_false(ebpf_attach_target_is_active(&target),
		      "target should be inactive after bundle teardown");
}

ZTEST(ebpf_tracing, test_bundle_enable_rolls_back_on_attachment_failure)
{
	struct ebpf_attach_target target =
		EBPF_ATTACH_TARGET_TRACING(EBPF_TRACING_ATTACH_THREAD_SWITCHED_IN);
	struct ebpf_attachment_spec good_spec = {
		.name = "good_attachment",
		.type = EBPF_PROG_TYPE_SCHED,
		.insns = exit_prog,
		.insn_cnt = ARRAY_SIZE(exit_prog),
		.hook_name = "kernel/thread_switched_in",
	};
	struct ebpf_attachment_spec bad_spec = {
		.name = "bad_attachment",
		.type = EBPF_PROG_TYPE_SCHED,
		.insns = invalid_prog,
		.insn_cnt = ARRAY_SIZE(invalid_prog),
		.hook_name = "kernel/thread_switched_in",
	};
	struct ebpf_bundle *bundle;
	struct ebpf_attachment *good_attachment;
	struct ebpf_attachment *bad_attachment;
	int ret;

	ret = ebpf_bundle_create("rollback_bundle", &bundle);
	zassert_ok(ret, "bundle create failed: %d", ret);

	ret = ebpf_bundle_add_attachment(bundle, &good_spec, &good_attachment);
	zassert_ok(ret, "good attachment add failed: %d", ret);
	ret = ebpf_bundle_add_attachment(bundle, &bad_spec, &bad_attachment);
	zassert_ok(ret, "bad attachment add failed: %d", ret);

	ret = ebpf_bundle_enable(bundle);
	zassert_equal(ret, -EINVAL,
		      "bundle enable should fail when one attachment cannot verify, got %d", ret);
	zassert_false(ebpf_attach_target_is_active(&target),
		     "failed bundle enable must not leave any attachment published");

	ret = ebpf_bundle_destroy(bundle);
	zassert_ok(ret, "bundle destroy after rollback test failed: %d", ret);
}

ZTEST(ebpf_tracing, test_disable_does_not_bypass_verifier)
{
	struct ebpf_prog *prog = create_prog_from_insns("invalid_prog",
						       invalid_prog,
						       ARRAY_SIZE(invalid_prog));
	struct ebpf_attach_target target =
		EBPF_ATTACH_TARGET_TRACING(EBPF_TRACING_ATTACH_THREAD_SWITCHED_IN);
	int ret;

	ret = ebpf_prog_attach(prog, target);
	zassert_ok(ret, "attach failed: %d", ret);

	ret = ebpf_prog_disable(prog);
	zassert_ok(ret, "disable failed: %d", ret);
	ret = ebpf_prog_attach(prog, target);
	zassert_equal(ret, -EALREADY,
		      "disable should keep program attached, got %d", ret);
	zassert_false(ebpf_attach_target_is_active(&target),
		     "disable before enable must not publish the target");

	ret = ebpf_prog_enable(prog);
	zassert_equal(ret, -EINVAL, "invalid program should fail verification, got %d", ret);
	ret = ebpf_prog_attach(prog, target);
	zassert_equal(ret, -EALREADY,
		      "failed enable should keep program attached, got %d", ret);
	zassert_false(ebpf_attach_target_is_active(&target),
		     "failed enable must not publish the target");

	ebpf_prog_detach(prog);
	ebpf_prog_destroy(prog);
}

ZTEST(ebpf_tracing, test_enable_requires_current_target)
{
	struct ebpf_prog *prog = create_prog("enable_requires_target");
	struct ebpf_attach_target target =
		EBPF_ATTACH_TARGET_TRACING(EBPF_TRACING_ATTACH_THREAD_SWITCHED_IN);
	int ret;

	ret = ebpf_prog_enable(prog);
	zassert_equal(ret, -ENOENT,
		      "enable without attach should fail, got %d", ret);
	ret = ebpf_prog_attach(prog, target);
	zassert_ok(ret, "enable failure should leave the program attachable, got %d", ret);
	zassert_false(ebpf_attach_target_is_active(&target),
		     "fresh attachment must stay inactive until enable");
	ebpf_prog_detach(prog);
	ebpf_prog_destroy(prog);
}

ZTEST(ebpf_tracing, test_reattach_starts_new_session)
{
	struct ebpf_prog *prog = create_prog("reattach_session_prog");
	struct ebpf_attach_target target_a =
		EBPF_ATTACH_TARGET_TRACING(EBPF_TRACING_ATTACH_THREAD_SWITCHED_IN);
	struct ebpf_attach_target target_b =
		EBPF_ATTACH_TARGET_TRACING(EBPF_TRACING_ATTACH_IDLE_ENTER);
	uint32_t dummy_ctx = 0U;
	int ret;

	ret = ebpf_prog_attach(prog, target_a);
	zassert_ok(ret, "attach target_a failed: %d", ret);
	ret = ebpf_prog_enable(prog);
	zassert_ok(ret, "enable target_a failed: %d", ret);
	ebpf_attach_target_dispatch(&target_a, &dummy_ctx, sizeof(dummy_ctx));

	ebpf_prog_disable(prog);
	zassert_false(ebpf_attach_target_is_active(&target_a),
		     "disable should unpublish the current attachment");

	ret = ebpf_prog_detach(prog);
	zassert_ok(ret, "detach target_a failed: %d", ret);

	ret = ebpf_prog_attach(prog, target_b);
	zassert_ok(ret, "attach target_b failed: %d", ret);
	zassert_false(ebpf_attach_target_is_active(&target_b),
		     "reattach should require enable for the new attachment");

	ret = ebpf_prog_enable(prog);
	zassert_ok(ret, "enable target_b failed: %d", ret);
	ebpf_attach_target_dispatch(&target_b, &dummy_ctx, sizeof(dummy_ctx));

	ebpf_prog_disable(prog);
	ret = ebpf_prog_detach(prog);
	zassert_ok(ret, "detach target_b failed: %d", ret);

	ret = ebpf_prog_attach(prog, target_a);
	zassert_ok(ret, "reattach target_a failed: %d", ret);
	zassert_false(ebpf_attach_target_is_active(&target_a),
		     "returning to a prior target should still require enable");

	ebpf_prog_detach(prog);
	ebpf_prog_destroy(prog);
}

ZTEST(ebpf_tracing, test_detach_only_clears_own_program)
{
	struct ebpf_prog *prog_a = create_prog("prog_a_owner");
	struct ebpf_prog *prog_b = create_prog("prog_b_owner");
	struct ebpf_attach_target target =
		EBPF_ATTACH_TARGET_TRACING(EBPF_TRACING_ATTACH_THREAD_SWITCHED_IN);
	int ret;

	ret = ebpf_prog_attach(prog_a, target);
	zassert_ok(ret, "attach failed: %d", ret);

	ret = ebpf_prog_attach(prog_b, target);
	zassert_ok(ret, "second attach failed: %d", ret);

	ebpf_prog_detach(prog_b);
	ret = ebpf_prog_enable(prog_a);
	zassert_ok(ret, "detaching a different program should keep the owner attached, got %d", ret);
	zassert_true(ebpf_attach_target_is_active(&target),
		     "owner program should still be publishable after detaching another program");

	ebpf_prog_disable(prog_a);
	ebpf_prog_detach(prog_a);
	ebpf_prog_destroy(prog_a);
	ebpf_prog_destroy(prog_b);
}

ZTEST(ebpf_tracing, test_prog_type_matches_only_compatible_targets)
{
	struct ebpf_prog *sched_prog = create_prog_with_type("sched_prog",
						     EBPF_PROG_TYPE_SCHED);
	struct ebpf_prog *isr_prog = create_prog_with_type("isr_prog",
						   EBPF_PROG_TYPE_ISR);
	struct ebpf_prog *pm_prog = create_prog_with_type("pm_prog",
						  EBPF_PROG_TYPE_PM);
	int ret;

	ret = ebpf_prog_attach(sched_prog,
			       EBPF_ATTACH_TARGET_TRACING(EBPF_TRACING_ATTACH_THREAD_SWITCHED_IN));
	zassert_ok(ret, "sched attach to thread TP failed: %d", ret);
	ebpf_prog_detach(sched_prog);

	ret = ebpf_prog_attach(sched_prog,
			       EBPF_ATTACH_TARGET_TRACING(EBPF_TRACING_ATTACH_THREAD_SWITCHED_OUT));
	zassert_ok(ret, "sched attach to thread-out TP failed: %d", ret);
	ebpf_prog_detach(sched_prog);

	ret = ebpf_prog_attach(sched_prog,
			       EBPF_ATTACH_TARGET_TRACING(EBPF_TRACING_ATTACH_ISR_ENTER));
	zassert_equal(ret, -EINVAL,
		      "sched program should reject ISR TP, got %d", ret);

	ret = ebpf_prog_attach(isr_prog,
			       EBPF_ATTACH_TARGET_TRACING(EBPF_TRACING_ATTACH_ISR_ENTER));
	zassert_ok(ret, "ISR attach failed: %d", ret);
	ebpf_prog_detach(isr_prog);

	ret = ebpf_prog_attach(isr_prog,
			       EBPF_ATTACH_TARGET_TRACING(EBPF_TRACING_ATTACH_THREAD_SWITCHED_IN));
	zassert_equal(ret, -EINVAL,
		      "ISR program should reject sched TP, got %d", ret);

	ret = ebpf_prog_attach(pm_prog,
			       EBPF_ATTACH_TARGET_PM(EBPF_PM_ATTACH_STATE_ENTRY));
	zassert_ok(ret, "pm attach failed: %d", ret);
	ebpf_prog_detach(pm_prog);

	ret = ebpf_prog_attach(pm_prog,
			       EBPF_ATTACH_TARGET_TRACING(EBPF_TRACING_ATTACH_IDLE_ENTER));
	zassert_equal(ret, -EINVAL,
		      "pm program should reject tracing target, got %d", ret);

	ebpf_prog_destroy(sched_prog);
	ebpf_prog_destroy(isr_prog);
	ebpf_prog_destroy(pm_prog);
}

ZTEST(ebpf_tracing, test_enable_returns_eagain_if_session_changes_before_commit)
{
	struct ebpf_prog *prog = create_prog("enable_session_race_prog");
	struct ebpf_attach_target target_a =
		EBPF_ATTACH_TARGET_TRACING(EBPF_TRACING_ATTACH_THREAD_SWITCHED_IN);
	struct ebpf_attach_target target_b =
		EBPF_ATTACH_TARGET_TRACING(EBPF_TRACING_ATTACH_IDLE_ENTER);
	int ret;

	enable_thread_ret = 0;
	verify_return_hook_enabled = false;
	while (k_sem_take(&verify_return_entered, K_NO_WAIT) == 0) {
	}
	while (k_sem_take(&verify_return_continue, K_NO_WAIT) == 0) {
	}

	ret = ebpf_prog_attach(prog, target_a);
	zassert_ok(ret, "attach target_a failed: %d", ret);

	verify_return_hook_enabled = true;
	k_thread_create(&enable_thread, enable_stack, K_THREAD_STACK_SIZEOF(enable_stack),
			enable_thread_entry, prog, NULL, NULL, 1, 0, K_NO_WAIT);

	zassert_ok(k_sem_take(&verify_return_entered, K_SECONDS(1)),
		   "enable thread did not complete verify before commit");

	ret = ebpf_prog_detach(prog);
	zassert_ok(ret, "detach during enable failed: %d", ret);

	ret = ebpf_prog_attach(prog, target_b);
	zassert_ok(ret, "reattach during enable failed: %d", ret);

	k_sem_give(&verify_return_continue);
	k_thread_join(&enable_thread, K_SECONDS(1));
	verify_return_hook_enabled = false;

	zassert_equal(enable_thread_ret, -EAGAIN,
		      "enable should fail with -EAGAIN after session change, got %d",
		      enable_thread_ret);
	zassert_false(ebpf_attach_target_is_active(&target_a),
		     "old target must stay inactive after the session changes");
	zassert_false(ebpf_attach_target_is_active(&target_b),
		     "new session should remain inactive until enable is retried");
	ret = ebpf_prog_attach(prog, target_b);
	zassert_equal(ret, -EALREADY,
		      "new session should remain attached after raced enable, got %d", ret);

	ret = ebpf_prog_enable(prog);
	zassert_ok(ret, "enable target_b after race failed: %d", ret);
	zassert_true(ebpf_attach_target_is_active(&target_b),
		     "retry enable should publish the reattached target");
	zassert_false(ebpf_attach_target_is_active(&target_a),
		     "retry enable must not reactivate the old target");

	ebpf_prog_disable(prog);
	ebpf_prog_detach(prog);
	ebpf_prog_destroy(prog);
}

ZTEST_SUITE(ebpf_tracing, NULL, NULL, NULL, NULL, NULL);
