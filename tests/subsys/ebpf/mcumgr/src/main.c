/*
 * SPDX-FileCopyrightText: Copyright 2026 NXP
 *
 * SPDX-License-Identifier: Apache-2.0
 */

#include <string.h>

#include <zcbor_common.h>
#include <zcbor_decode.h>
#include <zcbor_encode.h>

#include <mgmt/mcumgr/util/zcbor_bulk.h>
#include <smp_internal.h>

#include <zephyr/ebpf/ebpf_bundle.h>
#include <zephyr/ebpf/ebpf_hook.h>
#include <zephyr/ebpf/ebpf_loader.h>
#include <zephyr/ebpf/ebpf_map.h>
#include <zephyr/mgmt/mcumgr/grp/ebpf_mgmt/ebpf_mgmt.h>
#include <zephyr/mgmt/mcumgr/mgmt/mgmt.h>
#include <zephyr/mgmt/mcumgr/transport/smp_dummy.h>
#include <zephyr/net_buf.h>
#include <zephyr/sys/byteorder.h>
#include <zephyr/ztest.h>

#include "../../../../subsys/ebpf/attach/ebpf_attach_target_internal.h"
#include "../../../../subsys/ebpf/loader/ebpf_loader_internal.h"

#define SMP_RESPONSE_WAIT_TIME 10
#define ZCBOR_BUFFER_SIZE 512
#define OUTPUT_BUFFER_SIZE 768
#define ZCBOR_HISTORY_ARRAY_SIZE 8
#define LOAD_SPLIT_OFFSET 160

static struct net_buf *nb;

static const uint8_t signed_probe_bundle[] = {
	0x45, 0x42, 0x50, 0x46, 0x02, 0x00, 0x40, 0x00, 0x5B, 0x01, 0x00, 0x00,
	0x02, 0x00, 0x00, 0x00, 0x98, 0x3A, 0x00, 0x00, 0xDC, 0x00, 0x00, 0x00,
	0x01, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00,
	0x40, 0x00, 0x00, 0x00, 0x54, 0x00, 0x00, 0x00, 0x68, 0x00, 0x00, 0x00,
	0xDC, 0x00, 0x00, 0x00, 0x3B, 0x00, 0x00, 0x00, 0x17, 0x01, 0x00, 0x00,
	0x44, 0x00, 0x00, 0x00, 0xE2, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x04, 0x00, 0x00, 0x00, 0x04, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00,
	0xEE, 0x00, 0x00, 0x00, 0xFD, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x74, 0x00, 0x00, 0x00, 0x0D, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x04, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xB4, 0x01, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x63, 0x1A, 0xFC, 0xFF, 0x00, 0x00, 0x00, 0x00,
	0xBF, 0xA2, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x07, 0x02, 0x00, 0x00,
	0xFC, 0xFF, 0xFF, 0xFF, 0x18, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x85, 0x00, 0x00, 0x00,
	0x01, 0x00, 0x00, 0x00, 0x15, 0x00, 0x03, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x61, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x04, 0x01, 0x00, 0x00,
	0x01, 0x00, 0x00, 0x00, 0x63, 0x10, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0xB4, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x95, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x70, 0x72, 0x6F, 0x62, 0x65, 0x00, 0x63, 0x6F,
	0x75, 0x6E, 0x74, 0x65, 0x72, 0x5F, 0x6D, 0x61, 0x70, 0x00, 0x63, 0x6F,
	0x75, 0x6E, 0x74, 0x5F, 0x73, 0x77, 0x69, 0x74, 0x63, 0x68, 0x65, 0x73,
	0x00, 0x6B, 0x65, 0x72, 0x6E, 0x65, 0x6C, 0x2F, 0x74, 0x68, 0x72, 0x65,
	0x61, 0x64, 0x5F, 0x73, 0x77, 0x69, 0x74, 0x63, 0x68, 0x65, 0x64, 0x5F,
	0x69, 0x6E, 0x00, 0x00, 0x00, 0x00, 0x00, 0xB3, 0x75, 0x09, 0xE2, 0x9D,
	0x66, 0xF3, 0x8F, 0x62, 0xEE, 0xED, 0x04, 0x28, 0x21, 0xB0, 0xBF, 0x61,
	0x29, 0xDC, 0xA1, 0x39, 0x42, 0x49, 0x6E, 0xFC, 0xB0, 0x33, 0x18, 0x3E,
	0xD2, 0xDD, 0xB9, 0xE9, 0x55, 0xDC, 0x45, 0x4D, 0x26, 0x6D, 0x5B, 0x35,
	0xF0, 0x37, 0xD3, 0x64, 0xDD, 0x9F, 0x6A, 0x34, 0xD2, 0x8A, 0xAA, 0x95,
	0x19, 0xAC, 0x8B, 0xFA, 0x5B, 0xFD, 0xCE, 0x5E, 0x6D, 0xC2, 0x8D,
};

struct group_error {
	uint16_t group;
	uint16_t rc;
	bool found;
};

struct load_response {
	uint32_t off;
	bool off_found;
	bool loaded;
	bool loaded_found;
	bool enabled;
	bool enabled_found;
	struct zcbor_string name;
	bool name_found;
	struct group_error err;
};

struct status_response {
	struct zcbor_string name;
	bool name_found;
	bool loaded;
	bool loaded_found;
	bool enabled;
	bool enabled_found;
	uint32_t ttl_ms;
	bool ttl_found;
	bool auto_unloaded;
	bool auto_unloaded_found;
	struct group_error err;
};

static void cleanup_test(void *data)
{
	ARG_UNUSED(data);

	if (nb != NULL) {
		net_buf_unref(nb);
		nb = NULL;
	}

	(void)ebpf_loader_unload_by_name("probe");
	smp_dummy_disable();
	smp_dummy_clear_state();
}

static bool mcumgr_ret_decode(zcbor_state_t *state, void *result_ptr)
{
	struct group_error *result = result_ptr;
	bool ok;
	size_t decoded;
	uint32_t tmp_group;
	uint32_t tmp_rc;
	struct zcbor_map_decode_key_val output_decode[] = {
		ZCBOR_MAP_DECODE_KEY_DECODER("group", zcbor_uint32_decode, &tmp_group),
		ZCBOR_MAP_DECODE_KEY_DECODER("rc", zcbor_uint32_decode, &tmp_rc),
	};

	result->found = false;
	ok = zcbor_map_decode_bulk(state, output_decode, ARRAY_SIZE(output_decode), &decoded) == 0;
	if (ok &&
	    zcbor_map_decode_bulk_key_found(output_decode, ARRAY_SIZE(output_decode), "group") &&
	    zcbor_map_decode_bulk_key_found(output_decode, ARRAY_SIZE(output_decode), "rc")) {
		result->group = (uint16_t)tmp_group;
		result->rc = (uint16_t)tmp_rc;
		result->found = true;
	}

	return ok;
}

static void smp_make_hdr(struct smp_hdr *hdr, size_t len, uint8_t op, uint8_t cmd_id)
{
	*hdr = (struct smp_hdr) {
		.nh_len = sys_cpu_to_be16(len),
		.nh_flags = 0,
		.nh_op = op,
		.nh_group = sys_cpu_to_be16(ZEPHYR_MGMT_GRP_EBPF),
		.nh_seq = 1,
		.nh_id = cmd_id,
		.nh_version = 1,
	};
}

static bool create_load_packet(uint8_t *buffer, uint8_t *output_buffer, uint16_t *buffer_size,
			       uint32_t off, uint32_t total_len, const uint8_t *data,
			       size_t data_len, bool include_total_len, bool include_enable,
			       bool enable_value)
{
	int field_count = 2 + (include_total_len ? 1 : 0) + (include_enable ? 1 : 0);
	bool ok;
	zcbor_state_t zse[ZCBOR_HISTORY_ARRAY_SIZE] = { 0 };

	memset(buffer, 0, ZCBOR_BUFFER_SIZE);
	memset(output_buffer, 0, OUTPUT_BUFFER_SIZE);
	*buffer_size = 0U;

	zcbor_new_encode_state(zse, ARRAY_SIZE(zse), buffer, ZCBOR_BUFFER_SIZE, 0);
	ok = zcbor_map_start_encode(zse, field_count) &&
		zcbor_tstr_put_lit(zse, "off") &&
		zcbor_uint32_put(zse, off);
	if (ok && include_total_len) {
		ok = zcbor_tstr_put_lit(zse, "len") && zcbor_uint32_put(zse, total_len);
	}
	if (ok) {
		ok = zcbor_tstr_put_lit(zse, "data") && zcbor_bstr_encode_ptr(zse, data, data_len);
	}
	if (ok && include_enable) {
		ok = zcbor_tstr_put_lit(zse, "enable") && zcbor_bool_put(zse, enable_value);
	}
	ok = ok && zcbor_map_end_encode(zse, field_count);

	*buffer_size = (uint16_t)(zse->payload_mut - buffer);
	smp_make_hdr((struct smp_hdr *)output_buffer, *buffer_size, MGMT_OP_WRITE,
		     ZEPHYR_MGMT_GRP_EBPF_CMD_LOAD);
	memcpy(output_buffer + sizeof(struct smp_hdr), buffer, *buffer_size);
	*buffer_size += sizeof(struct smp_hdr);

	return ok;
}

static bool create_name_packet(uint8_t *buffer, uint8_t *output_buffer, uint16_t *buffer_size,
			       uint8_t op, uint8_t cmd_id, const char *name)
{
	bool ok;
	zcbor_state_t zse[ZCBOR_HISTORY_ARRAY_SIZE] = { 0 };

	memset(buffer, 0, ZCBOR_BUFFER_SIZE);
	memset(output_buffer, 0, OUTPUT_BUFFER_SIZE);
	*buffer_size = 0U;

	zcbor_new_encode_state(zse, ARRAY_SIZE(zse), buffer, ZCBOR_BUFFER_SIZE, 0);
	ok = zcbor_map_start_encode(zse, 1) &&
		zcbor_tstr_put_lit(zse, "name") &&
		zcbor_tstr_put_term(zse, name, strlen(name)) &&
		zcbor_map_end_encode(zse, 1);

	*buffer_size = (uint16_t)(zse->payload_mut - buffer);
	smp_make_hdr((struct smp_hdr *)output_buffer, *buffer_size, op, cmd_id);
	memcpy(output_buffer + sizeof(struct smp_hdr), buffer, *buffer_size);
	*buffer_size += sizeof(struct smp_hdr);

	return ok;
}

static bool create_dump_packet(uint8_t *buffer, uint8_t *output_buffer, uint16_t *buffer_size,
			       const char *name)
{
	bool ok;
	int field_count = name != NULL ? 1 : 0;
	zcbor_state_t zse[ZCBOR_HISTORY_ARRAY_SIZE] = { 0 };

	memset(buffer, 0, ZCBOR_BUFFER_SIZE);
	memset(output_buffer, 0, OUTPUT_BUFFER_SIZE);
	*buffer_size = 0U;

	zcbor_new_encode_state(zse, ARRAY_SIZE(zse), buffer, ZCBOR_BUFFER_SIZE, 0);
	ok = zcbor_map_start_encode(zse, field_count);
	if (ok && name != NULL) {
		ok = zcbor_tstr_put_lit(zse, "name") &&
			zcbor_tstr_put_term(zse, name, strlen(name));
	}
	ok = ok && zcbor_map_end_encode(zse, field_count);

	*buffer_size = (uint16_t)(zse->payload_mut - buffer);
	smp_make_hdr((struct smp_hdr *)output_buffer, *buffer_size, MGMT_OP_READ,
		     ZEPHYR_MGMT_GRP_EBPF_CMD_DUMP);
	memcpy(output_buffer + sizeof(struct smp_hdr), buffer, *buffer_size);
	*buffer_size += sizeof(struct smp_hdr);

	return ok;
}

static struct net_buf *exchange_request(const uint8_t *packet, uint16_t packet_size)
{
	bool received;

	smp_dummy_enable();
	smp_dummy_clear_state();
	(void)smp_dummy_tx_pkt(packet, packet_size);
	smp_dummy_add_data();
	received = smp_dummy_wait_for_data(SMP_RESPONSE_WAIT_TIME);
	zassert_true(received, "expected mcumgr response");

	return smp_dummy_get_outgoing();
}

static void decode_load_response(struct net_buf *rsp, struct load_response *decoded_rsp)
{
	struct smp_hdr *header = (struct smp_hdr *)rsp->data;
	uint32_t off = 0U;
	size_t decoded = 0U;
	zcbor_state_t zsd[ZCBOR_HISTORY_ARRAY_SIZE] = { 0 };
	struct zcbor_map_decode_key_val decode[] = {
		ZCBOR_MAP_DECODE_KEY_DECODER("off", zcbor_uint32_decode, &off),
		ZCBOR_MAP_DECODE_KEY_DECODER("loaded", zcbor_bool_decode, &decoded_rsp->loaded),
		ZCBOR_MAP_DECODE_KEY_DECODER("enabled", zcbor_bool_decode, &decoded_rsp->enabled),
		ZCBOR_MAP_DECODE_KEY_DECODER("name", zcbor_tstr_decode, &decoded_rsp->name),
		ZCBOR_MAP_DECODE_KEY_DECODER("err", mcumgr_ret_decode, &decoded_rsp->err),
	};
	bool ok;

	zassert_equal(header->nh_op, MGMT_OP_WRITE_RSP, "unexpected mcumgr op");
	zassert_equal(sys_be16_to_cpu(header->nh_group), ZEPHYR_MGMT_GRP_EBPF,
		      "unexpected mcumgr group");
	zassert_equal(header->nh_id, ZEPHYR_MGMT_GRP_EBPF_CMD_LOAD,
		      "unexpected mcumgr id");

	memset(decoded_rsp, 0, sizeof(*decoded_rsp));
	zcbor_new_decode_state(zsd, ARRAY_SIZE(zsd), rsp->data + sizeof(*header),
			       rsp->len - sizeof(*header), 1, NULL, 0);
	ok = zcbor_map_decode_bulk(zsd, decode, ARRAY_SIZE(decode), &decoded) == 0;
	zassert_true(ok, "failed to decode load response");

	if (zcbor_map_decode_bulk_key_found(decode, ARRAY_SIZE(decode), "off")) {
		decoded_rsp->off = off;
		decoded_rsp->off_found = true;
	}
	decoded_rsp->loaded_found = zcbor_map_decode_bulk_key_found(decode, ARRAY_SIZE(decode), "loaded");
	decoded_rsp->enabled_found = zcbor_map_decode_bulk_key_found(decode, ARRAY_SIZE(decode), "enabled");
	decoded_rsp->name_found = zcbor_map_decode_bulk_key_found(decode, ARRAY_SIZE(decode), "name");
}

static void decode_status_response(struct net_buf *rsp, uint8_t expected_id,
				   struct status_response *decoded_rsp)
{
	struct smp_hdr *header = (struct smp_hdr *)rsp->data;
	size_t decoded = 0U;
	zcbor_state_t zsd[ZCBOR_HISTORY_ARRAY_SIZE] = { 0 };
	struct zcbor_map_decode_key_val decode[] = {
		ZCBOR_MAP_DECODE_KEY_DECODER("name", zcbor_tstr_decode, &decoded_rsp->name),
		ZCBOR_MAP_DECODE_KEY_DECODER("loaded", zcbor_bool_decode, &decoded_rsp->loaded),
		ZCBOR_MAP_DECODE_KEY_DECODER("enabled", zcbor_bool_decode, &decoded_rsp->enabled),
		ZCBOR_MAP_DECODE_KEY_DECODER("ttl_ms", zcbor_uint32_decode, &decoded_rsp->ttl_ms),
		ZCBOR_MAP_DECODE_KEY_DECODER("auto_unloaded", zcbor_bool_decode,
					     &decoded_rsp->auto_unloaded),
		ZCBOR_MAP_DECODE_KEY_DECODER("err", mcumgr_ret_decode, &decoded_rsp->err),
	};
	bool ok;

	zassert_equal(header->nh_group, sys_cpu_to_be16(ZEPHYR_MGMT_GRP_EBPF),
		      "unexpected mcumgr group");
	zassert_equal(header->nh_id, expected_id, "unexpected mcumgr id");

	memset(decoded_rsp, 0, sizeof(*decoded_rsp));
	zcbor_new_decode_state(zsd, ARRAY_SIZE(zsd), rsp->data + sizeof(*header),
			       rsp->len - sizeof(*header), 1, NULL, 0);
	ok = zcbor_map_decode_bulk(zsd, decode, ARRAY_SIZE(decode), &decoded) == 0;
	zassert_true(ok, "failed to decode status response");

	decoded_rsp->name_found = zcbor_map_decode_bulk_key_found(decode, ARRAY_SIZE(decode), "name");
	decoded_rsp->loaded_found = zcbor_map_decode_bulk_key_found(decode, ARRAY_SIZE(decode), "loaded");
	decoded_rsp->enabled_found = zcbor_map_decode_bulk_key_found(decode, ARRAY_SIZE(decode), "enabled");
	decoded_rsp->ttl_found = zcbor_map_decode_bulk_key_found(decode, ARRAY_SIZE(decode), "ttl_ms");
	decoded_rsp->auto_unloaded_found =
		zcbor_map_decode_bulk_key_found(decode, ARRAY_SIZE(decode), "auto_unloaded");
}

ZTEST(ebpf_mcumgr, test_signed_loader_image_loads_and_dispatches)
{
	struct ebpf_loader_handle *handle;
	struct ebpf_bundle *bundle;
	struct ebpf_map *map;
	struct ebpf_attach_target target =
		EBPF_ATTACH_TARGET_TRACING(EBPF_TRACING_ATTACH_THREAD_SWITCHED_IN);
	uint32_t key = 0U;
	uint32_t *value;
	uint32_t before_dispatch;
	int ret;

	ret = ebpf_loader_load(signed_probe_bundle, sizeof(signed_probe_bundle), &handle);
	zassert_ok(ret, "signed loader load failed: %d", ret);

	bundle = ebpf_loader_bundle(handle);
	zassert_not_null(bundle, "signed loader should create a bundle");
	map = ebpf_bundle_find_map(bundle, "counter_map");
	zassert_not_null(map, "signed loader should expose runtime map");

	ret = ebpf_loader_enable(handle);
	zassert_ok(ret, "signed loader enable failed: %d", ret);

	value = ebpf_map_lookup_elem(map, &key);
	zassert_not_null(value, "signed loader map lookup failed");
	before_dispatch = *value;
	ebpf_attach_target_dispatch(&target, &before_dispatch, sizeof(before_dispatch));
	value = ebpf_map_lookup_elem(map, &key);
	zassert_equal(*value, before_dispatch + 1U,
		      "signed runtime bundle should increment the counter map");

	ret = ebpf_loader_unload(handle);
	zassert_ok(ret, "signed loader unload failed: %d", ret);
}

ZTEST(ebpf_mcumgr, test_signed_loader_image_rejects_tamper)
{
	uint8_t tampered[sizeof(signed_probe_bundle)];
	const struct ebpf_loader_image_header *header =
		(const struct ebpf_loader_image_header *)signed_probe_bundle;
	struct ebpf_loader_handle *handle = NULL;
	int ret;

	memcpy(tampered, signed_probe_bundle, sizeof(tampered));
	tampered[header->auth_offset - 1U] ^= 0x01U;

	ret = ebpf_loader_load(tampered, sizeof(tampered), &handle);
	zassert_equal(ret, -EBADMSG, "tampered signed image should fail verification, got %d", ret);
	zassert_is_null(handle, "tampered image must not create a runtime handle");
}

ZTEST(ebpf_mcumgr, test_mcumgr_signed_load_enable_disable_unload_cycle)
{
	uint8_t buffer[ZCBOR_BUFFER_SIZE];
	uint8_t output_buffer[OUTPUT_BUFFER_SIZE];
	uint16_t buffer_size;
	struct load_response load_rsp;
	struct status_response status_rsp;
	bool ok;

	ok = create_load_packet(buffer, output_buffer, &buffer_size, 0U,
				sizeof(signed_probe_bundle), signed_probe_bundle,
				LOAD_SPLIT_OFFSET, true, true, true);
	zassert_true(ok, "failed to create first load packet");
	nb = exchange_request(output_buffer, buffer_size);
	decode_load_response(nb, &load_rsp);
	zassert_true(load_rsp.off_found, "expected first load response offset");
	zassert_equal(load_rsp.off, LOAD_SPLIT_OFFSET, "unexpected first load offset");
	zassert_false(load_rsp.loaded_found, "partial load must not report completion");
	net_buf_unref(nb);
	nb = NULL;

	ok = create_load_packet(buffer, output_buffer, &buffer_size, LOAD_SPLIT_OFFSET,
				0U, signed_probe_bundle + LOAD_SPLIT_OFFSET,
				sizeof(signed_probe_bundle) - LOAD_SPLIT_OFFSET,
				false, false, false);
	zassert_true(ok, "failed to create second load packet");
	nb = exchange_request(output_buffer, buffer_size);
	decode_load_response(nb, &load_rsp);
	zassert_true(load_rsp.off_found, "expected final load response offset");
	zassert_equal(load_rsp.off, sizeof(signed_probe_bundle), "unexpected final load offset");
	zassert_true(load_rsp.loaded_found && load_rsp.loaded, "load response should report loaded=true");
	zassert_true(load_rsp.enabled_found && load_rsp.enabled,
		     "load response should report enabled=true");
	zassert_true(load_rsp.name_found, "load response should report the bundle name");
	zassert_equal(load_rsp.name.len, strlen("probe"), "unexpected load response name length");
	zassert_mem_equal(load_rsp.name.value, "probe", strlen("probe"),
			  "unexpected loaded bundle name");
	net_buf_unref(nb);
	nb = NULL;

	ok = create_dump_packet(buffer, output_buffer, &buffer_size, "probe");
	zassert_true(ok, "failed to create dump packet");
	nb = exchange_request(output_buffer, buffer_size);
	decode_status_response(nb, ZEPHYR_MGMT_GRP_EBPF_CMD_DUMP, &status_rsp);
	zassert_true(status_rsp.name_found, "dump should return bundle name");
	zassert_true(status_rsp.loaded_found && status_rsp.loaded, "dump should report loaded=true");
	zassert_true(status_rsp.enabled_found && status_rsp.enabled, "dump should report enabled=true");
	zassert_true(status_rsp.ttl_found && status_rsp.ttl_ms == 15000U,
		     "dump should preserve TTL");
	zassert_true(status_rsp.auto_unloaded_found && !status_rsp.auto_unloaded,
		     "dump should report auto_unloaded=false");
	net_buf_unref(nb);
	nb = NULL;

	ok = create_name_packet(buffer, output_buffer, &buffer_size, MGMT_OP_WRITE,
				ZEPHYR_MGMT_GRP_EBPF_CMD_DISABLE, "probe");
	zassert_true(ok, "failed to create disable packet");
	nb = exchange_request(output_buffer, buffer_size);
	decode_status_response(nb, ZEPHYR_MGMT_GRP_EBPF_CMD_DISABLE, &status_rsp);
	zassert_true(status_rsp.enabled_found && !status_rsp.enabled,
		     "disable response should report enabled=false");
	net_buf_unref(nb);
	nb = NULL;

	ok = create_name_packet(buffer, output_buffer, &buffer_size, MGMT_OP_WRITE,
				ZEPHYR_MGMT_GRP_EBPF_CMD_ENABLE, "probe");
	zassert_true(ok, "failed to create enable packet");
	nb = exchange_request(output_buffer, buffer_size);
	decode_status_response(nb, ZEPHYR_MGMT_GRP_EBPF_CMD_ENABLE, &status_rsp);
	zassert_true(status_rsp.enabled_found && status_rsp.enabled,
		     "enable response should report enabled=true");
	net_buf_unref(nb);
	nb = NULL;

	ok = create_name_packet(buffer, output_buffer, &buffer_size, MGMT_OP_WRITE,
				ZEPHYR_MGMT_GRP_EBPF_CMD_UNLOAD, "probe");
	zassert_true(ok, "failed to create unload packet");
	nb = exchange_request(output_buffer, buffer_size);
	decode_status_response(nb, ZEPHYR_MGMT_GRP_EBPF_CMD_UNLOAD, &status_rsp);
	zassert_true(status_rsp.name_found, "unload response should report the bundle name");
	net_buf_unref(nb);
	nb = NULL;

	ok = create_dump_packet(buffer, output_buffer, &buffer_size, "probe");
	zassert_true(ok, "failed to create final dump packet");
	nb = exchange_request(output_buffer, buffer_size);
	decode_status_response(nb, ZEPHYR_MGMT_GRP_EBPF_CMD_DUMP, &status_rsp);
	zassert_true(status_rsp.err.found, "missing final dump error payload");
	zassert_equal(status_rsp.err.group, ZEPHYR_MGMT_GRP_EBPF,
		      "unexpected final dump error group");
	zassert_equal(status_rsp.err.rc, ZEPHYR_EBPF_MGMT_ERR_NOT_FOUND,
		      "expected not-found after unload");
}

ZTEST(ebpf_mcumgr, test_mcumgr_rejects_tampered_signed_bundle)
{
	uint8_t buffer[ZCBOR_BUFFER_SIZE];
	uint8_t output_buffer[OUTPUT_BUFFER_SIZE];
	uint8_t tampered[sizeof(signed_probe_bundle)];
	uint16_t buffer_size;
	struct load_response load_rsp;
	bool ok;

	memcpy(tampered, signed_probe_bundle, sizeof(tampered));
	tampered[100] ^= 0x01U;

	ok = create_load_packet(buffer, output_buffer, &buffer_size, 0U,
				sizeof(tampered), tampered, LOAD_SPLIT_OFFSET, true, true, true);
	zassert_true(ok, "failed to create first tampered load packet");
	nb = exchange_request(output_buffer, buffer_size);
	decode_load_response(nb, &load_rsp);
	zassert_true(load_rsp.off_found, "expected first tampered load response offset");
	zassert_equal(load_rsp.off, LOAD_SPLIT_OFFSET, "unexpected first tampered load offset");
	net_buf_unref(nb);
	nb = NULL;

	ok = create_load_packet(buffer, output_buffer, &buffer_size, LOAD_SPLIT_OFFSET,
				0U, tampered + LOAD_SPLIT_OFFSET,
				sizeof(tampered) - LOAD_SPLIT_OFFSET, false, false, false);
	zassert_true(ok, "failed to create final tampered load packet");
	nb = exchange_request(output_buffer, buffer_size);
	decode_load_response(nb, &load_rsp);
	zassert_true(load_rsp.err.found, "tampered load should return a group error");
	zassert_equal(load_rsp.err.group, ZEPHYR_MGMT_GRP_EBPF,
		      "unexpected tampered load error group");
	zassert_equal(load_rsp.err.rc, ZEPHYR_EBPF_MGMT_ERR_VERIFY_FAILED,
		      "tampered load should fail signature verification");
}

ZTEST_SUITE(ebpf_mcumgr, NULL, NULL, NULL, cleanup_test, NULL);