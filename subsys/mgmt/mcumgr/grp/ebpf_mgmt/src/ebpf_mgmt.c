/*
 * Copyright (c) 2026 NXP
 *
 * SPDX-License-Identifier: Apache-2.0
 */

#include <string.h>

#include <zcbor_common.h>
#include <zcbor_decode.h>
#include <zcbor_encode.h>

#include <mgmt/mcumgr/util/zcbor_bulk.h>

#include <zephyr/kernel.h>
#include <zephyr/logging/log.h>

#include <zephyr/ebpf/ebpf_loader.h>
#include <zephyr/mgmt/mcumgr/grp/ebpf_mgmt/ebpf_mgmt.h>
#include <zephyr/mgmt/mcumgr/mgmt/handlers.h>
#include <zephyr/mgmt/mcumgr/mgmt/mgmt.h>

LOG_MODULE_REGISTER(mcumgr_ebpf_grp, CONFIG_MCUMGR_GRP_EBPF_LOG_LEVEL);

struct ebpf_mgmt_upload_state {
	uint8_t *image;
	size_t image_size;
	size_t received;
	bool auto_enable;
};

struct ebpf_mgmt_dump_ctx {
	zcbor_state_t *zse;
	const char *filter_name;
	size_t count;
	bool ok;
};

static struct ebpf_mgmt_upload_state ebpf_upload_state;
static K_MUTEX_DEFINE(ebpf_upload_lock);

static void ebpf_mgmt_reset_upload_locked(void)
{
	k_free(ebpf_upload_state.image);
	ebpf_upload_state.image = NULL;
	ebpf_upload_state.image_size = 0U;
	ebpf_upload_state.received = 0U;
	ebpf_upload_state.auto_enable = false;
}

static int ebpf_mgmt_strdup_zcbor(const struct zcbor_string *value, char **out)
{
	char *copy;

	if (value == NULL || out == NULL || value->value == NULL || value->len == 0U) {
		return -EINVAL;
	}

	copy = k_malloc(value->len + 1U);
	if (copy == NULL) {
		return -ENOMEM;
	}

	memcpy(copy, value->value, value->len);
	copy[value->len] = '\0';
	*out = copy;

	return 0;
}

static uint16_t ebpf_mgmt_map_loader_error(int rc)
{
	switch (rc) {
	case 0:
		return ZEPHYR_EBPF_MGMT_ERR_OK;
	case -EBADMSG:
		return ZEPHYR_EBPF_MGMT_ERR_VERIFY_FAILED;
	case -EALREADY:
		return ZEPHYR_EBPF_MGMT_ERR_NAME_CONFLICT;
	case -ENOENT:
		return ZEPHYR_EBPF_MGMT_ERR_NOT_FOUND;
	case -ENOMEM:
		return ZEPHYR_EBPF_MGMT_ERR_NO_MEMORY;
	case -EBUSY:
		return ZEPHYR_EBPF_MGMT_ERR_BUSY;
	case -EMSGSIZE:
		return ZEPHYR_EBPF_MGMT_ERR_DATA_TOO_LARGE;
	case -ENOTSUP:
		return ZEPHYR_EBPF_MGMT_ERR_UNSUPPORTED;
	case -EINVAL:
		return ZEPHYR_EBPF_MGMT_ERR_MALFORMED;
	default:
		return ZEPHYR_EBPF_MGMT_ERR_LOAD_FAILED;
	}
}

#ifdef CONFIG_MCUMGR_SMP_SUPPORT_ORIGINAL_PROTOCOL
static int ebpf_mgmt_translate_error_code(uint16_t ret)
{
	switch (ret) {
	case ZEPHYR_EBPF_MGMT_ERR_MALFORMED:
	case ZEPHYR_EBPF_MGMT_ERR_UPLOAD_OFFSET:
	case ZEPHYR_EBPF_MGMT_ERR_UPLOAD_TOO_LARGE:
		return MGMT_ERR_EINVAL;
	case ZEPHYR_EBPF_MGMT_ERR_NOT_FOUND:
		return MGMT_ERR_ENOENT;
	case ZEPHYR_EBPF_MGMT_ERR_VERIFY_FAILED:
		return MGMT_ERR_ECORRUPT;
	case ZEPHYR_EBPF_MGMT_ERR_NAME_CONFLICT:
		return MGMT_ERR_EBADSTATE;
	case ZEPHYR_EBPF_MGMT_ERR_NO_MEMORY:
		return MGMT_ERR_ENOMEM;
	case ZEPHYR_EBPF_MGMT_ERR_BUSY:
	case ZEPHYR_EBPF_MGMT_ERR_UPLOAD_IN_PROGRESS:
		return MGMT_ERR_EBUSY;
	case ZEPHYR_EBPF_MGMT_ERR_DATA_TOO_LARGE:
		return MGMT_ERR_EMSGSIZE;
	case ZEPHYR_EBPF_MGMT_ERR_UNSUPPORTED:
		return MGMT_ERR_ENOTSUP;
	default:
		return MGMT_ERR_EUNKNOWN;
	}
}
#endif

static bool ebpf_mgmt_name_matches(const struct ebpf_loader_status *status,
					 const char *filter_name)
{
	if (filter_name == NULL) {
		return true;
	}

	return strcmp(status->name, filter_name) == 0;
}

static bool ebpf_mgmt_count_cb(const struct ebpf_loader_status *status, void *user_data)
{
	struct ebpf_mgmt_dump_ctx *ctx = user_data;

	if (ebpf_mgmt_name_matches(status, ctx->filter_name)) {
		ctx->count++;
	}

	return true;
}

static bool ebpf_mgmt_encode_dump_cb(const struct ebpf_loader_status *status, void *user_data)
{
	struct ebpf_mgmt_dump_ctx *ctx = user_data;

	if (!ebpf_mgmt_name_matches(status, ctx->filter_name)) {
		return true;
	}

	ctx->ok = ctx->ok &&
		zcbor_map_start_encode(ctx->zse, 5) &&
		zcbor_tstr_put_lit(ctx->zse, "name") &&
		zcbor_tstr_put_term(ctx->zse, status->name, strlen(status->name)) &&
		zcbor_tstr_put_lit(ctx->zse, "loaded") &&
		zcbor_bool_put(ctx->zse, status->loaded) &&
		zcbor_tstr_put_lit(ctx->zse, "enabled") &&
		zcbor_bool_put(ctx->zse, status->enabled) &&
		zcbor_tstr_put_lit(ctx->zse, "ttl_ms") &&
		zcbor_uint32_put(ctx->zse, status->ttl_ms) &&
		zcbor_tstr_put_lit(ctx->zse, "auto_unloaded") &&
		zcbor_bool_put(ctx->zse, status->auto_unloaded) &&
		zcbor_map_end_encode(ctx->zse, 5);

	return ctx->ok;
}

static int ebpf_mgmt_load(struct smp_streamer *ctxt)
{
	zcbor_state_t *zse = ctxt->writer->zs;
	zcbor_state_t *zsd = ctxt->reader->zs;
	uint32_t off = 0U;
	uint32_t total_len = 0U;
	bool auto_enable = false;
	struct zcbor_string data = { 0 };
	struct zcbor_map_decode_key_val load_decode[] = {
		ZCBOR_MAP_DECODE_KEY_DECODER("off", zcbor_uint32_decode, &off),
		ZCBOR_MAP_DECODE_KEY_DECODER("len", zcbor_uint32_decode, &total_len),
		ZCBOR_MAP_DECODE_KEY_DECODER("data", zcbor_bstr_decode, &data),
		ZCBOR_MAP_DECODE_KEY_DECODER("enable", zcbor_bool_decode, &auto_enable),
	};
	struct ebpf_loader_handle *handle = NULL;
	uint8_t *image = NULL;
	uint32_t next_off;
	size_t decoded = 0U;
	bool ok;
	int rc;

	ok = zcbor_map_decode_bulk(zsd, load_decode, ARRAY_SIZE(load_decode), &decoded) == 0;
	if (!ok ||
	    !zcbor_map_decode_bulk_key_found(load_decode, ARRAY_SIZE(load_decode), "off") ||
	    !zcbor_map_decode_bulk_key_found(load_decode, ARRAY_SIZE(load_decode), "data") ||
	    (off == 0U &&
	     !zcbor_map_decode_bulk_key_found(load_decode, ARRAY_SIZE(load_decode), "len")) ||
	    data.len == 0U) {
		ok = smp_add_cmd_err(zse, ZEPHYR_MGMT_GRP_EBPF,
				     ZEPHYR_EBPF_MGMT_ERR_MALFORMED);
		return MGMT_RETURN_CHECK(ok);
	}

	k_mutex_lock(&ebpf_upload_lock, K_FOREVER);
	if (off == 0U) {
		ebpf_mgmt_reset_upload_locked();
		if (total_len == 0U || total_len > CONFIG_MCUMGR_GRP_EBPF_UPLOAD_MAX_SIZE ||
		    data.len > total_len) {
			k_mutex_unlock(&ebpf_upload_lock);
			ok = smp_add_cmd_err(zse, ZEPHYR_MGMT_GRP_EBPF,
					     ZEPHYR_EBPF_MGMT_ERR_UPLOAD_TOO_LARGE);
			return MGMT_RETURN_CHECK(ok);
		}

		ebpf_upload_state.image = k_malloc(total_len);
		if (ebpf_upload_state.image == NULL) {
			k_mutex_unlock(&ebpf_upload_lock);
			ok = smp_add_cmd_err(zse, ZEPHYR_MGMT_GRP_EBPF,
					     ZEPHYR_EBPF_MGMT_ERR_NO_MEMORY);
			return MGMT_RETURN_CHECK(ok);
		}

		ebpf_upload_state.image_size = total_len;
		ebpf_upload_state.received = 0U;
		ebpf_upload_state.auto_enable =
			zcbor_map_decode_bulk_key_found(load_decode, ARRAY_SIZE(load_decode), "enable") &&
			auto_enable;
	} else if (ebpf_upload_state.image == NULL || off != ebpf_upload_state.received) {
		k_mutex_unlock(&ebpf_upload_lock);
		ok = smp_add_cmd_err(zse, ZEPHYR_MGMT_GRP_EBPF,
				     ZEPHYR_EBPF_MGMT_ERR_UPLOAD_OFFSET);
		return MGMT_RETURN_CHECK(ok);
	}

	if ((size_t)off + data.len > ebpf_upload_state.image_size) {
		k_mutex_unlock(&ebpf_upload_lock);
		ok = smp_add_cmd_err(zse, ZEPHYR_MGMT_GRP_EBPF,
				     ZEPHYR_EBPF_MGMT_ERR_MALFORMED);
		return MGMT_RETURN_CHECK(ok);
	}

	memcpy(ebpf_upload_state.image + off, data.value, data.len);
	ebpf_upload_state.received = (size_t)off + data.len;
	next_off = (uint32_t)ebpf_upload_state.received;

	if (ebpf_upload_state.received == ebpf_upload_state.image_size) {
		image = ebpf_upload_state.image;
		ebpf_upload_state.image = NULL;
		total_len = (uint32_t)ebpf_upload_state.image_size;
		auto_enable = ebpf_upload_state.auto_enable;
		ebpf_upload_state.image_size = 0U;
		ebpf_upload_state.received = 0U;
		ebpf_upload_state.auto_enable = false;
	}
	k_mutex_unlock(&ebpf_upload_lock);

	if (image != NULL) {
		rc = ebpf_loader_load(image, total_len, &handle);
		k_free(image);
		if (rc == 0 && auto_enable) {
			rc = ebpf_loader_enable(handle);
			if (rc != 0) {
				(void)ebpf_loader_unload(handle);
				handle = NULL;
			}
		}
		if (rc != 0) {
			ok = smp_add_cmd_err(zse, ZEPHYR_MGMT_GRP_EBPF,
					     ebpf_mgmt_map_loader_error(rc));
			return MGMT_RETURN_CHECK(ok);
		}

		ok = zcbor_tstr_put_lit(zse, "off") &&
			zcbor_uint32_put(zse, next_off) &&
			zcbor_tstr_put_lit(zse, "loaded") &&
			zcbor_bool_put(zse, true) &&
			zcbor_tstr_put_lit(zse, "enabled") &&
			zcbor_bool_put(zse, auto_enable) &&
			zcbor_tstr_put_lit(zse, "name") &&
			zcbor_tstr_put_term(zse, ebpf_loader_name(handle),
					    strlen(ebpf_loader_name(handle)));
		return MGMT_RETURN_CHECK(ok);
	}

	ok = zcbor_tstr_put_lit(zse, "off") && zcbor_uint32_put(zse, next_off);
	return MGMT_RETURN_CHECK(ok);
}

static int ebpf_mgmt_decode_name(struct smp_streamer *ctxt, char **name_out)
{
	zcbor_state_t *zsd = ctxt->reader->zs;
	struct zcbor_string name = { 0 };
	struct zcbor_map_decode_key_val decode[] = {
		ZCBOR_MAP_DECODE_KEY_DECODER("name", zcbor_tstr_decode, &name),
	};
	size_t decoded = 0U;
	bool ok;

	ok = zcbor_map_decode_bulk(zsd, decode, ARRAY_SIZE(decode), &decoded) == 0;
	if (!ok || !zcbor_map_decode_bulk_key_found(decode, ARRAY_SIZE(decode), "name")) {
		return -EINVAL;
	}

	return ebpf_mgmt_strdup_zcbor(&name, name_out);
}

static int ebpf_mgmt_enable(struct smp_streamer *ctxt)
{
	zcbor_state_t *zse = ctxt->writer->zs;
	char *name = NULL;
	bool ok;
	int rc;

	rc = ebpf_mgmt_decode_name(ctxt, &name);
	if (rc != 0) {
		ok = smp_add_cmd_err(zse, ZEPHYR_MGMT_GRP_EBPF,
				     ZEPHYR_EBPF_MGMT_ERR_MALFORMED);
		return MGMT_RETURN_CHECK(ok);
	}

	rc = ebpf_loader_enable_by_name(name);
	if (rc != 0) {
		k_free(name);
		ok = smp_add_cmd_err(zse, ZEPHYR_MGMT_GRP_EBPF,
				     ebpf_mgmt_map_loader_error(rc));
		return MGMT_RETURN_CHECK(ok);
	}

	ok = zcbor_tstr_put_lit(zse, "name") &&
		zcbor_tstr_put_term(zse, name, strlen(name)) &&
		zcbor_tstr_put_lit(zse, "enabled") &&
		zcbor_bool_put(zse, true);
	k_free(name);

	return MGMT_RETURN_CHECK(ok);
}

static int ebpf_mgmt_disable(struct smp_streamer *ctxt)
{
	zcbor_state_t *zse = ctxt->writer->zs;
	char *name = NULL;
	bool ok;
	int rc;

	rc = ebpf_mgmt_decode_name(ctxt, &name);
	if (rc != 0) {
		ok = smp_add_cmd_err(zse, ZEPHYR_MGMT_GRP_EBPF,
				     ZEPHYR_EBPF_MGMT_ERR_MALFORMED);
		return MGMT_RETURN_CHECK(ok);
	}

	rc = ebpf_loader_disable_by_name(name);
	if (rc != 0) {
		k_free(name);
		ok = smp_add_cmd_err(zse, ZEPHYR_MGMT_GRP_EBPF,
				     ebpf_mgmt_map_loader_error(rc));
		return MGMT_RETURN_CHECK(ok);
	}

	ok = zcbor_tstr_put_lit(zse, "name") &&
		zcbor_tstr_put_term(zse, name, strlen(name)) &&
		zcbor_tstr_put_lit(zse, "enabled") &&
		zcbor_bool_put(zse, false);
	k_free(name);

	return MGMT_RETURN_CHECK(ok);
}

static int ebpf_mgmt_unload(struct smp_streamer *ctxt)
{
	zcbor_state_t *zse = ctxt->writer->zs;
	char *name = NULL;
	bool ok;
	int rc;

	rc = ebpf_mgmt_decode_name(ctxt, &name);
	if (rc != 0) {
		ok = smp_add_cmd_err(zse, ZEPHYR_MGMT_GRP_EBPF,
				     ZEPHYR_EBPF_MGMT_ERR_MALFORMED);
		return MGMT_RETURN_CHECK(ok);
	}

	rc = ebpf_loader_unload_by_name(name);
	if (rc != 0) {
		k_free(name);
		ok = smp_add_cmd_err(zse, ZEPHYR_MGMT_GRP_EBPF,
				     ebpf_mgmt_map_loader_error(rc));
		return MGMT_RETURN_CHECK(ok);
	}

	ok = zcbor_tstr_put_lit(zse, "name") &&
		zcbor_tstr_put_term(zse, name, strlen(name)) &&
		zcbor_tstr_put_lit(zse, "unloaded") &&
		zcbor_bool_put(zse, true);
	k_free(name);

	return MGMT_RETURN_CHECK(ok);
}

static int ebpf_mgmt_dump(struct smp_streamer *ctxt)
{
	zcbor_state_t *zse = ctxt->writer->zs;
	zcbor_state_t *zsd = ctxt->reader->zs;
	struct zcbor_string name = { 0 };
	struct ebpf_loader_status status;
	struct zcbor_map_decode_key_val decode[] = {
		ZCBOR_MAP_DECODE_KEY_DECODER("name", zcbor_tstr_decode, &name),
	};
	struct ebpf_mgmt_dump_ctx ctx = {
		.zse = zse,
		.filter_name = NULL,
		.count = 0U,
		.ok = true,
	};
	char *filter_name = NULL;
	size_t decoded = 0U;
	bool ok;
	int rc;

	ok = zcbor_map_decode_bulk(zsd, decode, ARRAY_SIZE(decode), &decoded) == 0;
	if (!ok) {
		ok = smp_add_cmd_err(zse, ZEPHYR_MGMT_GRP_EBPF,
				     ZEPHYR_EBPF_MGMT_ERR_MALFORMED);
		return MGMT_RETURN_CHECK(ok);
	}

	if (zcbor_map_decode_bulk_key_found(decode, ARRAY_SIZE(decode), "name")) {
		rc = ebpf_mgmt_strdup_zcbor(&name, &filter_name);
		if (rc != 0) {
			ok = smp_add_cmd_err(zse, ZEPHYR_MGMT_GRP_EBPF,
					     ZEPHYR_EBPF_MGMT_ERR_NO_MEMORY);
			return MGMT_RETURN_CHECK(ok);
		}

		rc = ebpf_loader_status_by_name(filter_name, &status);
		if (rc != 0) {
			k_free(filter_name);
			ok = smp_add_cmd_err(zse, ZEPHYR_MGMT_GRP_EBPF,
					     ebpf_mgmt_map_loader_error(rc));
			return MGMT_RETURN_CHECK(ok);
		}

		ok = zcbor_tstr_put_lit(zse, "name") &&
			zcbor_tstr_put_term(zse, status.name, strlen(status.name)) &&
			zcbor_tstr_put_lit(zse, "loaded") &&
			zcbor_bool_put(zse, status.loaded) &&
			zcbor_tstr_put_lit(zse, "enabled") &&
			zcbor_bool_put(zse, status.enabled) &&
			zcbor_tstr_put_lit(zse, "ttl_ms") &&
			zcbor_uint32_put(zse, status.ttl_ms) &&
			zcbor_tstr_put_lit(zse, "auto_unloaded") &&
			zcbor_bool_put(zse, status.auto_unloaded);
		k_free(filter_name);

		return MGMT_RETURN_CHECK(ok);
	}

	ebpf_loader_foreach(ebpf_mgmt_count_cb, &ctx);

	ctx.ok = zcbor_tstr_put_lit(zse, "bundles") &&
		zcbor_list_start_encode(zse, ctx.count);
	if (ctx.ok) {
		ebpf_loader_foreach(ebpf_mgmt_encode_dump_cb, &ctx);
	}
	ctx.ok = ctx.ok && zcbor_list_end_encode(zse, ctx.count);

	return MGMT_RETURN_CHECK(ctx.ok);
}

static int ebpf_mgmt_map_read(struct smp_streamer *ctxt)
{
	zcbor_state_t *zse = ctxt->writer->zs;
	zcbor_state_t *zsd = ctxt->reader->zs;
	struct zcbor_string bundle_name = { 0 };
	struct zcbor_string map_name = { 0 };
	struct zcbor_string key = { 0 };
	struct zcbor_map_decode_key_val decode[] = {
		ZCBOR_MAP_DECODE_KEY_DECODER("name", zcbor_tstr_decode, &bundle_name),
		ZCBOR_MAP_DECODE_KEY_DECODER("map", zcbor_tstr_decode, &map_name),
		ZCBOR_MAP_DECODE_KEY_DECODER("key", zcbor_bstr_decode, &key),
	};
	struct ebpf_loader_map_info info;
	char *bundle_name_copy = NULL;
	char *map_name_copy = NULL;
	uint8_t *key_copy = NULL;
	uint8_t *value_copy = NULL;
	size_t decoded = 0U;
	bool ok;
	int rc;

	ok = zcbor_map_decode_bulk(zsd, decode, ARRAY_SIZE(decode), &decoded) == 0;
	if (!ok ||
	    !zcbor_map_decode_bulk_key_found(decode, ARRAY_SIZE(decode), "name") ||
	    !zcbor_map_decode_bulk_key_found(decode, ARRAY_SIZE(decode), "map") ||
	    !zcbor_map_decode_bulk_key_found(decode, ARRAY_SIZE(decode), "key")) {
		ok = smp_add_cmd_err(zse, ZEPHYR_MGMT_GRP_EBPF,
				     ZEPHYR_EBPF_MGMT_ERR_MALFORMED);
		return MGMT_RETURN_CHECK(ok);
	}

	rc = ebpf_mgmt_strdup_zcbor(&bundle_name, &bundle_name_copy);
	if (rc == 0) {
		rc = ebpf_mgmt_strdup_zcbor(&map_name, &map_name_copy);
	}
	if (rc != 0) {
		k_free(bundle_name_copy);
		k_free(map_name_copy);
		ok = smp_add_cmd_err(zse, ZEPHYR_MGMT_GRP_EBPF,
				     ZEPHYR_EBPF_MGMT_ERR_NO_MEMORY);
		return MGMT_RETURN_CHECK(ok);
	}

	rc = ebpf_loader_map_info_by_name(bundle_name_copy, map_name_copy, &info);
	if (rc != 0) {
		k_free(bundle_name_copy);
		k_free(map_name_copy);
		ok = smp_add_cmd_err(zse, ZEPHYR_MGMT_GRP_EBPF,
				     ebpf_mgmt_map_loader_error(rc));
		return MGMT_RETURN_CHECK(ok);
	}

	if (key.len != info.key_size ||
	    info.value_size > CONFIG_MCUMGR_GRP_EBPF_MAP_READ_MAX_SIZE) {
		k_free(bundle_name_copy);
		k_free(map_name_copy);
		ok = smp_add_cmd_err(zse, ZEPHYR_MGMT_GRP_EBPF,
				     key.len != info.key_size ?
				     ZEPHYR_EBPF_MGMT_ERR_MALFORMED :
				     ZEPHYR_EBPF_MGMT_ERR_DATA_TOO_LARGE);
		return MGMT_RETURN_CHECK(ok);
	}

	key_copy = k_malloc(info.key_size);
	value_copy = k_malloc(info.value_size);
	if (key_copy == NULL || value_copy == NULL) {
		k_free(bundle_name_copy);
		k_free(map_name_copy);
		k_free(key_copy);
		k_free(value_copy);
		ok = smp_add_cmd_err(zse, ZEPHYR_MGMT_GRP_EBPF,
				     ZEPHYR_EBPF_MGMT_ERR_NO_MEMORY);
		return MGMT_RETURN_CHECK(ok);
	}

	memcpy(key_copy, key.value, key.len);
	rc = ebpf_loader_map_lookup_copy_by_name(bundle_name_copy, map_name_copy,
							 key_copy, value_copy,
							 info.value_size);
	if (rc != 0) {
		k_free(bundle_name_copy);
		k_free(map_name_copy);
		k_free(key_copy);
		k_free(value_copy);
		ok = smp_add_cmd_err(zse, ZEPHYR_MGMT_GRP_EBPF,
				     ebpf_mgmt_map_loader_error(rc));
		return MGMT_RETURN_CHECK(ok);
	}

	ok = zcbor_tstr_put_lit(zse, "name") &&
		zcbor_tstr_put_term(zse, bundle_name_copy, strlen(bundle_name_copy)) &&
		zcbor_tstr_put_lit(zse, "map") &&
		zcbor_tstr_put_term(zse, map_name_copy, strlen(map_name_copy)) &&
		zcbor_tstr_put_lit(zse, "type") &&
		zcbor_uint32_put(zse, info.type) &&
		zcbor_tstr_put_lit(zse, "key_size") &&
		zcbor_uint32_put(zse, info.key_size) &&
		zcbor_tstr_put_lit(zse, "value_size") &&
		zcbor_uint32_put(zse, info.value_size) &&
		zcbor_tstr_put_lit(zse, "value") &&
		zcbor_bstr_encode_ptr(zse, (const char *)value_copy, info.value_size);

	k_free(bundle_name_copy);
	k_free(map_name_copy);
	k_free(key_copy);
	k_free(value_copy);

	return MGMT_RETURN_CHECK(ok);
}

static const struct mgmt_handler ebpf_mgmt_handlers[] = {
	[ZEPHYR_MGMT_GRP_EBPF_CMD_LOAD] = {
		.mh_read = NULL,
		.mh_write = ebpf_mgmt_load,
	},
	[ZEPHYR_MGMT_GRP_EBPF_CMD_ENABLE] = {
		.mh_read = NULL,
		.mh_write = ebpf_mgmt_enable,
	},
	[ZEPHYR_MGMT_GRP_EBPF_CMD_DISABLE] = {
		.mh_read = NULL,
		.mh_write = ebpf_mgmt_disable,
	},
	[ZEPHYR_MGMT_GRP_EBPF_CMD_UNLOAD] = {
		.mh_read = NULL,
		.mh_write = ebpf_mgmt_unload,
	},
	[ZEPHYR_MGMT_GRP_EBPF_CMD_DUMP] = {
		.mh_read = ebpf_mgmt_dump,
		.mh_write = NULL,
	},
	[ZEPHYR_MGMT_GRP_EBPF_CMD_MAP_READ] = {
		.mh_read = ebpf_mgmt_map_read,
		.mh_write = NULL,
	},
};

static struct mgmt_group ebpf_mgmt_group = {
	.mg_handlers = ebpf_mgmt_handlers,
	.mg_handlers_count = ARRAY_SIZE(ebpf_mgmt_handlers),
	.mg_group_id = ZEPHYR_MGMT_GRP_EBPF,
#ifdef CONFIG_MCUMGR_SMP_SUPPORT_ORIGINAL_PROTOCOL
	.mg_translate_error = ebpf_mgmt_translate_error_code,
#endif
#ifdef CONFIG_MCUMGR_GRP_ENUM_DETAILS_NAME
	.mg_group_name = "zephyr ebpf mgmt",
#endif
};

static void ebpf_mgmt_init(void)
{
	mgmt_register_group(&ebpf_mgmt_group);
}

MCUMGR_HANDLER_DEFINE(zephyr_ebpf_mgmt, ebpf_mgmt_init);