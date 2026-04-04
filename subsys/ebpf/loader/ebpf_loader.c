/*
 * SPDX-FileCopyrightText: Copyright 2026 NXP
 *
 * SPDX-License-Identifier: Apache-2.0
 */

#include <string.h>
#include <zephyr/kernel.h>
#include <zephyr/sys/atomic.h>
#include <zephyr/sys/crc.h>
#include <zephyr/sys/slist.h>
#include <zephyr/sys/util.h>

#if defined(CONFIG_EBPF_LOADER_AUTH_ECDSA_P256)
#include <psa/crypto.h>
#endif

#include "ebpf_loader_internal.h"
#include "../bundle/ebpf_bundle_internal.h"

enum ebpf_loader_flag {
	EBPF_LOADER_FLAG_ENABLED = 0,
	EBPF_LOADER_FLAG_TTL_EXPIRED,
	EBPF_LOADER_FLAG_AUTO_UNLOADED,
};

struct ebpf_loader_handle {
	struct k_mutex lock;
	sys_snode_t registry_node;
	struct k_timer ttl_timer;
	struct ebpf_bundle *bundle;
	char *owned_name;
	uint32_t ttl_ms;
	atomic_t flags;
};

static sys_slist_t ebpf_loader_registry;
static K_MUTEX_DEFINE(ebpf_loader_registry_lock);

#if defined(CONFIG_EBPF_LOADER_AUTH_ECDSA_P256)
BUILD_ASSERT(sizeof(CONFIG_EBPF_LOADER_ECDSA_P256_PUBKEY_HEX) == (65U * 2U) + 1U,
	     "CONFIG_EBPF_LOADER_ECDSA_P256_PUBKEY_HEX must contain a 65-byte SEC1 public key in hex");
#endif

static void ebpf_loader_ttl_work_handler(struct k_work *work);
static K_WORK_DEFINE(ebpf_loader_ttl_work, ebpf_loader_ttl_work_handler);

/* Duplicate the bundle name so the loader handle owns stable storage. */
static char *ebpf_loader_strdup(const char *src)
{
	char *copy;
	size_t len;

	if (src == NULL) {
		return NULL;
	}

	len = strlen(src) + 1U;
	copy = k_malloc(len);
	if (copy == NULL) {
		return NULL;
	}

	memcpy(copy, src, len);

	return copy;
}

/* Look up one registered loader handle while the registry lock is held. */
static struct ebpf_loader_handle *ebpf_loader_find_handle_locked(const char *name)
{
	struct ebpf_loader_handle *handle;

	SYS_SLIST_FOR_EACH_CONTAINER(&ebpf_loader_registry, handle, registry_node) {
		if ((handle->owned_name != NULL) && (strcmp(handle->owned_name, name) == 0)) {
			return handle;
		}
	}

	return NULL;
}

/* Snapshot loader-visible status fields from one handle under its lock. */
static void ebpf_loader_fill_status_locked(const struct ebpf_loader_handle *handle,
					  struct ebpf_loader_status *status)
{
	status->name = handle->owned_name;
	status->ttl_ms = handle->ttl_ms;
	status->enabled = (handle->bundle != NULL) &&
		atomic_test_bit(&handle->flags, EBPF_LOADER_FLAG_ENABLED);
	status->auto_unloaded = atomic_test_bit(&handle->flags,
					      EBPF_LOADER_FLAG_AUTO_UNLOADED);
	status->loaded = handle->bundle != NULL;
}

/* Copy the public metadata exposed for one runtime map. */
static void ebpf_loader_fill_map_info(const struct ebpf_map *map,
				      struct ebpf_loader_map_info *info)
{
	info->name = ebpf_map_get_name(map);
	info->type = ebpf_map_get_type(map);
	info->key_size = ebpf_map_get_key_size(map);
	info->value_size = ebpf_map_get_value_size(map);
	info->max_entries = ebpf_map_get_max_entries(map);
}

/* Check that one offset-and-size pair stays within the signed image area. */
static bool ebpf_loader_range_valid(size_t total_size, uint32_t offset,
				    size_t size)
{
	if ((size_t)offset > total_size) {
		return false;
	}

	return size <= (total_size - (size_t)offset);
}

/* Resolve one NUL-terminated string stored in the image string table. */
static const char *ebpf_loader_get_string(const uint8_t *image,
					  const struct ebpf_loader_image_header *header,
					  uint32_t offset)
{
	const char *str;
	size_t max_len;
	size_t signed_size = (size_t)header->auth_offset;

	if (offset < header->strings_offset || (size_t)offset >= signed_size ||
	    offset >= (header->strings_offset + header->strings_size)) {
		return NULL;
	}

	str = (const char *)image + offset;
	max_len = MIN((size_t)((header->strings_offset + header->strings_size) - offset),
				signed_size - (size_t)offset);

	if (memchr(str, '\0', max_len) == NULL) {
		return NULL;
	}

	return str;
}

#if defined(CONFIG_EBPF_LOADER_AUTH_ECDSA_P256)
/* Decode the pinned SEC1 public key from Kconfig into raw bytes. */
static int ebpf_loader_get_pinned_pubkey(uint8_t *pubkey, size_t pubkey_size)
{
	size_t out_len;

	if (pubkey == NULL || pubkey_size != 65U) {
		return -EINVAL;
	}

	out_len = hex2bin(CONFIG_EBPF_LOADER_ECDSA_P256_PUBKEY_HEX,
			 sizeof(CONFIG_EBPF_LOADER_ECDSA_P256_PUBKEY_HEX) - 1U,
			 pubkey, pubkey_size);
	if (out_len != pubkey_size || pubkey[0] != 0x04U) {
		return -EINVAL;
	}

	return 0;
}

/* Verify an image signed with the configured ECDSA-P256 key. */
static int ebpf_loader_validate_ecdsa_p256(const uint8_t *image,
					 const struct ebpf_loader_image_header *header)
{
	const struct ebpf_loader_auth_ecdsa_p256 *auth;
	psa_key_attributes_t attr = PSA_KEY_ATTRIBUTES_INIT;
	psa_algorithm_t alg = PSA_ALG_ECDSA(PSA_ALG_SHA_256);
	psa_key_id_t key_id = PSA_KEY_ID_NULL;
	uint8_t pubkey[65];
	uint8_t digest[32];
	size_t digest_len;
	psa_status_t status;
	int ret;

	if (header->auth_size != sizeof(*auth)) {
		return -EINVAL;
	}

	auth = (const struct ebpf_loader_auth_ecdsa_p256 *)(image + header->auth_offset);
	if (auth->key_id != 0U) {
		return -ENOTSUP;
	}

	ret = ebpf_loader_get_pinned_pubkey(pubkey, sizeof(pubkey));
	if (ret != 0) {
		return ret;
	}

	status = psa_crypto_init();
	if (status != PSA_SUCCESS) {
		return -EIO;
	}

	status = psa_hash_compute(PSA_ALG_SHA_256, image, (size_t)header->auth_offset,
				  digest, sizeof(digest), &digest_len);
	if (status != PSA_SUCCESS || digest_len != sizeof(digest)) {
		return -EIO;
	}

	psa_set_key_usage_flags(&attr, PSA_KEY_USAGE_VERIFY_HASH);
	psa_set_key_algorithm(&attr, alg);
	psa_set_key_type(&attr, PSA_KEY_TYPE_ECC_PUBLIC_KEY(PSA_ECC_FAMILY_SECP_R1));
	psa_set_key_bits(&attr, 256);

	status = psa_import_key(&attr, pubkey, sizeof(pubkey), &key_id);
	if (status != PSA_SUCCESS) {
		return -EINVAL;
	}

	status = psa_verify_hash(key_id, alg, digest, sizeof(digest),
				 auth->signature, sizeof(auth->signature));
	psa_destroy_key(key_id);

	return status == PSA_SUCCESS ? 0 : -EBADMSG;
}
#endif

/* Dispatch to the configured authentication scheme for this image. */
static int ebpf_loader_validate_auth(const uint8_t *image,
				    const struct ebpf_loader_image_header *header)
{
	const struct ebpf_loader_auth_crc32 *crc_auth;
	uint32_t crc;

	switch (header->auth_type) {
	case EBPF_LOADER_AUTH_NONE:
		return header->auth_size == 0U ? 0 : -EINVAL;
	case EBPF_LOADER_AUTH_CRC32:
		if (header->auth_size != sizeof(*crc_auth)) {
			return -EINVAL;
		}

		crc_auth = (const struct ebpf_loader_auth_crc32 *)(image + header->auth_offset);
		crc = crc32_ieee(image, (size_t)header->auth_offset);
		return crc == crc_auth->crc32 ? 0 : -EBADMSG;
	case EBPF_LOADER_AUTH_ECDSA_P256_SHA256:
#if defined(CONFIG_EBPF_LOADER_AUTH_ECDSA_P256)
		return ebpf_loader_validate_ecdsa_p256(image, header);
#else
		return -ENOTSUP;
#endif
	default:
		return -ENOTSUP;
	}
}

/* Validate the bundle header and every variable-sized region before loading */
static int ebpf_loader_validate_image(const uint8_t *image, size_t image_size,
				      const struct ebpf_loader_image_header **header_out)
{
	const struct ebpf_loader_image_header *header;
	size_t maps_size;
	size_t attachments_size;
	size_t relocs_size;
	size_t signed_size;
	int ret;

	if (image == NULL || header_out == NULL ||
	    image_size < sizeof(struct ebpf_loader_image_header)) {
		return -EINVAL;
	}

	header = (const struct ebpf_loader_image_header *)image;

	/* Check magic == "EBPF", version == 2, header_size == 64 bytes;
	 * Check total_size does not exceed actual image_size
	 */
	if (header->magic != EBPF_LOADER_IMAGE_MAGIC ||
	    header->version != EBPF_LOADER_IMAGE_VERSION ||
	    header->header_size != sizeof(*header) ||
	    header->total_size > image_size ||
	    header->total_size < header->header_size) {
		return -EINVAL;
	}

	/* Check auth_offset + auth_size == total_size (auth block must be at the end) */
	if (header->auth_offset > header->total_size ||
	    header->auth_size > (header->total_size - header->auth_offset) ||
	    (header->auth_offset + header->auth_size) != header->total_size) {
		return -EINVAL;
	}

	signed_size = (size_t)header->auth_offset;

	if (signed_size < header->header_size) {
		return -EINVAL;
	}

	/* Verify that the offset + size of maps/attachments/relocs/strings are all
	 * within the [0, auth_offset) range to prevent out-of-bounds access
	 */
	maps_size = (size_t)header->map_count * sizeof(struct ebpf_loader_image_map);
	attachments_size = (size_t)header->attachment_count *
			   sizeof(struct ebpf_loader_image_attachment);
	relocs_size = (size_t)header->reloc_count * sizeof(struct ebpf_loader_image_reloc);

	if ((header->map_count != 0U &&
	     !ebpf_loader_range_valid(signed_size, header->maps_offset, maps_size)) ||
	    (header->attachment_count != 0U &&
	     !ebpf_loader_range_valid(signed_size, header->attachments_offset, attachments_size)) ||
	    (header->reloc_count != 0U &&
	     !ebpf_loader_range_valid(signed_size, header->relocs_offset, relocs_size)) ||
	    !ebpf_loader_range_valid(signed_size, header->strings_offset, header->strings_size)) {
		return -EINVAL;
	}

	/* Verify that bundle_name_offset points to a valid NUL-terminated string. */
	if (ebpf_loader_get_string(image, header, header->bundle_name_offset) == NULL) {
		return -EINVAL;
	}

	/* Call ebpf_loader_validate_auth() to validate authentication
	 * (CRC32 checksum / ECDSA-P256 signature verification)
	 */
	ret = ebpf_loader_validate_auth(image, header);
	if (ret != 0) {
		return ret;
	}

	*header_out = header;

	return 0;
}

/* Enable one loaded bundle and arm TTL expiry if configured. */
static int ebpf_loader_enable_locked(struct ebpf_loader_handle *handle)
{
	int ret;

	if (handle->bundle == NULL) {
		return -ENOENT;
	}

	ret = ebpf_bundle_enable(handle->bundle);
	if (ret == 0) {
		atomic_set_bit(&handle->flags, EBPF_LOADER_FLAG_ENABLED);
		atomic_clear_bit(&handle->flags, EBPF_LOADER_FLAG_AUTO_UNLOADED);
		atomic_clear_bit(&handle->flags, EBPF_LOADER_FLAG_TTL_EXPIRED);
		if (handle->ttl_ms != 0U) {
			k_timer_start(&handle->ttl_timer, K_MSEC(handle->ttl_ms), K_NO_WAIT);
		}
	}

	return ret;
}

/* Disable one bundle and stop any pending TTL expiration. */
static int ebpf_loader_disable_locked(struct ebpf_loader_handle *handle)
{
	int ret = 0;

	k_timer_stop(&handle->ttl_timer);
	atomic_clear_bit(&handle->flags, EBPF_LOADER_FLAG_TTL_EXPIRED);
	if (handle->bundle != NULL) {
		ret = ebpf_bundle_disable(handle->bundle);
	}
	atomic_clear_bit(&handle->flags, EBPF_LOADER_FLAG_ENABLED);

	return ret;
}

/* Tear down the bundle owned by one handle and mark it auto-unloaded. */
static int ebpf_loader_destroy_bundle_locked(struct ebpf_loader_handle *handle)
{
	int ret;

	if (handle->bundle == NULL) {
		atomic_clear_bit(&handle->flags, EBPF_LOADER_FLAG_ENABLED);
		atomic_set_bit(&handle->flags, EBPF_LOADER_FLAG_AUTO_UNLOADED);
		return 0;
	}

	ret = ebpf_bundle_destroy(handle->bundle);

	handle->bundle = NULL;
	atomic_clear_bit(&handle->flags, EBPF_LOADER_FLAG_ENABLED);
	atomic_set_bit(&handle->flags, EBPF_LOADER_FLAG_AUTO_UNLOADED);

	return ret;
}

/* Defer TTL-triggered teardown into workqueue context. */
static void ebpf_loader_ttl_timer_handler(struct k_timer *timer)
{
	struct ebpf_loader_handle *handle = CONTAINER_OF(timer,
							 struct ebpf_loader_handle,
							 ttl_timer);

	atomic_set_bit(&handle->flags, EBPF_LOADER_FLAG_TTL_EXPIRED);
	(void)k_work_submit(&ebpf_loader_ttl_work);
}

/* Destroy every bundle whose TTL expiry has been observed by the timer. */
static void ebpf_loader_ttl_work_handler(struct k_work *work)
{
	struct ebpf_loader_handle *handle;

	ARG_UNUSED(work);

	k_mutex_lock(&ebpf_loader_registry_lock, K_FOREVER);
	SYS_SLIST_FOR_EACH_CONTAINER(&ebpf_loader_registry, handle, registry_node) {
		if (!atomic_test_and_clear_bit(&handle->flags,
					       EBPF_LOADER_FLAG_TTL_EXPIRED)) {
			continue;
		}

		k_mutex_lock(&handle->lock, K_FOREVER);
		(void)ebpf_loader_destroy_bundle_locked(handle);
		k_mutex_unlock(&handle->lock);
	}
	k_mutex_unlock(&ebpf_loader_registry_lock);
}

/* Instantiate runtime maps from the serialized map records in one image. */
static int ebpf_loader_create_maps(const uint8_t *image,
				   const struct ebpf_loader_image_header *header,
				   struct ebpf_bundle *bundle,
				   struct ebpf_map ***maps_out)
{
	const struct ebpf_loader_image_map *image_maps;
	struct ebpf_map **maps;
	uint32_t i;

	if (header->map_count == 0U) {
		*maps_out = NULL;
		return 0;
	}

	image_maps = (const struct ebpf_loader_image_map *)(image + header->maps_offset);
	maps = k_malloc(sizeof(*maps) * header->map_count);
	if (maps == NULL) {
		return -ENOMEM;
	}

	memset(maps, 0, sizeof(*maps) * header->map_count);

	for (i = 0U; i < header->map_count; i++) {
		const char *name = ebpf_loader_get_string(image, header,
					 image_maps[i].name_offset);
		struct ebpf_map_spec spec;
		int ret;

		if (name == NULL || image_maps[i].type >= EBPF_MAP_TYPE_MAX) {
			k_free(maps);
			return -EINVAL;
		}

		spec.name = name;
		spec.type = (enum ebpf_map_type)image_maps[i].type;
		spec.key_size = image_maps[i].key_size;
		spec.value_size = image_maps[i].value_size;
		spec.max_entries = image_maps[i].max_entries;

		ret = ebpf_bundle_add_map(bundle, &spec, &maps[i]);
		if (ret != 0) {
			k_free(maps);
			return ret;
		}
	}

	*maps_out = maps;

	return 0;
}

/* Rewrite serialized map relocations into runtime map handles before load. */
static int ebpf_loader_apply_relocs(const struct ebpf_loader_image_header *header,
				    const struct ebpf_loader_image_reloc *relocs,
				    struct ebpf_map **maps,
				    uint32_t attachment_index,
				    struct ebpf_insn *insns,
				    uint32_t insn_cnt)
{
	uint32_t i;

	for (i = 0U; i < header->reloc_count; i++) {
		if (relocs[i].attachment_index != attachment_index) {
			continue;
		}

		if (relocs[i].map_index >= header->map_count ||
		    relocs[i].insn_index >= insn_cnt ||
		    maps == NULL || maps[relocs[i].map_index] == NULL) {
			return -EINVAL;
		}

		insns[relocs[i].insn_index].imm =
			(int32_t)ebpf_map_get_id(maps[relocs[i].map_index]);
	}

	return 0;
}

/* Instantiate runtime attachments from the serialized attachment records. */
static int ebpf_loader_create_attachments(const uint8_t *image,
					  const struct ebpf_loader_image_header *header,
					  struct ebpf_bundle *bundle,
					  struct ebpf_map **maps)
{
	const struct ebpf_loader_image_attachment *image_attachments;
	const struct ebpf_loader_image_reloc *relocs;
	uint32_t i;

	if (header->attachment_count == 0U) {
		return 0;
	}

	image_attachments = (const struct ebpf_loader_image_attachment *)(image +
							header->attachments_offset);
	relocs = header->reloc_count == 0U ? NULL :
		(const struct ebpf_loader_image_reloc *)(image + header->relocs_offset);

	for (i = 0U; i < header->attachment_count; i++) {
		const char *name = ebpf_loader_get_string(image, header,
						  image_attachments[i].name_offset);
		const char *hook_name = ebpf_loader_get_string(image, header,
						  image_attachments[i].hook_name_offset);
		struct ebpf_attachment *attachment;
		struct ebpf_bundle_attachment_spec spec;
		struct ebpf_insn *owned_insns;
		size_t insn_size;
		int ret;

		if (name == NULL || hook_name == NULL ||
		    image_attachments[i].prog_type >= EBPF_PROG_TYPE_MAX) {
			return -EINVAL;
		}

		insn_size = (size_t)image_attachments[i].insn_cnt * sizeof(struct ebpf_insn);
		if (image_attachments[i].insn_cnt == 0U ||
		    !ebpf_loader_range_valid((size_t)header->auth_offset,
					     image_attachments[i].insns_offset,
					     insn_size)) {
			return -EINVAL;
		}

		owned_insns = k_malloc(insn_size);
		if (owned_insns == NULL) {
			return -ENOMEM;
		}

		memcpy(owned_insns, image + image_attachments[i].insns_offset, insn_size);

		ret = ebpf_loader_apply_relocs(header, relocs, maps, i, owned_insns,
					       image_attachments[i].insn_cnt);
		if (ret != 0) {
			k_free(owned_insns);
			return ret;
		}

		spec.name = name;
		spec.type = (enum ebpf_prog_type)image_attachments[i].prog_type;
		spec.insns = owned_insns;
		spec.insn_cnt = image_attachments[i].insn_cnt;
		spec.hook_name = hook_name;

		ret = ebpf_bundle_add_attachment(bundle, &spec, &attachment);
		ARG_UNUSED(attachment);
		k_free(owned_insns);
		if (ret != 0) {
			return ret;
		}
	}

	return 0;
}

int ebpf_loader_load(const void *image, size_t image_size,
		     struct ebpf_loader_handle **handle_out)
{
	const struct ebpf_loader_image_header *header;
	struct ebpf_loader_handle *handle;
	struct ebpf_map **maps = NULL;
	const char *bundle_name;
	const uint8_t *bytes = image;
	int ret;

	if (image == NULL || handle_out == NULL) {
		return -EINVAL;
	}

	ret = ebpf_loader_validate_image(bytes, image_size, &header);
	if (ret != 0) {
		return ret;
	}

	handle = k_malloc(sizeof(*handle));
	if (handle == NULL) {
		return -ENOMEM;
	}

	memset(handle, 0, sizeof(*handle));

	*handle_out = NULL;
	k_mutex_init(&handle->lock);
	k_timer_init(&handle->ttl_timer, ebpf_loader_ttl_timer_handler, NULL);

	bundle_name = ebpf_loader_get_string(bytes, header, header->bundle_name_offset);
	handle->owned_name = ebpf_loader_strdup(bundle_name);
	if (handle->owned_name == NULL) {
		k_free(handle);
		return -ENOMEM;
	}

	handle->ttl_ms = header->ttl_ms;

	/* Hold the registry lock across duplicate-name validation and final
	 * registration so two same-name loads cannot slip through concurrently.
	 * If a bundle with the same name already exists, return -EALREADY.
	 */
	k_mutex_lock(&ebpf_loader_registry_lock, K_FOREVER);
	if (ebpf_loader_find_handle_locked(bundle_name) != NULL) {
		k_mutex_unlock(&ebpf_loader_registry_lock);
		k_free(handle->owned_name);
		k_free(handle);
		return -EALREADY;
	}

	ret = ebpf_bundle_create(handle->owned_name, &handle->bundle);

	if (ret == 0) {
		ret = ebpf_loader_create_maps(bytes, header, handle->bundle, &maps);
	}
	if (ret == 0) {
		ret = ebpf_loader_create_attachments(bytes, header, handle->bundle, maps);
	}
	if (ret == 0) {
		/* Publish one new handle into the registry while the registry lock is held. */
		sys_slist_append(&ebpf_loader_registry, &handle->registry_node);
		*handle_out = handle;
	}

	k_mutex_unlock(&ebpf_loader_registry_lock);

	/* On any failure, clean up all partially created state. If the bundle was created, it
	 * will be destroyed in the error path since it is owned by the handle and not yet enabled.
	 * No need to hold the registry lock here since the handle is not published if we are in
	 * this error path.
	 */
	if (ret != 0) {
		if (handle->bundle != NULL) {
			/* 
			 */
			(void)ebpf_bundle_destroy(handle->bundle);
		}
		k_free(maps);
		k_free(handle->owned_name);
		k_free(handle);
		return ret;
	}

	k_free(maps);

	return 0;
}

int ebpf_loader_enable(struct ebpf_loader_handle *handle)
{
	int ret;

	if (handle == NULL) {
		return -EINVAL;
	}

	k_mutex_lock(&handle->lock, K_FOREVER);
	ret = ebpf_loader_enable_locked(handle);
	k_mutex_unlock(&handle->lock);

	return ret;
}

int ebpf_loader_disable(struct ebpf_loader_handle *handle)
{
	int ret = 0;

	if (handle == NULL) {
		return -EINVAL;
	}

	k_mutex_lock(&handle->lock, K_FOREVER);
	ret = ebpf_loader_disable_locked(handle);
	k_mutex_unlock(&handle->lock);

	return ret;
}

int ebpf_loader_unload(struct ebpf_loader_handle *handle)
{
	int ret = 0;
	int destroy_ret;

	if (handle == NULL) {
		return -EINVAL;
	}

	k_mutex_lock(&ebpf_loader_registry_lock, K_FOREVER);

	/* Remove one handle from the global loader registry. */
	(void)sys_slist_find_and_remove(&ebpf_loader_registry,
					&handle->registry_node);
	k_mutex_unlock(&ebpf_loader_registry_lock);
	k_mutex_lock(&handle->lock, K_FOREVER);
	k_timer_stop(&handle->ttl_timer);
	atomic_clear_bit(&handle->flags, EBPF_LOADER_FLAG_TTL_EXPIRED);
	if (handle->bundle != NULL) {
		destroy_ret = ebpf_loader_destroy_bundle_locked(handle);
		if (destroy_ret != 0) {
			ret = destroy_ret;
		}
	}
	k_mutex_unlock(&handle->lock);

	k_free(handle->owned_name);
	k_free(handle);

	return ret;
}

const char *ebpf_loader_name(const struct ebpf_loader_handle *handle)
{
	if (handle == NULL) {
		return NULL;
	}

	return handle->owned_name;
}

struct ebpf_bundle *ebpf_loader_bundle(struct ebpf_loader_handle *handle)
{
	if (handle == NULL) {
		return NULL;
	}

	return handle->bundle;
}

bool ebpf_loader_is_enabled(const struct ebpf_loader_handle *handle)
{
	if (handle == NULL) {
		return false;
	}

	return atomic_test_bit(&handle->flags, EBPF_LOADER_FLAG_ENABLED);
}

bool ebpf_loader_was_auto_unloaded(const struct ebpf_loader_handle *handle)
{
	if (handle == NULL) {
		return false;
	}

	return atomic_test_bit(&handle->flags, EBPF_LOADER_FLAG_AUTO_UNLOADED);
}

int ebpf_loader_enable_by_name(const char *name)
{
	struct ebpf_loader_handle *handle;
	int ret;

	if (name == NULL) {
		return -EINVAL;
	}

	k_mutex_lock(&ebpf_loader_registry_lock, K_FOREVER);
	handle = ebpf_loader_find_handle_locked(name);
	if (handle == NULL) {
		k_mutex_unlock(&ebpf_loader_registry_lock);
		return -ENOENT;
	}

	k_mutex_lock(&handle->lock, K_FOREVER);
	k_mutex_unlock(&ebpf_loader_registry_lock);
	ret = ebpf_loader_enable_locked(handle);
	k_mutex_unlock(&handle->lock);

	return ret;
}

int ebpf_loader_disable_by_name(const char *name)
{
	struct ebpf_loader_handle *handle;
	int ret;

	if (name == NULL) {
		return -EINVAL;
	}

	k_mutex_lock(&ebpf_loader_registry_lock, K_FOREVER);
	handle = ebpf_loader_find_handle_locked(name);
	if (handle == NULL) {
		k_mutex_unlock(&ebpf_loader_registry_lock);
		return -ENOENT;
	}

	k_mutex_lock(&handle->lock, K_FOREVER);
	k_mutex_unlock(&ebpf_loader_registry_lock);
	ret = ebpf_loader_disable_locked(handle);
	k_mutex_unlock(&handle->lock);

	return ret;
}

int ebpf_loader_unload_by_name(const char *name)
{
	struct ebpf_loader_handle *handle;
	int ret = 0;
	int destroy_ret;

	if (name == NULL) {
		return -EINVAL;
	}

	k_mutex_lock(&ebpf_loader_registry_lock, K_FOREVER);
	handle = ebpf_loader_find_handle_locked(name);
	if (handle == NULL) {
		k_mutex_unlock(&ebpf_loader_registry_lock);
		return -ENOENT;
	}

	(void)sys_slist_find_and_remove(&ebpf_loader_registry, &handle->registry_node);
	k_mutex_lock(&handle->lock, K_FOREVER);
	k_mutex_unlock(&ebpf_loader_registry_lock);
	k_timer_stop(&handle->ttl_timer);
	atomic_clear_bit(&handle->flags, EBPF_LOADER_FLAG_TTL_EXPIRED);
	if (handle->bundle != NULL) {
		destroy_ret = ebpf_loader_destroy_bundle_locked(handle);
		if (destroy_ret != 0) {
			ret = destroy_ret;
		}
	}
	k_mutex_unlock(&handle->lock);

	k_free(handle->owned_name);
	k_free(handle);

	return ret;
}

int ebpf_loader_map_info_by_name(const char *bundle_name,
					 const char *map_name,
					 struct ebpf_loader_map_info *info_out)
{
	struct ebpf_loader_handle *handle;
	struct ebpf_map *map;
	int ret = 0;

	if (bundle_name == NULL || map_name == NULL || info_out == NULL) {
		return -EINVAL;
	}

	k_mutex_lock(&ebpf_loader_registry_lock, K_FOREVER);
	handle = ebpf_loader_find_handle_locked(bundle_name);
	if (handle == NULL) {
		k_mutex_unlock(&ebpf_loader_registry_lock);
		return -ENOENT;
	}

	k_mutex_lock(&handle->lock, K_FOREVER);
	k_mutex_unlock(&ebpf_loader_registry_lock);

	if (handle->bundle == NULL) {
		ret = -ENOENT;
		goto out;
	}

	map = ebpf_bundle_find_map(handle->bundle, map_name);
	if (map == NULL) {
		ret = -ENOENT;
		goto out;
	}

	ebpf_loader_fill_map_info(map, info_out);

out:
	k_mutex_unlock(&handle->lock);

	return ret;
}

int ebpf_loader_map_lookup_copy_by_name(const char *bundle_name,
					const char *map_name,
					const void *key,
					void *value_out,
					size_t value_size)
{
	struct ebpf_loader_handle *handle;
	struct ebpf_map *map;
	void *value;
	int ret = 0;

	if (bundle_name == NULL || map_name == NULL || key == NULL || value_out == NULL) {
		return -EINVAL;
	}

	k_mutex_lock(&ebpf_loader_registry_lock, K_FOREVER);
	handle = ebpf_loader_find_handle_locked(bundle_name);
	if (handle == NULL) {
		k_mutex_unlock(&ebpf_loader_registry_lock);
		return -ENOENT;
	}

	k_mutex_lock(&handle->lock, K_FOREVER);
	k_mutex_unlock(&ebpf_loader_registry_lock);

	if (handle->bundle == NULL) {
		ret = -ENOENT;
		goto out;
	}

	map = ebpf_bundle_find_map(handle->bundle, map_name);
	if (map == NULL) {
		ret = -ENOENT;
		goto out;
	}

	if (value_size < ebpf_map_get_value_size(map)) {
		ret = -EMSGSIZE;
		goto out;
	}

	value = ebpf_map_lookup_elem(map, key);
	if (value == NULL) {
		ret = -ENOENT;
		goto out;
	}

	memcpy(value_out, value, ebpf_map_get_value_size(map));

out:
	k_mutex_unlock(&handle->lock);

	return ret;
}

int ebpf_loader_status_by_name(const char *name,
			       struct ebpf_loader_status *status_out)
{
	struct ebpf_loader_handle *handle;

	if (name == NULL || status_out == NULL) {
		return -EINVAL;
	}

	k_mutex_lock(&ebpf_loader_registry_lock, K_FOREVER);
	handle = ebpf_loader_find_handle_locked(name);
	if (handle == NULL) {
		k_mutex_unlock(&ebpf_loader_registry_lock);
		return -ENOENT;
	}

	k_mutex_lock(&handle->lock, K_FOREVER);
	k_mutex_unlock(&ebpf_loader_registry_lock);
	ebpf_loader_fill_status_locked(handle, status_out);
	k_mutex_unlock(&handle->lock);

	return 0;
}

void ebpf_loader_foreach(ebpf_loader_foreach_cb_t cb, void *user_data)
{
	struct ebpf_loader_handle *handle;

	if (cb == NULL) {
		return;
	}

	k_mutex_lock(&ebpf_loader_registry_lock, K_FOREVER);
	SYS_SLIST_FOR_EACH_CONTAINER(&ebpf_loader_registry, handle, registry_node) {
		struct ebpf_loader_status status;
		bool keep_going;

		k_mutex_lock(&handle->lock, K_FOREVER);
		ebpf_loader_fill_status_locked(handle, &status);
		keep_going = cb(&status, user_data);
		k_mutex_unlock(&handle->lock);
		if (!keep_going) {
			break;
		}
	}
	k_mutex_unlock(&ebpf_loader_registry_lock);
}

