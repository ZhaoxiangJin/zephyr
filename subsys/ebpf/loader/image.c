/*
 * SPDX-FileCopyrightText: Copyright 2026 NXP
 *
 * SPDX-License-Identifier: Apache-2.0
 */

#include <errno.h>
#include <string.h>

#include <zephyr/sys/crc.h>
#include <zephyr/sys/util.h>
#include <zephyr/toolchain.h>

#if defined(CONFIG_EBPF_LOADER_AUTH_ECDSA_P256)
#include <psa/crypto.h>
#endif

#include "image.h"

struct __packed ebpf_loader_auth_crc32 {
	uint32_t crc32;
};

struct __packed ebpf_loader_auth_ecdsa_p256 {
	uint32_t key_id;
	uint8_t signature[64];
};

#if defined(CONFIG_EBPF_LOADER_AUTH_ECDSA_P256)
BUILD_ASSERT(sizeof(CONFIG_EBPF_LOADER_ECDSA_P256_PUBKEY_HEX) == (65U * 2U) + 1U,
	     "CONFIG_EBPF_LOADER_ECDSA_P256_PUBKEY_HEX must contain a 65-byte SEC1 public key in hex");
#endif

bool ebpf_loader_range_valid(size_t total_size, uint32_t offset, size_t size)
{
	if ((size_t)offset > total_size) {
		return false;
	}

	return size <= (total_size - (size_t)offset);
}

const char *ebpf_loader_get_string(const uint8_t *image,
				   const struct ebpf_loader_image_header *header,
				   uint32_t offset)
{
	size_t signed_size = (size_t)header->auth_offset;
	const char *str;
	size_t max_len;

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
	if (pubkey == NULL || pubkey_size != 65U) {
		return -EINVAL;
	}

	size_t out_len;

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

int ebpf_loader_validate_image(const uint8_t *image, size_t image_size,
			       const struct ebpf_loader_image_header **header_out)
{
	if (image == NULL || header_out == NULL ||
	    image_size < sizeof(struct ebpf_loader_image_header)) {
		return -EINVAL;
	}

	const struct ebpf_loader_image_header *header;
	size_t attachments_size;
	size_t maps_size;
	size_t relocs_size;
	size_t signed_size;
	int ret;

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
