/*
 * SPDX-FileCopyrightText: Copyright 2026 NXP
 *
 * SPDX-License-Identifier: Apache-2.0
 */

/**
 * @file
 * @brief eBPF loader image parsing and authentication interfaces.
 *
 * @note Visibility: loader component only (loader.c <-> image.c).
 */

#ifndef ZEPHYR_SUBSYS_EBPF_LOADER_IMAGE_H_
#define ZEPHYR_SUBSYS_EBPF_LOADER_IMAGE_H_

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#include <zephyr/toolchain.h>

#ifdef __cplusplus
extern "C" {
#endif

#define EBPF_LOADER_IMAGE_MAGIC		0x46504245U
#define EBPF_LOADER_IMAGE_VERSION	1U

enum ebpf_loader_auth_type {
	EBPF_LOADER_AUTH_NONE = 0,
	EBPF_LOADER_AUTH_CRC32 = 1,
	EBPF_LOADER_AUTH_ECDSA_P256_SHA256 = 2,
};

struct __packed ebpf_loader_image_header {
	uint32_t magic;
	uint16_t version;
	uint16_t header_size;
	uint32_t total_size;
	uint32_t auth_type;
	uint32_t ttl_ms;
	uint32_t bundle_name_offset;
	uint32_t map_count;
	uint32_t attachment_count;
	uint32_t reloc_count;
	uint32_t maps_offset;
	uint32_t attachments_offset;
	uint32_t relocs_offset;
	uint32_t strings_offset;
	uint32_t strings_size;
	uint32_t auth_offset;
	uint32_t auth_size;
};

struct __packed ebpf_loader_image_map {
	uint32_t name_offset;
	uint32_t type;
	uint32_t key_size;
	uint32_t value_size;
	uint32_t max_entries;
};

struct __packed ebpf_loader_image_attachment {
	uint32_t name_offset;
	uint32_t hook_name_offset;
	uint32_t prog_type;
	uint32_t insns_offset;
	uint32_t insn_cnt;
};

struct __packed ebpf_loader_image_reloc {
	uint32_t attachment_index;
	uint32_t insn_index;
	uint32_t map_index;
};

/**
 * @brief Check that one offset-and-size pair stays within a signed region.
 *
 * Used to validate variable-sized regions declared by an image header
 * (maps, attachments, relocs, strings, instruction streams) before they
 * are dereferenced. The check is overflow-safe for untrusted inputs.
 *
 * @param[in] total_size Size of the signed region (typically @c auth_offset).
 * @param[in] offset Start offset of the region to check, relative to the image base.
 * @param[in] size Size of the region to check.
 *
 * @retval true  The half-open range [offset, offset + size) fits in
 *               [0, total_size).
 * @retval false @p offset is past @p total_size or @p size overflows the
 *               remaining space.
 */
bool ebpf_loader_range_valid(size_t total_size, uint32_t offset, size_t size);

/**
 * @brief Resolve one NUL-terminated string stored in the image string table.
 *
 * Bounds-checks @p offset against the string table declared by @p header,
 * then confirms a NUL terminator exists before the table ends. The returned
 * pointer is only valid for the lifetime of @p image.
 *
 * @param[in] image Probe image bytes (must be the same bytes previously
 *                  validated via ebpf_loader_validate_image()).
 * @param[in] header Validated image header describing @p image.
 * @param[in] offset Byte offset into @p image of the string to resolve.
 *
 * @retval NULL @p offset is outside the string table or the string is not
 *              NUL-terminated inside the signed region.
 * @retval str  Pointer into @p image for the resolved NUL-terminated string.
 */
const char *ebpf_loader_get_string(const uint8_t *image,
				   const struct ebpf_loader_image_header *header,
				   uint32_t offset);

/**
 * @brief Parse and authenticate one probe image.
 *
 * On success, @p header_out points inside @p image and is valid for the
 * lifetime of @p image. No runtime objects are created here.
 *
 * @param[in] image Probe image bytes.
 * @param[in] image_size Size of @p image in bytes.
 * @param[out] header_out Receives a pointer to the validated image header.
 *
 * @retval 0 Image is well-formed and authenticates successfully.
 * @retval -EINVAL Image is malformed or its geometry is inconsistent.
 * @retval -EBADMSG Authentication check failed.
 * @retval -ENOTSUP Authentication scheme not supported by this build.
 * @retval -EIO Crypto backend failed.
 */
int ebpf_loader_validate_image(const uint8_t *image, size_t image_size,
			       const struct ebpf_loader_image_header **header_out);

#ifdef __cplusplus
}
#endif

#endif /* ZEPHYR_SUBSYS_EBPF_LOADER_IMAGE_H_ */
