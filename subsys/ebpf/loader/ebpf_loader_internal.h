/*
 * SPDX-FileCopyrightText: Copyright 2026 NXP
 *
 * SPDX-License-Identifier: Apache-2.0
 */

/**
 * @file
 * @brief Internal eBPF loader interfaces and image format definitions.
 */

#ifndef ZEPHYR_SUBSYS_EBPF_LOADER_INTERNAL_H_
#define ZEPHYR_SUBSYS_EBPF_LOADER_INTERNAL_H_

#include <zephyr/toolchain.h>

#include <zephyr/ebpf/ebpf_loader.h>
#include <zephyr/ebpf/ebpf_bundle.h>

#ifdef __cplusplus
extern "C" {
#endif

#define EBPF_LOADER_IMAGE_MAGIC		0x46504245U
#define EBPF_LOADER_IMAGE_VERSION	2U

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

struct __packed ebpf_loader_auth_crc32 {
	uint32_t crc32;
};

struct __packed ebpf_loader_auth_ecdsa_p256 {
	uint32_t key_id;
	uint8_t signature[64];
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

struct ebpf_bundle *ebpf_loader_bundle(struct ebpf_loader_handle *handle);

bool ebpf_loader_is_enabled(const struct ebpf_loader_handle *handle);

bool ebpf_loader_was_auto_unloaded(const struct ebpf_loader_handle *handle);

#ifdef __cplusplus
}
#endif

#endif /* ZEPHYR_SUBSYS_EBPF_LOADER_INTERNAL_H_ */

