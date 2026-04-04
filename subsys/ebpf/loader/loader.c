/*
 * SPDX-FileCopyrightText: Copyright 2026 NXP
 *
 * SPDX-License-Identifier: Apache-2.0
 */

#include <string.h>
#include <zephyr/kernel.h>
#include <zephyr/sys/slist.h>
#include <zephyr/sys/util.h>

#include "image.h"
#include "../bundle/bundle.h"

struct ebpf_loader_handle {
	struct k_mutex lock;
	sys_snode_t registry_node;
	struct ebpf_bundle *bundle;
	char *name;
};

/* Global registry of all loaded handles, linked via handle->registry_node.
 * Protected by ebpf_loader_registry_lock; the registry lock also serializes
 * duplicate-name checks against publication in ebpf_loader_load() so two
 * same-name loads cannot race past each other.
 */
static sys_slist_t ebpf_loader_registry;
static K_MUTEX_DEFINE(ebpf_loader_registry_lock);

/* Rewrite serialized map relocations into runtime map handles before load. */
static int ebpf_loader_apply_relocs(const struct ebpf_loader_image_header *header,
				    const struct ebpf_loader_image_reloc *relocs,
				    struct ebpf_map **maps, uint32_t attachment_index,
				    struct ebpf_insn *insns, uint32_t insn_cnt)
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
		struct ebpf_attachment_spec spec;
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
		    			     image_attachments[i].insns_offset, insn_size)) {
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

int ebpf_loader_load(const void *image, size_t image_size, struct ebpf_loader_handle **handle_out)
{
	if (image == NULL || handle_out == NULL) {
		return -EINVAL;
	}

	const struct ebpf_loader_image_header *header;
	struct ebpf_loader_handle *handle;
	struct ebpf_loader_handle *existing;
	struct ebpf_map **maps = NULL;
	const uint8_t *bytes = image;
	const char *bundle_name;
	int ret;

	/* Validate the image format and extract the header pointer.
	 * This also serves to prevent out-of-bounds access to the
	 * header in subsequent steps.
	 */
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

	bundle_name = ebpf_loader_get_string(bytes, header, header->bundle_name_offset);
	if (bundle_name == NULL) {
		k_free(handle);
		return -EINVAL;
	}

	/* Copy the bundle name into loader-owned storage so the handle outlives
	 * the caller's image buffer.
	 */
	size_t name_len = strlen(bundle_name) + 1U;

	handle->name = k_malloc(name_len);
	if (handle->name == NULL) {
		k_free(handle);
		return -ENOMEM;
	}
	memcpy(handle->name, bundle_name, name_len);

	/* Hold the registry lock across duplicate-name validation and final
	 * registration so two same-name loads cannot slip through concurrently.
	 * If a bundle with the same name already exists, return -EALREADY.
	 */
	k_mutex_lock(&ebpf_loader_registry_lock, K_FOREVER);
	SYS_SLIST_FOR_EACH_CONTAINER(&ebpf_loader_registry, existing, registry_node) {
		if ((existing->name != NULL) && (strcmp(existing->name, bundle_name) == 0)) {
			k_mutex_unlock(&ebpf_loader_registry_lock);
			k_free(handle->name);
			k_free(handle);
			return -EALREADY;
		}
	}

	ret = ebpf_bundle_create(handle->name, &handle->bundle);

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

	/* On any failure, clean up all partially created state. If the bundle was created,
	 * it will be destroyed in the error path since it is owned by the handle and not
	 * yet enabled. No need to hold the registry lock here since the handle is not
	 * published if we are in this error path.
	 */
	if (ret != 0) {
		if (handle->bundle != NULL) {
			(void)ebpf_bundle_destroy(handle->bundle);
		}
		k_free(maps);
		k_free(handle->name);
		k_free(handle);
		return ret;
	}

	k_free(maps);

	return 0;
}

int ebpf_loader_unload(struct ebpf_loader_handle *handle)
{
	if (handle == NULL) {
		return -EINVAL;
	}

	int ret = 0;

	k_mutex_lock(&ebpf_loader_registry_lock, K_FOREVER);
	/* Remove one handle from the global loader registry. */
	(void)sys_slist_find_and_remove(&ebpf_loader_registry, &handle->registry_node);
	k_mutex_unlock(&ebpf_loader_registry_lock);

	k_mutex_lock(&handle->lock, K_FOREVER);
	if (handle->bundle != NULL) {
		ret = ebpf_bundle_destroy(handle->bundle);
		handle->bundle = NULL;
	}
	k_mutex_unlock(&handle->lock);

	k_free(handle->name);
	k_free(handle);

	return ret;
}

int ebpf_loader_enable(struct ebpf_loader_handle *handle)
{
	if (handle == NULL) {
		return -EINVAL;
	}

	int ret;

	k_mutex_lock(&handle->lock, K_FOREVER);
	if (handle->bundle == NULL) {
		ret = -ENOENT;
	} else {
		ret = ebpf_bundle_enable(handle->bundle);
	}
	k_mutex_unlock(&handle->lock);

	return ret;
}

int ebpf_loader_disable(struct ebpf_loader_handle *handle)
{
	if (handle == NULL) {
		return -EINVAL;
	}

	int ret = 0;

	k_mutex_lock(&handle->lock, K_FOREVER);
	if (handle->bundle != NULL) {
		ret = ebpf_bundle_disable(handle->bundle);
	}
	k_mutex_unlock(&handle->lock);

	return ret;
}

int ebpf_loader_map_lookup_copy(struct ebpf_loader_handle *handle, const char *map_name,
				const void *key, void *value_out, size_t value_size)
{
	if (handle == NULL || map_name == NULL || key == NULL || value_out == NULL) {
		return -EINVAL;
	}

	struct ebpf_map *map;
	void *value;
	int ret = 0;

	k_mutex_lock(&handle->lock, K_FOREVER);

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

const char *ebpf_loader_name(const struct ebpf_loader_handle *handle)
{
	if (handle == NULL) {
		return NULL;
	}

	return handle->name;
}
