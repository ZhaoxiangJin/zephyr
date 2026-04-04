/*
 * SPDX-FileCopyrightText: Copyright 2026 NXP
 *
 * SPDX-License-Identifier: Apache-2.0
 */

#include <string.h>
#include <zephyr/kernel.h>
#include <zephyr/sys/slist.h>
#include <zephyr/sys/util.h>

#include "bundle.h"

/*
 * Adapter node for the bundle->maps singly-linked list. struct ebpf_map is
 * defined in the map subsystem and has no slist node; this wrapper lets the
 * bundle own a list of maps without modifying the map struct itself.
 */
struct ebpf_bundle_map_ref {
	struct ebpf_map *map;
	sys_snode_t node;
};

struct ebpf_bundle_attachment_ref {
	struct ebpf_attachment *attachment;
	sys_snode_t node;
};

struct ebpf_bundle {
	struct k_mutex lock;
	sys_slist_t maps;
	sys_slist_t attachments;
	char *name;
};

int ebpf_bundle_create(const char *name, struct ebpf_bundle **bundle_out)
{
	if (name == NULL || bundle_out == NULL) {
		return -EINVAL;
	}

	struct ebpf_bundle *bundle;
	size_t name_len;

	bundle = k_malloc(sizeof(*bundle));
	if (bundle == NULL) {
		return -ENOMEM;
	}

	memset(bundle, 0, sizeof(*bundle));
	/* Bundle keeps a private stable name copy for handle lifetime. */
	name_len = strlen(name) + 1U;
	bundle->name = k_malloc(name_len);
	if (bundle->name == NULL) {
		k_free(bundle);
		return -ENOMEM;
	}

	memcpy(bundle->name, name, name_len);

	k_mutex_init(&bundle->lock);
	sys_slist_init(&bundle->maps);
	sys_slist_init(&bundle->attachments);
	*bundle_out = bundle;

	return 0;
}

int ebpf_bundle_destroy(struct ebpf_bundle *bundle)
{
	if (bundle == NULL) {
		return -EINVAL;
	}

	int ret = 0;
	int first_error = 0;
	sys_snode_t *node;

	/* Phase 1 — tear down every attachment BEFORE any map is freed,
	 * because a running program may still reference map memory.
	 */
	while (true) {
		/* Lock only covers the sys_slist_get (pop-head) to protect
		 * the list structure from concurrent add/remove. The lock is
		 * released before the expensive disable_sync so other paths
		 * are not blocked while we wait for readers to drain.
		 */
		k_mutex_lock(&bundle->lock, K_FOREVER);
		node = sys_slist_get(&bundle->attachments);
		k_mutex_unlock(&bundle->lock);
		if (node == NULL) {
			break;
		}

		struct ebpf_bundle_attachment_ref *ref =
			CONTAINER_OF(node, struct ebpf_bundle_attachment_ref, node);

		ret = ebpf_attachment_destroy(ref->attachment);
		if (ret != 0 && first_error == 0) {
			/* Record the first error but keep going so remaining resources
			 * are still cleaned up. The caller sees the first failure while
			 * we avoid leaking anything we *can* free.
			 */
			first_error = ret;
		}

		if (ret == 0) {
			k_free(ref);
		}
	}

	/* Phase 2 — all attachments are gone, so no program can still
	 * reference map memory. Safe to destroy maps now.
	 */
	while (true) {
		struct ebpf_bundle_map_ref *ref;

		k_mutex_lock(&bundle->lock, K_FOREVER);
		node = sys_slist_get(&bundle->maps);
		k_mutex_unlock(&bundle->lock);
		if (node == NULL) {
			break;
		}

		ref = CONTAINER_OF(node, struct ebpf_bundle_map_ref, node);
		ret = ebpf_map_destroy_owned(ref->map, bundle);
		if (ret != 0 && first_error == 0) {
			first_error = ret;
		}
		k_free(ref);
	}

	/* Phase 3 — free the bundle shell itself. */
	k_free(bundle->name);
	k_free(bundle);

	return first_error;
}

int ebpf_bundle_enable(struct ebpf_bundle *bundle)
{
	if (bundle == NULL) {
		return -EINVAL;
	}

	struct ebpf_bundle_attachment_ref *ref;
	int rollback_ret = 0;
	int ret = 0;

	k_mutex_lock(&bundle->lock, K_FOREVER);
	SYS_SLIST_FOR_EACH_CONTAINER(&bundle->attachments, ref, node) {
		ret = ebpf_attachment_enable(ref->attachment);
		if (ret != 0) {
			break;
		}
	}

	if (ret != 0) {
		SYS_SLIST_FOR_EACH_CONTAINER(&bundle->attachments, ref, node) {
			int disable_ret = ebpf_attachment_disable(ref->attachment);

			if (disable_ret != 0 && rollback_ret == 0) {
				rollback_ret = disable_ret;
			}
		}
	}
	k_mutex_unlock(&bundle->lock);

	return rollback_ret != 0 ? rollback_ret : ret;
}

int ebpf_bundle_disable(struct ebpf_bundle *bundle)
{
	if (bundle == NULL) {
		return -EINVAL;
	}

	struct ebpf_bundle_attachment_ref *ref;
	int first_error = 0;
	int ret;

	k_mutex_lock(&bundle->lock, K_FOREVER);
	SYS_SLIST_FOR_EACH_CONTAINER(&bundle->attachments, ref, node) {
		ret = ebpf_attachment_disable(ref->attachment);
		if (ret != 0 && first_error == 0) {
			first_error = ret;
		}
	}
	k_mutex_unlock(&bundle->lock);

	return first_error;
}

int ebpf_bundle_add_map(struct ebpf_bundle *bundle,
			const struct ebpf_map_spec *spec,
			struct ebpf_map **map_out)
{
	if (bundle == NULL || spec == NULL || map_out == NULL) {
		return -EINVAL;
	}

	struct ebpf_map *map;
	int ret;

	ret = ebpf_map_create(spec, &map);
	if (ret != 0) {
		return ret;
	}

	ret = ebpf_map_claim_owner(map, bundle);
	if (ret != 0) {
		(void)ebpf_map_destroy(map);
		return ret;
	}

	struct ebpf_bundle_map_ref *ref = k_malloc(sizeof(*ref));
	if (ref == NULL) {
		(void)ebpf_map_destroy_owned(map, bundle);
		return -ENOMEM;
	}

	ref->map = map;
	ref->node.next = NULL;

	k_mutex_lock(&bundle->lock, K_FOREVER);
	sys_slist_append(&bundle->maps, &ref->node);
	k_mutex_unlock(&bundle->lock);

	*map_out = map;

	return 0;
}

int ebpf_bundle_add_attachment(struct ebpf_bundle *bundle,
			       const struct ebpf_attachment_spec *spec,
			       struct ebpf_attachment **attachment_out)
{
	if (bundle == NULL || spec == NULL || attachment_out == NULL) {
		return -EINVAL;
	}

	struct ebpf_attachment *attachment;
	struct ebpf_bundle_attachment_ref *ref;
	int ret;

	ret = ebpf_attachment_create(spec, &attachment);
	if (ret != 0) {
		return ret;
	}

	ref = k_malloc(sizeof(*ref));
	if (ref == NULL) {
		(void)ebpf_attachment_destroy(attachment);
		return -ENOMEM;
	}
	ref->attachment = attachment;
	ref->node.next = NULL;

	k_mutex_lock(&bundle->lock, K_FOREVER);
	sys_slist_append(&bundle->attachments, &ref->node);
	k_mutex_unlock(&bundle->lock);

	*attachment_out = attachment;

	return 0;
}

struct ebpf_map *ebpf_bundle_find_map(struct ebpf_bundle *bundle,
				      const char *name)
{
	if (bundle == NULL || name == NULL) {
		return NULL;
	}

	struct ebpf_bundle_map_ref *ref;
	struct ebpf_map *map = NULL;

	k_mutex_lock(&bundle->lock, K_FOREVER);
	SYS_SLIST_FOR_EACH_CONTAINER(&bundle->maps, ref, node) {
		if (strcmp(ebpf_map_get_name(ref->map), name) == 0) {
			map = ref->map;
			break;
		}
	}
	k_mutex_unlock(&bundle->lock);

	return map;
}

struct ebpf_attachment *ebpf_bundle_find_attachment(struct ebpf_bundle *bundle,
						    const char *name)
{
	if (bundle == NULL || name == NULL) {
		return NULL;
	}

	struct ebpf_bundle_attachment_ref *ref;
	struct ebpf_attachment *attachment = NULL;

	k_mutex_lock(&bundle->lock, K_FOREVER);
	SYS_SLIST_FOR_EACH_CONTAINER(&bundle->attachments, ref, node) {
		if (strcmp(ebpf_attachment_name(ref->attachment), name) == 0) {
			attachment = ref->attachment;
			break;
		}
	}
	k_mutex_unlock(&bundle->lock);

	return attachment;
}
