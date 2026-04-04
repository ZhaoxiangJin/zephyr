/*
 * SPDX-FileCopyrightText: Copyright 2026 NXP
 *
 * SPDX-License-Identifier: Apache-2.0
 */

#include <string.h>
#include <zephyr/kernel.h>
#include <zephyr/sys/slist.h>
#include <zephyr/sys/util.h>

#include "ebpf_bundle_internal.h"

/*
 * Adapter node for the bundle->maps singly-linked list. struct ebpf_map is
 * defined in the map subsystem and has no slist node; this wrapper lets the
 * bundle own a list of maps without modifying the map struct itself.
 */
struct ebpf_bundle_map_ref {
	struct ebpf_map *map;
	sys_snode_t node;
};

struct ebpf_attachment {
	struct ebpf_bundle *owner;
	struct ebpf_prog *prog;
	sys_snode_t owner_node;
	char *owned_name;
	char *owned_hook_name;
	struct ebpf_insn *owned_insns;
};

struct ebpf_bundle {
	struct k_mutex lock;
	sys_slist_t maps;
	sys_slist_t attachments;
	char *owned_name;
	const char *name;
};

static char *ebpf_bundle_strdup(const char *src)
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

int ebpf_bundle_create(const char *name, struct ebpf_bundle **bundle_out)
{
	struct ebpf_bundle *bundle;

	if (name == NULL || bundle_out == NULL) {
		return -EINVAL;
	}

	bundle = k_malloc(sizeof(*bundle));
	if (bundle == NULL) {
		return -ENOMEM;
	}

	memset(bundle, 0, sizeof(*bundle));
	bundle->owned_name = ebpf_bundle_strdup(name);
	if (bundle->owned_name == NULL) {
		k_free(bundle);
		return -ENOMEM;
	}

	bundle->name = bundle->owned_name;
	k_mutex_init(&bundle->lock);
	sys_slist_init(&bundle->maps);
	sys_slist_init(&bundle->attachments);
	*bundle_out = bundle;

	return 0;
}

int ebpf_bundle_destroy(struct ebpf_bundle *bundle)
{
	int ret = 0;
	int first_error = 0;
	sys_snode_t *node;

	if (bundle == NULL) {
		return -EINVAL;
	}

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

		struct ebpf_attachment *attachment =
			CONTAINER_OF(node, struct ebpf_attachment, owner_node);

		/* Use the _sync variant: it removes the program from the
		 * dispatch snapshot AND waits for every in-flight reader to
		 * finish, so no thread is still executing this bytecode when
		 * we free the memory below.
		 */
		ret = ebpf_prog_disable_sync(attachment->prog);
		if (ret == 0) {
			ret = ebpf_prog_detach(attachment->prog);
		}
		if (ret != 0 && first_error == 0) {
			/* Record the first error but keep going so remaining resources
			 * are still cleaned up. The caller sees the first failure while
			 * we avoid leaking anything we *can* free.
			 */
			first_error = ret;
		}

		/* Only free when disable+detach succeeded; otherwise the program
		 * may still be reachable — leak rather than use-after-free.
		 */
		if (ret == 0) {
			ebpf_prog_destroy(attachment->prog);
			k_free(attachment->owned_insns);
			k_free(attachment->owned_hook_name);
			k_free(attachment->owned_name);
			k_free(attachment);
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
	k_free(bundle->owned_name);
	k_free(bundle);

	return first_error;
}

int ebpf_bundle_add_map(struct ebpf_bundle *bundle,
			const struct ebpf_map_spec *spec,
			struct ebpf_map **map_out)
{
	struct ebpf_map *map;
	int ret;

	if (bundle == NULL || spec == NULL || map_out == NULL) {
		return -EINVAL;
	}

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
			       const struct ebpf_bundle_attachment_spec *spec,
			       struct ebpf_attachment **attachment_out)
{
	struct ebpf_attachment *attachment;
	struct ebpf_attach_target target;
	struct ebpf_prog_image image;
	size_t insn_size;
	int ret;

	if (bundle == NULL || spec == NULL || attachment_out == NULL ||
	    spec->name == NULL || spec->hook_name == NULL ||
	    spec->insns == NULL || spec->insn_cnt == 0U) {
		return -EINVAL;
	}

	attachment = k_malloc(sizeof(*attachment));
	if (attachment == NULL) {
		return -ENOMEM;
	}

	memset(attachment, 0, sizeof(*attachment));
	attachment->owned_name = ebpf_bundle_strdup(spec->name);
	if (attachment->owned_name == NULL) {
		k_free(attachment);
		return -ENOMEM;
	}

	attachment->owned_hook_name = ebpf_bundle_strdup(spec->hook_name);
	if (attachment->owned_hook_name == NULL) {
		k_free(attachment->owned_name);
		k_free(attachment);
		return -ENOMEM;
	}

	insn_size = sizeof(*spec->insns) * spec->insn_cnt;
	attachment->owned_insns = k_malloc(insn_size);
	if (attachment->owned_insns == NULL) {
		k_free(attachment->owned_hook_name);
		k_free(attachment->owned_name);
		k_free(attachment);
		return -ENOMEM;
	}

	memcpy(attachment->owned_insns, spec->insns, insn_size);
	image = (struct ebpf_prog_image) {
		.name = attachment->owned_name,
		.type = spec->type,
		.insns = attachment->owned_insns,
		.insn_cnt = spec->insn_cnt,
	};
	ret = ebpf_prog_create(&image, &attachment->prog);
	if (ret != 0) {
		k_free(attachment->owned_insns);
		k_free(attachment->owned_hook_name);
		k_free(attachment->owned_name);
		k_free(attachment);
		return ret;
	}
	attachment->owner_node.next = NULL;

	attachment->owner = bundle;
	ret = ebpf_hook_name_to_target(spec->hook_name, &target);
	if (ret == 0) {
		ret = ebpf_prog_attach(attachment->prog, target);
	}
	if (ret != 0) {
		ebpf_prog_destroy(attachment->prog);
		k_free(attachment->owned_insns);
		k_free(attachment->owned_hook_name);
		k_free(attachment->owned_name);
		k_free(attachment);
		return ret;
	}

	k_mutex_lock(&bundle->lock, K_FOREVER);
	sys_slist_append(&bundle->attachments, &attachment->owner_node);
	k_mutex_unlock(&bundle->lock);

	*attachment_out = attachment;

	return 0;
}

int ebpf_bundle_enable(struct ebpf_bundle *bundle)
{
	struct ebpf_attachment *attachment;
	int ret = 0;
	int rollback_ret = 0;

	if (bundle == NULL) {
		return -EINVAL;
	}

	k_mutex_lock(&bundle->lock, K_FOREVER);
	SYS_SLIST_FOR_EACH_CONTAINER(&bundle->attachments, attachment, owner_node) {
		ret = ebpf_prog_enable(attachment->prog);
		if (ret != 0) {
			break;
		}
	}

	if (ret != 0) {
		SYS_SLIST_FOR_EACH_CONTAINER(&bundle->attachments, attachment, owner_node) {
			int disable_ret = ebpf_prog_disable(attachment->prog);

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
	struct ebpf_attachment *attachment;
	int ret;
	int first_error = 0;

	if (bundle == NULL) {
		return -EINVAL;
	}

	k_mutex_lock(&bundle->lock, K_FOREVER);
	SYS_SLIST_FOR_EACH_CONTAINER(&bundle->attachments, attachment, owner_node) {
		ret = ebpf_prog_disable(attachment->prog);
		if (ret != 0 && first_error == 0) {
			first_error = ret;
		}
	}
	k_mutex_unlock(&bundle->lock);

	return first_error;
}

struct ebpf_map *ebpf_bundle_find_map(struct ebpf_bundle *bundle,
				      const char *name)
{
	struct ebpf_bundle_map_ref *ref;
	struct ebpf_map *map = NULL;

	if (bundle == NULL || name == NULL) {
		return NULL;
	}

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
