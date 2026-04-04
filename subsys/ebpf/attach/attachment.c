/*
 * SPDX-FileCopyrightText: Copyright 2026 NXP
 *
 * SPDX-License-Identifier: Apache-2.0
 */

#include <string.h>

#include <zephyr/kernel.h>

#include "attachment.h"
#include "hook/hook.h"

struct ebpf_attachment {
	struct ebpf_prog *prog;
	char *name;
	char *hook_name;
	struct ebpf_insn *insns;
};

static char *ebpf_attachment_strdup(const char *src)
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

static void ebpf_attachment_free(struct ebpf_attachment *attachment)
{
	if (attachment == NULL) {
		return;
	}

	k_free(attachment->insns);
	k_free(attachment->hook_name);
	k_free(attachment->name);
	k_free(attachment);
}

int ebpf_attachment_create(const struct ebpf_attachment_spec *spec,
			   struct ebpf_attachment **attachment_out)
{
	struct ebpf_attachment *attachment;
	struct ebpf_attach_target target;
	struct ebpf_prog_image image;
	size_t insn_size;
	int ret;

	if (spec == NULL || attachment_out == NULL || spec->name == NULL ||
	    spec->hook_name == NULL || spec->insns == NULL || spec->insn_cnt == 0U ||
	    spec->type >= EBPF_PROG_TYPE_MAX) {
		return -EINVAL;
	}

	attachment = k_malloc(sizeof(*attachment));
	if (attachment == NULL) {
		return -ENOMEM;
	}

	memset(attachment, 0, sizeof(*attachment));
	attachment->name = ebpf_attachment_strdup(spec->name);
	if (attachment->name == NULL) {
		ebpf_attachment_free(attachment);
		return -ENOMEM;
	}

	attachment->hook_name = ebpf_attachment_strdup(spec->hook_name);
	if (attachment->hook_name == NULL) {
		ebpf_attachment_free(attachment);
		return -ENOMEM;
	}

	insn_size = sizeof(*spec->insns) * spec->insn_cnt;
	attachment->insns = k_malloc(insn_size);
	if (attachment->insns == NULL) {
		ebpf_attachment_free(attachment);
		return -ENOMEM;
	}

	memcpy(attachment->insns, spec->insns, insn_size);
	image = (struct ebpf_prog_image) {
		.name = attachment->name,
		.type = spec->type,
		.insns = attachment->insns,
		.insn_cnt = spec->insn_cnt,
	};

	ret = ebpf_prog_create(&image, &attachment->prog);
	if (ret != 0) {
		ebpf_attachment_free(attachment);
		return ret;
	}

	ret = ebpf_hook_name_to_target(spec->hook_name, &target);
	if (ret == 0) {
		ret = ebpf_prog_attach(attachment->prog, target);
	}
	if (ret != 0) {
		ebpf_prog_destroy(attachment->prog);
		attachment->prog = NULL;
		ebpf_attachment_free(attachment);
		return ret;
	}

	*attachment_out = attachment;

	return 0;
}

int ebpf_attachment_destroy(struct ebpf_attachment *attachment)
{
	if (attachment == NULL) {
		return -EINVAL;
	}

	int ret;

	ret = ebpf_prog_disable_sync(attachment->prog);
	if (ret == 0) {
		ret = ebpf_prog_detach(attachment->prog);
	}
	if (ret != 0) {
		return ret;
	}

	ebpf_prog_destroy(attachment->prog);
	attachment->prog = NULL;
	ebpf_attachment_free(attachment);

	return 0;
}

int ebpf_attachment_enable(struct ebpf_attachment *attachment)
{
	if (attachment == NULL) {
		return -EINVAL;
	}

	return ebpf_prog_enable(attachment->prog);
}

int ebpf_attachment_disable(struct ebpf_attachment *attachment)
{
	if (attachment == NULL) {
		return -EINVAL;
	}

	return ebpf_prog_disable(attachment->prog);
}

int ebpf_attachment_disable_sync(struct ebpf_attachment *attachment)
{
	if (attachment == NULL) {
		return -EINVAL;
	}

	return ebpf_prog_disable_sync(attachment->prog);
}

const char *ebpf_attachment_name(const struct ebpf_attachment *attachment)
{
	return attachment != NULL ? attachment->name : NULL;
}

const char *ebpf_attachment_hook_name(const struct ebpf_attachment *attachment)
{
	return attachment != NULL ? attachment->hook_name : NULL;
}
