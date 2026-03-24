/*
 * SPDX-FileCopyrightText: Copyright 2026 NXP
 *
 * SPDX-License-Identifier: Apache-2.0
 */

#include <string.h>

#include <zephyr/logging/log.h>

#include <zephyr/ebpf/ebpf_prog.h>

LOG_MODULE_REGISTER(ebpf_prog, CONFIG_EBPF_LOG_LEVEL);

int ebpf_verify(const struct ebpf_prog *prog);
bool ebpf_attach_target_is_valid(const struct ebpf_attach_target *target);
bool ebpf_prog_can_attach_target(enum ebpf_prog_type type,
				 const struct ebpf_attach_target *target);

void ebpf_prog_init(struct ebpf_prog *prog, const char *name,
		    enum ebpf_prog_type type, const struct ebpf_insn *insns,
		    uint32_t insn_cnt)
{
	if (prog == NULL) {
		return;
	}

	memset(prog, 0, sizeof(*prog));
	prog->name = name;
	prog->type = type;
	prog->insns = insns;
	prog->insn_cnt = insn_cnt;
	prog->runtime.state = EBPF_PROG_STATE_DETACHED;
	prog->runtime.target = EBPF_ATTACH_TARGET_NONE;
}

int ebpf_prog_attach(struct ebpf_prog *prog, struct ebpf_attach_target target)
{
	if (prog == NULL) {
		return -EINVAL;
	}

	if (!ebpf_attach_target_is_valid(&target)) {
		LOG_ERR("Program '%s' has invalid target backend=%d point=%u",
			prog->name, target.backend, target.point);
		return -EINVAL;
	}

	if (!ebpf_prog_can_attach_target(prog->type, &target)) {
		LOG_ERR("Program '%s' type %d incompatible with %s",
			prog->name, prog->type, ebpf_attach_target_name(&target));
		return -EINVAL;
	}

	k_spinlock_key_t key = k_spin_lock(&prog->runtime.lock);

	if (prog->runtime.state != EBPF_PROG_STATE_DETACHED) {
		k_spin_unlock(&prog->runtime.lock, key);
		LOG_WRN("Program '%s' already attached to %s",
			prog->name, ebpf_attach_target_name(&prog->runtime.target));
		return -EALREADY;
	}

	prog->runtime.target = target;
	prog->runtime.session_seq++;
	prog->runtime.state = EBPF_PROG_STATE_ATTACHED;
	prog->runtime.stats.run_count = 0;
	prog->runtime.stats.run_time_ns = 0;

	k_spin_unlock(&prog->runtime.lock, key);

	LOG_DBG("Program '%s' attached to %s", prog->name,
		ebpf_attach_target_name(&prog->runtime.target));

	return 0;
}

int ebpf_prog_detach(struct ebpf_prog *prog)
{
	if (prog == NULL) {
		return -EINVAL;
	}

	k_spinlock_key_t key = k_spin_lock(&prog->runtime.lock);

	if (prog->runtime.state == EBPF_PROG_STATE_DETACHED) {
		k_spin_unlock(&prog->runtime.lock, key);
		LOG_DBG("Program '%s' already detached", prog->name);
		return 0;
	}

	if (prog->runtime.state == EBPF_PROG_STATE_ENABLED) {
		ebpf_attach_target_dec(&prog->runtime.target);
	}

	prog->runtime.target = EBPF_ATTACH_TARGET_NONE;
	prog->runtime.session_seq++;
	prog->runtime.state = EBPF_PROG_STATE_DETACHED;
	prog->runtime.stats.run_count = 0;
	prog->runtime.stats.run_time_ns = 0;

	k_spin_unlock(&prog->runtime.lock, key);

	LOG_DBG("Program '%s' detached", prog->name);

	return 0;
}

int ebpf_prog_verify(struct ebpf_prog *prog)
{
	if (prog == NULL) {
		return -EINVAL;
	}

	k_spinlock_key_t key = k_spin_lock(&prog->runtime.lock);

	if (prog->runtime.state == EBPF_PROG_STATE_DETACHED) {
		k_spin_unlock(&prog->runtime.lock, key);
		LOG_ERR("Program '%s' is not attached", prog->name);
		return -ENOENT;
	}

	if (prog->runtime.state == EBPF_PROG_STATE_VERIFIED ||
	    prog->runtime.state == EBPF_PROG_STATE_ENABLED) {
		k_spin_unlock(&prog->runtime.lock, key);
		LOG_DBG("Program '%s' already verified for current attachment", prog->name);
		return 0;
	}

	/* Capture the current session_seq to detect any session changes during verification. */
	uint32_t session_seq = prog->runtime.session_seq;

	k_spin_unlock(&prog->runtime.lock, key);

	/* Verification runs without holding the runtime lock. The result is committed
	 * only if the program is still in the same attachment session afterwards.
	 */
	int ret = ebpf_verify(prog);
	if (ret != 0) {
		LOG_ERR("Verification failed for '%s': %d", prog->name, ret);
		return ret;
	}

	key = k_spin_lock(&prog->runtime.lock);
	if (prog->runtime.state == EBPF_PROG_STATE_DETACHED ||
	    prog->runtime.session_seq != session_seq) {
		k_spin_unlock(&prog->runtime.lock, key);
		LOG_DBG("Program '%s' session changed during verify", prog->name);
		return -EAGAIN;
	}

	prog->runtime.state = EBPF_PROG_STATE_VERIFIED;
	k_spin_unlock(&prog->runtime.lock, key);

	LOG_DBG("Program '%s' verified", prog->name);

	return 0;
}

int ebpf_prog_enable(struct ebpf_prog *prog)
{
	if (prog == NULL) {
		return -EINVAL;
	}

	k_spinlock_key_t key = k_spin_lock(&prog->runtime.lock);

	if (prog->runtime.state == EBPF_PROG_STATE_DETACHED) {
		k_spin_unlock(&prog->runtime.lock, key);
		LOG_ERR("Program '%s' is not attached", prog->name);
		return -ENOENT;
	}

	if (prog->runtime.state == EBPF_PROG_STATE_ENABLED) {
		k_spin_unlock(&prog->runtime.lock, key);
		LOG_DBG("Program '%s' already enabled for current attachment", prog->name);
		return 0;
	}

	k_spin_unlock(&prog->runtime.lock, key);

	int ret = ebpf_prog_verify(prog);
	if (ret != 0) {
		LOG_ERR("Enable failed for '%s': %d", prog->name, ret);
		return ret;
	}

	key = k_spin_lock(&prog->runtime.lock);
	ret = 0;

	if (prog->runtime.state == EBPF_PROG_STATE_VERIFIED) {
		prog->runtime.state = EBPF_PROG_STATE_ENABLED;
		ebpf_attach_target_inc(&prog->runtime.target);
	} else if (prog->runtime.state != EBPF_PROG_STATE_ENABLED) {
		ret = -EAGAIN;
	}

	k_spin_unlock(&prog->runtime.lock, key);
	if (ret != 0) {
		LOG_DBG("Program '%s' state changed during enable", prog->name);
		return ret;
	}

	LOG_DBG("Program '%s' enabled", prog->name);

	return 0;
}

int ebpf_prog_disable(struct ebpf_prog *prog)
{
	if (prog == NULL) {
		return -EINVAL;
	}

	k_spinlock_key_t key = k_spin_lock(&prog->runtime.lock);
	if (prog->runtime.state != EBPF_PROG_STATE_ENABLED) {
		k_spin_unlock(&prog->runtime.lock, key);
		LOG_DBG("Program '%s' already not enabled", prog->name);
		return 0;
	}

	ebpf_attach_target_dec(&prog->runtime.target);
	prog->runtime.state = EBPF_PROG_STATE_VERIFIED;

	k_spin_unlock(&prog->runtime.lock, key);

	LOG_DBG("Program '%s' disabled", prog->name);

	return 0;
}

enum ebpf_prog_state ebpf_prog_get_state(const struct ebpf_prog *prog)
{
	enum ebpf_prog_state state = EBPF_PROG_STATE_DETACHED;
	k_spinlock_key_t key;

	if (prog == NULL) {
		return state;
	}

	key = k_spin_lock((struct k_spinlock *)&prog->runtime.lock);
	state = prog->runtime.state;
	k_spin_unlock((struct k_spinlock *)&prog->runtime.lock, key);

	return state;
}

struct ebpf_attach_target ebpf_prog_get_target(const struct ebpf_prog *prog)
{
	struct ebpf_attach_target target = EBPF_ATTACH_TARGET_NONE;
	k_spinlock_key_t key;

	if (prog == NULL) {
		return target;
	}

	key = k_spin_lock((struct k_spinlock *)&prog->runtime.lock);
	target = prog->runtime.target;
	k_spin_unlock((struct k_spinlock *)&prog->runtime.lock, key);

	return target;
}

struct ebpf_prog_stats ebpf_prog_get_stats(const struct ebpf_prog *prog)
{
	struct ebpf_prog_stats stats = { 0, 0 };
	k_spinlock_key_t key;

	if (prog == NULL) {
		return stats;
	}

	key = k_spin_lock((struct k_spinlock *)&prog->runtime.lock);
	stats = prog->runtime.stats;
	k_spin_unlock((struct k_spinlock *)&prog->runtime.lock, key);

	return stats;
}
