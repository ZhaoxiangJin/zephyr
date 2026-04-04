/*
 * SPDX-FileCopyrightText: Copyright 2026 NXP
 *
 * SPDX-License-Identifier: Apache-2.0
 */

/**
 * @file
 * @brief Thread-switch counter eBPF sample.
 *
 * Builds a restricted-C probe bundle at host build time, embeds it into the
 * application image, then loads and enables that bundle through the runtime
 * loader. The loaded probe counts thread-switch events through the stable hook
 * ``kernel/thread_switched_in``.
 */

#include <stdbool.h>
#include <stdint.h>

#include <zephyr/kernel.h>
#include <zephyr/sys/printk.h>

#include <zephyr/ebpf/ebpf_loader.h>

static const uint8_t thread_switch_probe_bundle[] = {
#include "thread_switch_counter.bundle.inc"
};

#define WORKER_STACK_SIZE 1024
#define WORKER_PRIORITY   7
#define SAMPLE_SECONDS    5
#define WORKER_SLEEP_MS   1

static K_THREAD_STACK_DEFINE(worker_a_stack, WORKER_STACK_SIZE);
static struct k_thread worker_a;
static volatile bool workers_should_run = true;

static void sample_worker(void *arg0, void *arg1, void *arg2)
{
	ARG_UNUSED(arg0);
	ARG_UNUSED(arg1);
	ARG_UNUSED(arg2);

	while (workers_should_run) {
		k_msleep(WORKER_SLEEP_MS);
	}
}

int main(void)
{
	struct ebpf_loader_handle *handle;
	uint32_t key = 0U;
	uint32_t previous_count = 0U;
	int ret;

	printk("eBPF thread-switch counter\n");
	printk("==========================\n\n");

	ret = ebpf_loader_load(thread_switch_probe_bundle,
			       sizeof(thread_switch_probe_bundle), &handle);
	if (ret != 0) {
		printk("Failed to load runtime bundle: %d\n", ret);
		return ret;
	}

	ret = ebpf_loader_enable(handle);
	if (ret != 0) {
		printk("Failed to enable runtime bundle: %d\n", ret);
		(void)ebpf_loader_unload(handle);
		return ret;
	}

	printk("Loaded bundle: %s\n", ebpf_loader_name(handle));
	printk("Runtime-loaded probe enabled.\n");

	k_thread_create(&worker_a, worker_a_stack, WORKER_STACK_SIZE,
			sample_worker, NULL, NULL, NULL,
			WORKER_PRIORITY, 0, K_NO_WAIT);

	for (int second = 0; second < SAMPLE_SECONDS; second++) {
		uint32_t current_count;

		k_sleep(K_SECONDS(1));

		ret = ebpf_loader_map_lookup_copy(handle, "counter_map",
						  &key, &current_count,
						  sizeof(current_count));
		if (ret != 0) {
			printk("Runtime map lookup failed: %d\n", ret);
			workers_should_run = false;
			break;
		}

		printk("[%d] thread_switched_in count=%u (+%u)\n",
			second + 1, current_count,
			current_count - previous_count);
		previous_count = current_count;
	}

	workers_should_run = false;
	k_thread_abort(&worker_a);

	ret = ebpf_loader_disable(handle);
	if (ret != 0) {
		printk("Failed to disable runtime bundle: %d\n", ret);
		return ret;
	}

	ret = ebpf_loader_unload(handle);
	if (ret != 0) {
		printk("Failed to unload runtime bundle: %d\n", ret);
		return ret;
	}

	printk("Runtime-loaded bundle unloaded.\n");
	printk("Thread-switch counter sample complete.\n");

	return 0;
}
