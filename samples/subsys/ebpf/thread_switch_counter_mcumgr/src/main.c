/*
 * SPDX-FileCopyrightText: Copyright 2026 NXP
 *
 * SPDX-License-Identifier: Apache-2.0
 */

/**
 * @file
 * @brief Thread-switch counter sample driven by remote MCUmgr bundle delivery.
 */

#include <zephyr/kernel.h>
#include <zephyr/sys/printk.h>

#define WORKER_STACK_SIZE  1024
#define WORKER_PRIORITY    7
#define WORKER_SLEEP_MS    1

static K_THREAD_STACK_DEFINE(worker_stack, WORKER_STACK_SIZE);
static struct k_thread worker_thread;

static void sample_worker(void *arg0, void *arg1, void *arg2)
{
	ARG_UNUSED(arg0);
	ARG_UNUSED(arg1);
	ARG_UNUSED(arg2);

	while (true) {
		k_msleep(WORKER_SLEEP_MS);
	}
}

int main(void)
{
	printk("eBPF thread-switch counter over MCUmgr\n");
	printk("====================================\n\n");
	printk("This firmware only generates thread-switch activity.\n");
	printk("Use the MCUmgr eBPF group to load probes and read maps remotely.\n\n");

	k_thread_create(&worker_thread, worker_stack, WORKER_STACK_SIZE,
			sample_worker, NULL, NULL, NULL,
			WORKER_PRIORITY, 0, K_NO_WAIT);

	while (true) {
		k_sleep(K_SECONDS(1));
	}

	return 0;
}