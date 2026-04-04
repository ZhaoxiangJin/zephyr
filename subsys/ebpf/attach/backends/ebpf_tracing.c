/*
 * SPDX-FileCopyrightText: Copyright 2026 NXP
 *
 * SPDX-License-Identifier: Apache-2.0
 */

#include <tracing_user.h>

#include <zephyr/kernel.h>
#include <zephyr/kernel_structs.h>

#include "../ebpf_attach_target_internal.h"

#if defined(CONFIG_ARM)
#include <zephyr/arch/arm/irq.h>
#elif defined(CONFIG_ARM64)
#include <zephyr/arch/arm64/irq.h>
#elif defined(CONFIG_ARCH_POSIX)
#include <zephyr/arch/posix/posix_soc_if.h>
#endif

static const struct ebpf_attach_target thread_switched_in_target =
	EBPF_ATTACH_TARGET_TRACING(EBPF_TRACING_ATTACH_THREAD_SWITCHED_IN);
static const struct ebpf_attach_target thread_switched_out_target =
	EBPF_ATTACH_TARGET_TRACING(EBPF_TRACING_ATTACH_THREAD_SWITCHED_OUT);

static const struct ebpf_attach_target isr_enter_target =
	EBPF_ATTACH_TARGET_TRACING(EBPF_TRACING_ATTACH_ISR_ENTER);
static const struct ebpf_attach_target isr_exit_target =
	EBPF_ATTACH_TARGET_TRACING(EBPF_TRACING_ATTACH_ISR_EXIT);
static const struct ebpf_attach_target idle_enter_target =
	EBPF_ATTACH_TARGET_TRACING(EBPF_TRACING_ATTACH_IDLE_ENTER);
static const struct ebpf_attach_target idle_exit_target =
	EBPF_ATTACH_TARGET_TRACING(EBPF_TRACING_ATTACH_IDLE_EXIT);

static uint32_t ebpf_tracing_get_active_irq_num(void)
{
#if defined(CONFIG_ARM)
	#if defined(CONFIG_ARM_CUSTOM_INTERRUPT_CONTROLLER) || defined(CONFIG_MULTI_LEVEL_INTERRUPTS)
	unsigned int active_irq = z_soc_irq_get_active();
	#elif defined(CONFIG_CPU_CORTEX_M)
	unsigned int active_irq = __get_IPSR();
	#else
	return 0U;
	#endif

	return active_irq >= 16U ? active_irq - 16U : 0U;
#elif defined(CONFIG_ARM64)
	return z_soc_irq_get_active();
#elif defined(CONFIG_ARCH_POSIX)
	return (uint32_t)posix_get_current_irq();
#else
	return 0U;
#endif
}

/** @brief Dispatch thread-switch-in tracing events to attached eBPF programs. */
void sys_trace_thread_switched_in_user(void)
{
	if (ebpf_attach_target_is_active(&thread_switched_in_target)) {
		struct k_thread *thread = k_sched_current_thread_query();
		struct ebpf_ctx_thread ctx = {
			.thread_cookie = (uint64_t)(uintptr_t)thread,
			.priority = thread->base.prio,
		};

		ebpf_attach_target_dispatch(&thread_switched_in_target, &ctx, sizeof(ctx));
	}
}

/** @brief Dispatch thread-switch-out tracing events to attached eBPF programs. */
void sys_trace_thread_switched_out_user(void)
{
	if (ebpf_attach_target_is_active(&thread_switched_out_target)) {
		struct k_thread *thread = k_sched_current_thread_query();
		struct ebpf_ctx_thread ctx = {
			.thread_cookie = (uint64_t)(uintptr_t)thread,
			.priority = thread->base.prio,
		};

		ebpf_attach_target_dispatch(&thread_switched_out_target, &ctx, sizeof(ctx));
	}
}

/** @brief Dispatch ISR-entry tracing events to attached eBPF programs. */
void sys_trace_isr_enter_user(void)
{
	if (ebpf_attach_target_is_active(&isr_enter_target)) {
		struct ebpf_ctx_isr ctx = {
			.irq_num = ebpf_tracing_get_active_irq_num(),
		};

		ebpf_attach_target_dispatch(&isr_enter_target, &ctx, sizeof(ctx));
	}
}

/**  @brief Dispatch ISR-exit tracing events to attached eBPF programs. */
void sys_trace_isr_exit_user(void)
{
	if (ebpf_attach_target_is_active(&isr_exit_target)) {
		struct ebpf_ctx_isr ctx = {
			.irq_num = ebpf_tracing_get_active_irq_num(),
		};

		ebpf_attach_target_dispatch(&isr_exit_target, &ctx, sizeof(ctx));
	}
}

/** @brief Alias the scheduler handoff hook to the ISR-exit hook. */
void sys_trace_isr_exit_to_scheduler(void)
{
	sys_trace_isr_exit_user();
}

/** @brief Dispatch idle-entry tracing events to attached eBPF programs. */
void sys_trace_idle_user(void)
{
	if (ebpf_attach_target_is_active(&idle_enter_target)) {
		struct ebpf_ctx_idle ctx = {
			.cpu_id = CPU_ID,
		};

		ebpf_attach_target_dispatch(&idle_enter_target, &ctx, sizeof(ctx));
	}
}

/** @brief Dispatch idle-exit tracing events to attached eBPF programs. */
void sys_trace_idle_exit_user(void)
{
	if (ebpf_attach_target_is_active(&idle_exit_target)) {
		struct ebpf_ctx_idle ctx = {
			.cpu_id = CPU_ID,
		};

		ebpf_attach_target_dispatch(&idle_exit_target, &ctx, sizeof(ctx));
	}
}
