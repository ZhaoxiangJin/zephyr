/*
 * SPDX-FileCopyrightText: Copyright 2026 NXP
 *
 * SPDX-License-Identifier: Apache-2.0
 *
 * RT7xx Sense power domain (PMC1 / SLEEPCON1) low-power modes.
 *
 * This translation unit supplies the Sense domain instance and its mode table;
 * all sequencing lives in power_common.c. The Sense domain has no DSR mode, no
 * XIP/cache responsibility and no DSP, so those domain flags are false and the
 * XIP hooks stay NULL (this TU never links the XIP object).
 */

#include <zephyr/kernel.h>

#include "power_domain.h"
#include "power_resources.h"
#include <power_sram_banks.h>
#include "power_modes.h"

#include <fsl_common.h>

/* Sense-domain SLEEPCFG deep-sleep set. No COMP main clock, no FRO0/FRO1. */
#define SENSE_SLEEPCFG_PD (\
	SLEEPCON1_SLEEPCFG_SENSEP_MAINCLK_SHUTOFF_MASK | \
	SLEEPCON1_SLEEPCFG_SENSES_MAINCLK_SHUTOFF_MASK | \
	SLEEPCON1_SLEEPCFG_RAM0_CLK_SHUTOFF_MASK | \
	SLEEPCON1_SLEEPCFG_RAM1_CLK_SHUTOFF_MASK | \
	SLEEPCON1_SLEEPCFG_COMN_MAINCLK_SHUTOFF_MASK | \
	SLEEPCON1_SLEEPCFG_MEDIA_MAINCLK_SHUTOFF_MASK | \
	SLEEPCON1_SLEEPCFG_XTAL_PD_MASK | \
	SLEEPCON1_SLEEPCFG_FRO2_PD_MASK | SLEEPCON1_SLEEPCFG_LPOSC_PD_MASK | \
	SLEEPCON1_SLEEPCFG_PLLANA_PD_MASK | SLEEPCON1_SLEEPCFG_PLLLDO_PD_MASK | \
	SLEEPCON1_SLEEPCFG_AUDPLLANA_PD_MASK | SLEEPCON1_SLEEPCFG_AUDPLLLDO_PD_MASK | \
	SLEEPCON1_SLEEPCFG_ADC0_PD_MASK | SLEEPCON1_SLEEPCFG_FRO2_GATE_MASK)

#define RES_CLK_PLL (\
	SLEEPCON1_SLEEPCFG_PLLANA_PD_MASK | SLEEPCON1_SLEEPCFG_PLLLDO_PD_MASK | \
	SLEEPCON1_SLEEPCFG_AUDPLLANA_PD_MASK | SLEEPCON1_SLEEPCFG_AUDPLLLDO_PD_MASK)

/*
 * The Sense core executes from the SRAM18..SRAM29 partitions (the sram_code
 * region in the CPU1 devicetree), so their arrays must be retained or the image
 * is gone on wake. The periphery is left to power down: nothing accesses those
 * arrays while the core is asleep.
 *
 * Nothing else has to survive on the Sense core's account. The PMC aggregates the
 * two domains' votes, so the Sense domain does not have to keep the shared clocks
 * or the VDD2 rails alive on the Compute core's behalf -- while the Compute core
 * is active its own run configuration holds them up. That is why the Sense
 * deep-sleep mode collapses the core rails (collapse_vdd2_core) yet keeps only its
 * own SRAM: its votes are aggregated away while Compute runs.
 */
static const struct power_mode_desc sense_deep_sleep = {
	.collapse_vdd2_core = true,
	.full_dsr = false,
	.keep = {
		.sram_array = POWER_SRAM_KEEPALIVE,
	},
	.pmic_mode = 1U,
};

/*
 * FRO2 and LPOSC are shared with the Compute domain and never owned by Sense, so
 * their power-down-ready may never arrive; tell the PMC not to wait for it or the
 * state machine hangs. Unconditional (unlike Compute, Sense is not the arbiter of
 * "first domain down"). Set-and-never-clear, matching MCUXpresso.
 */
static void sense_arm_shared_clock_pdr_ignores(soc_sleepcon_t *sc)
{
	sc->PWRDOWN_WAIT |=
		SLEEPCON1_PWRDOWN_WAIT_IGN_FRO2PDR_MASK | SLEEPCON1_PWRDOWN_WAIT_IGN_LPOSCPDR_MASK;
}

static const struct power_domain sense_domain = {
	.pmc = PMC1,
	.sleepcon = SLEEPCON1,
	.sleepcfg_pd = SENSE_SLEEPCFG_PD,
	.sleepcfg_pll = RES_CLK_PLL,
	.ldo_vsel_clear = PMC_PDSLEEPCFG0_LDO2_VSEL_MASK,
	.arm_shared_clock_pdr_ignores = sense_arm_shared_clock_pdr_ignores,
	.regulator = &power_ldo_regulator_ops,
	.xip_suspend = NULL,
	.xip_resume = NULL,
};

void power_enter_deep_sleep(void)
{
	power_enter_common(&sense_domain, &sense_deep_sleep);
}
