/*
 * SPDX-FileCopyrightText: Copyright 2026 NXP
 *
 * SPDX-License-Identifier: Apache-2.0
 *
 * RT7xx Compute power domain (PMC0 / SLEEPCON0) low-power modes.
 *
 * This translation unit supplies the Compute domain instance and its mode table;
 * all sequencing lives in power_common.c. The Compute domain owns the VDD2 rails,
 * runs XIP, has the HiFi DSP, and supports DSR (STANDBY) in addition to deep
 * sleep.
 */

#include <zephyr/kernel.h>

#include "power_domain.h"
#include "power_resources.h"
#include <power_sram_banks.h>
#include "power_modes.h"

#include <fsl_common.h>

#if IS_ENABLED(CONFIG_SOC_MIMXRT7XX_PM_XIP_HANDOVER)
#include "power_xip.h"
#endif

/*
 * Compute-domain SLEEPCFG deep-sleep set: main clocks, oscillators, PLLs, ADC.
 *
 * Most of these are shared modules (RM "Aggregation for shared modules"): the
 * same field exists in SLEEPCON1, and the module only powers down when both
 * SLEEPCONs vote it down. That is what lets the Sense core keep running while
 * Compute sleeps, without Compute having to know about it.
 *
 * FRO0_PD, FRO1_PD and FRO0_GATE are the exception -- they exist only in
 * SLEEPCON0, so there is no arbitration and Compute powers them down
 * unilaterally. CPU1 cannot object; it has no copy of these fields and cannot
 * even reach the FRO0/FRO1 CSRs. Anything on the Sense side must therefore be
 * clocked from FRO2 (shared, and thus arbitrated) rather than FRO0/FRO1 -- see
 * the CPU1 branch of board_early_init_hook(), which uses FRO1 only to bootstrap
 * the Sense base clock and then re-points it at FRO2.
 */
#define COMPUTE_SLEEPCFG_PD (\
	SLEEPCON0_SLEEPCFG_COMP_MAINCLK_SHUTOFF_MASK | \
	SLEEPCON0_SLEEPCFG_SENSEP_MAINCLK_SHUTOFF_MASK | \
	SLEEPCON0_SLEEPCFG_SENSES_MAINCLK_SHUTOFF_MASK | \
	SLEEPCON0_SLEEPCFG_RAM0_CLK_SHUTOFF_MASK | \
	SLEEPCON0_SLEEPCFG_RAM1_CLK_SHUTOFF_MASK | \
	SLEEPCON0_SLEEPCFG_COMN_MAINCLK_SHUTOFF_MASK | \
	SLEEPCON0_SLEEPCFG_MEDIA_MAINCLK_SHUTOFF_MASK | \
	SLEEPCON0_SLEEPCFG_XTAL_PD_MASK | \
	SLEEPCON0_SLEEPCFG_FRO0_PD_MASK | SLEEPCON0_SLEEPCFG_FRO1_PD_MASK | \
	SLEEPCON0_SLEEPCFG_FRO2_PD_MASK | SLEEPCON0_SLEEPCFG_LPOSC_PD_MASK | \
	SLEEPCON0_SLEEPCFG_PLLANA_PD_MASK | SLEEPCON0_SLEEPCFG_PLLLDO_PD_MASK | \
	SLEEPCON0_SLEEPCFG_AUDPLLANA_PD_MASK | SLEEPCON0_SLEEPCFG_AUDPLLLDO_PD_MASK | \
	SLEEPCON0_SLEEPCFG_ADC0_PD_MASK | SLEEPCON0_SLEEPCFG_FRO0_GATE_MASK | \
	SLEEPCON0_SLEEPCFG_FRO2_GATE_MASK)

/* PLL subset, for the PMCREF_LP decision and the PLL keep-alive below. */
#define RES_CLK_PLL (\
	SLEEPCON0_SLEEPCFG_PLLANA_PD_MASK | SLEEPCON0_SLEEPCFG_PLLLDO_PD_MASK | \
	SLEEPCON0_SLEEPCFG_AUDPLLANA_PD_MASK | SLEEPCON0_SLEEPCFG_AUDPLLLDO_PD_MASK)

/*
 * Both PLLs stay powered across the window. The low-power entry/exit path has no
 * PLL re-lock step, so a powered-down PLL would come back unlocked and leave the
 * compute domain without its main clock. Dropping this needs the clock driver to
 * own PLL suspend/resume; until then the PLLs are kept up on purpose.
 *
 * CPU0's code and system caches are retained so they need not be refilled on
 * resume, and the OCOTP shadow RAM is retained because the boot ROM reads it on a
 * warm-reset boot.
 *
 * Deep sleep keeps VDD2_COMP powered, so retaining the compute main-memory arrays
 * (this image's code, stack and data) is enough to resume in place. DSR collapses
 * VDD2_COMP but leaves VDD2_COM (where the arrays live) in retention, so the same
 * array keep-alive carries the image across either window.
 *
 * Nothing is kept alive on the Sense core's (CPU1) account. CPU1 has no PM state
 * of its own; board second_core_boot() takes a pm_policy lock on SUSPEND_TO_IDLE
 * and STANDBY while CPU1 is up, so this path is never reached while Sense runs.
 */
#define COMPUTE_DEEP_KEEP								\
	{										\
		.clk = RES_CLK_PLL,							\
		.sram_array = POWER_SRAM_KEEPALIVE,					\
		.pram_array = RES_CPU0_CCACHE | RES_CPU0_SCACHE | RES_OCOTP,		\
	}

static const struct power_mode_desc compute_deep_sleep = {
	.collapse_vdd2_core = false,
	.full_dsr = false,
	.keep = COMPUTE_DEEP_KEEP,
	.pmic_mode = 1U,
};

static const struct power_mode_desc compute_dsr = {
	.collapse_vdd2_core = true,
	.full_dsr = true,
	.keep = COMPUTE_DEEP_KEEP,
	.pmic_mode = 1U,
};

/*
 * FRO0/FRO1 are owned by the Compute domain -- SLEEPCON1 has no control bits for
 * them at all, so no other domain can hold them up and their power-down-ready
 * really does arrive. Clear the ignore bit so SLEEPCON waits for that handshake
 * before the domain powers down (IGN_*PDR: 0 = wait, 1 = ignore). This re-asserts
 * the reset default defensively -- the bits are sticky and nothing else clears
 * them. A clock kept alive never powers down, so PWRDOWN_WAIT does not apply and
 * its bit is left untouched. Runs before the XSPI hand-over (flash still live),
 * so it need not be RAM-resident.
 */
static void compute_prep_owned_clock_pdr(soc_sleepcon_t *sc, uint32_t keep_clk)
{
	if ((keep_clk & SLEEPCON0_SLEEPCFG_FRO0_PD_MASK) == 0U) {
		sc->PWRDOWN_WAIT &= ~SLEEPCON0_PWRDOWN_WAIT_IGN_FRO0PDR_MASK;
	}
	if ((keep_clk & SLEEPCON0_SLEEPCFG_FRO1_PD_MASK) == 0U) {
		sc->PWRDOWN_WAIT &= ~SLEEPCON0_PWRDOWN_WAIT_IGN_FRO1PDR_MASK;
	}
}

/*
 * If this is the first domain entering deep sleep (DSSENS == 0), the Sense domain
 * is still using the shared FRO2/LPOSC, whose power-down-ready would never arrive;
 * tell the PMC not to wait for them or the state machine hangs (WFI falls back to
 * plain sleep). Set-and-never-clear, matching MCUXpresso. Resident in RAM because
 * it runs after the XSPI hand-over.
 */
AT_QUICKACCESS_SECTION_CODE(static void compute_arm_shared_clock_pdr_ignores(soc_sleepcon_t *sc))
{
	if ((PMC0->STATUS & PMC_STATUS_DSSENS_MASK) == 0U) {
		sc->PWRDOWN_WAIT |= SLEEPCON0_PWRDOWN_WAIT_IGN_FRO2PDR_MASK |
				    SLEEPCON0_PWRDOWN_WAIT_IGN_LPOSCPDR_MASK;
	}
}

/*
 * Stall the HiFi DSP if VDD2_DSP is about to power down while the DSP might still
 * be running: an in-flight AHB transaction at power-off would hang the bus. The
 * stall is not lifted on resume -- the domain was powered off, so whoever owns
 * the DSP (dsp_ctrl / remoteproc) must re-release it with a fresh image. SYSCON0
 * lives only in the Compute (core0) header set, so this access stays in this TU.
 */
static void compute_stall_dsp_if_powered_down(const struct power_domain *dom)
{
	if ((dom->pmc->PDSLEEPCFG0 & PMC_PDSLEEPCFG0_V2DSP_PD_MASK) != 0U) {
		SYSCON0->DSPSTALL = SYSCON0_DSPSTALL_DSPSTALL_MASK;
	}
}

static const struct power_domain compute_domain = {
	.pmc = PMC0,
	.sleepcon = SLEEPCON0,
	.sleepcfg_pd = COMPUTE_SLEEPCFG_PD,
	.sleepcfg_pll = RES_CLK_PLL,
	.ldo_vsel_clear = PMC_PDSLEEPCFG0_LDO1_VSEL_MASK,
	.stall_dsp_if_powered_down = compute_stall_dsp_if_powered_down,
	.prep_owned_clock_pdr = compute_prep_owned_clock_pdr,
	.arm_shared_clock_pdr_ignores = compute_arm_shared_clock_pdr_ignores,
	.regulator = &power_ldo_regulator_ops,
#if IS_ENABLED(CONFIG_SOC_MIMXRT7XX_PM_XIP_HANDOVER)
	.xip_suspend = power_xip_suspend,
	.xip_resume = power_xip_resume,
#endif
};

AT_QUICKACCESS_SECTION_CODE(void power_enter_deep_sleep(void))
{
	power_enter_common(&compute_domain, &compute_deep_sleep);
}

AT_QUICKACCESS_SECTION_CODE(void power_enter_dsr(void))
{
	power_enter_common(&compute_domain, &compute_dsr);
}
