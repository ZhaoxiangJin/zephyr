/*
 * SPDX-FileCopyrightText: Copyright 2026 NXP
 *
 * SPDX-License-Identifier: Apache-2.0
 *
 * Shared RT7xx CM33 low-power entry sequence.
 *
 * One power_enter_common() drives every (domain, mode) pair: deep sleep and DSR
 * on the Compute domain, deep sleep on Sense, and DPD/FDPD on either. The
 * per-domain and per-mode facts arrive as data (struct power_domain /
 * struct power_mode_desc); this file owns the sequencing and the
 * resource -> register programming, in one place, so the two domains cannot
 * drift apart.
 */

#include <zephyr/kernel.h>
#include <zephyr/arch/arch_interface.h>

#include "power_domain.h"
#include "power_resources.h"

#include <fsl_common.h>

/*
 * PDSLEEPCFG0 voltage-domain vote sets, as a strict layering (RM 31.2):
 *   base            deep sleep: collapse the media/DSP rails, retain the core rails.
 *   core (DSR/DPD)  additionally collapse VDD2_COMP + VDD2_COM.
 * DPD/FDPD are the core vote set plus the [DPD]/[FDPD] override bit.
 */
#define PDSLPCFG0_BASE_VOTES (\
	PMC_PDSLEEPCFG0_V2DSP_PD_MASK | PMC_PDSLEEPCFG0_V2MIPI_PD_MASK | \
	PMC_PDSLEEPCFG0_V2NMED_DSR_MASK | PMC_PDSLEEPCFG0_VNCOM_DSR_MASK)

#define PDSLPCFG0_CORE_VOTES (PMC_PDSLEEPCFG0_V2COMP_DSR_MASK | PMC_PDSLEEPCFG0_V2COM_DSR_MASK)

/* Mode / override bits cleared before each entry so a stale value cannot leak. */
#define PDSLPCFG0_MODE_BITS (\
	PMC_PDSLEEPCFG0_FDSR_MASK | PMC_PDSLEEPCFG0_DPD_MASK | PMC_PDSLEEPCFG0_FDPD_MASK | \
	PMC_PDSLEEPCFG0_PMICMODE_MASK)

/*
 * PDSLEEPCFG1 deep-sleep set: analog references, brown-out detectors, ROM, OTP,
 * and PMCREF_LP (drop the reference to low-power mode). Identical bit set on both
 * domains -- it lives on the shared PMC register layout.
 */
#define PDSLPCFG1_DEEP_SLEEP (\
	PMC_PDSLEEPCFG1_TEMP_PD_MASK | PMC_PDSLEEPCFG1_PMCREF_LP_MASK | \
	PMC_PDSLEEPCFG1_HVD1V8_PD_MASK | PMC_PDSLEEPCFG1_POR1_LP_MASK | \
	PMC_PDSLEEPCFG1_LVD1_LP_MASK | PMC_PDSLEEPCFG1_HVD1_PD_MASK | \
	PMC_PDSLEEPCFG1_AGDET1_PD_MASK | PMC_PDSLEEPCFG1_POR2_LP_MASK | \
	PMC_PDSLEEPCFG1_LVD2_LP_MASK | PMC_PDSLEEPCFG1_HVD2_PD_MASK | \
	PMC_PDSLEEPCFG1_AGDET2_PD_MASK | PMC_PDSLEEPCFG1_PORN_LP_MASK | \
	PMC_PDSLEEPCFG1_LVDN_LP_MASK | PMC_PDSLEEPCFG1_HVDN_PD_MASK | \
	PMC_PDSLEEPCFG1_OTP_PD_MASK | PMC_PDSLEEPCFG1_ROM_PD_MASK | PMC_PDSLEEPCFG1_SRAMSLEEP_MASK)

/*
 * Deep-sleep default for the memory-array registers: power everything down
 * except what the keep-alive set retains.
 */
#define PDSLPCFG2_5_DEEP_SLEEP (0xFFFFFFFFU)

/* -------------------------------------------------------------------------- */
/* Programming steps. Ordering and masks match the pre-refactor drivers        */
/* bit-for-bit; see power_domain.h for the model.                              */
/* -------------------------------------------------------------------------- */

static void program_sleepcfg(const struct power_domain *dom, const struct power_resource_set *keep)
{
	soc_sleepcon_t *sc = dom->sleepcon;

	sc->SLEEPCFG = (dom->sleepcfg_pd & ~keep->clk) | (sc->RUNCFG & ~keep->clk);

	/*
	 * A domain-owned clock being powered down has a power-down-ready that
	 * really arrives, so make SLEEPCON wait for that handshake. Only the
	 * Compute domain owns such clocks (FRO0/FRO1); Sense has none, so the hook
	 * is NULL there. Shared clocks (FRO2/LPOSC) go the other way and are
	 * handled by arm_shared_clock_pdr_ignores.
	 */
	if (dom->prep_owned_clock_pdr != NULL) {
		dom->prep_owned_clock_pdr(sc, keep->clk);
	}
}

/*
 * Program PDSLEEPCFG0 voltage domains as base [+ core] [+ override], filtered so
 * a mode never collapses a rail whose companion is kept up (RM 31.2 dependency
 * rules). PMIC/LDO fields are programmed separately by the regulator ops.
 */
static void program_pdslpcfg0(const struct power_domain *dom, const struct power_mode_desc *mode)
{
	PMC_Type *pmc = dom->pmc;

	uint32_t votes = PDSLPCFG0_BASE_VOTES;

	if (mode->collapse_vdd2_core) {
		votes |= PDSLPCFG0_CORE_VOTES;
	}

	if (mode->full_dsr) {
		votes |= PMC_PDSLEEPCFG0_FDSR_MASK;
	}

	/* Clear the whole managed vote set + mode bits before re-applying, so a
	 * dropped vote reliably clears and no stale value leaks from the live reg.
	 */
	uint32_t reg = pmc->PDSLEEPCFG0 & ~(PDSLPCFG0_BASE_VOTES | PDSLPCFG0_CORE_VOTES |
					    PDSLPCFG0_MODE_BITS);

	reg |= votes;

	/*
	 * V2DSP depends on V2COMP: if V2COMP is collapsed, V2DSP must be too.
	 * (In the base set V2DSP is already voted down; this keeps the invariant
	 * explicit for the core-collapse case.)
	 */
	if ((reg & PMC_PDSLEEPCFG0_V2COMP_DSR_MASK) != 0U) {
		reg |= PMC_PDSLEEPCFG0_V2DSP_PD_MASK;
	}

	/*
	 * RM 31.2: VDDN_COM may enter DSR only while VDD2_MEDIA/VDDN_MEDIA is also
	 * retained/off. Hardware does not block the illegal combination, so demote
	 * VDDN_COM to "on" (a legal state) rather than collapsing the shared rail
	 * on entry.
	 */
	if ((reg & PMC_PDSLEEPCFG0_VNCOM_DSR_MASK) != 0U &&
	    (reg & PMC_PDSLEEPCFG0_V2NMED_DSR_MASK) == 0U) {
		__ASSERT(false, "VNCOM_DSR requested but VDDN_MEDIA kept powered");
		reg &= ~PMC_PDSLEEPCFG0_VNCOM_DSR_MASK;
	}

	/*
	 * RM 31.2 Table 329: VDD2_COM may enter DSR only when VDD2_COMP, VDD2_DSP,
	 * VDD2_MEDIA/VDDN_MEDIA and VDDN_COM are all retained/off. V2COMP and V2DSP
	 * are guaranteed above, so only V2NMED + VNCOM can go missing -- check them.
	 */
	if ((reg & PMC_PDSLEEPCFG0_V2COM_DSR_MASK) != 0U &&
	    (reg & (PMC_PDSLEEPCFG0_V2NMED_DSR_MASK | PMC_PDSLEEPCFG0_VNCOM_DSR_MASK)) !=
		    (PMC_PDSLEEPCFG0_V2NMED_DSR_MASK | PMC_PDSLEEPCFG0_VNCOM_DSR_MASK)) {
		__ASSERT(false, "V2COM_DSR requested but a companion domain kept powered");
		reg &= ~PMC_PDSLEEPCFG0_V2COM_DSR_MASK;
	}

	switch (mode->override) {
	case OVR_DPD:
		reg |= PMC_PDSLEEPCFG0_DPD_MASK;
		break;
	case OVR_FDPD:
		reg |= PMC_PDSLEEPCFG0_FDPD_MASK;
		break;
	case OVR_NONE:
	default:
		break;
	}

	pmc->PDSLEEPCFG0 = reg;

	/*
	 * DPD (not FDPD) keeps VDD1V8 alive across the cold boot; clear the DSR
	 * request bits in the run config so they cannot leak into the boot state.
	 */
	if (mode->override == OVR_DPD) {
		pmc->PDRUNCFG0 &=
			~(PMC_PDRUNCFG0_V2NMED_DSR_MASK | PMC_PDRUNCFG0_VNCOM_DSR_MASK);
	}
}

/*
 * Default on-chip LDO regulator ops: program PMICMODE and drive the LDOs from
 * the POWERCFG.LDOxPD strapping. A board on an external PMIC replaces this.
 */
static void ldo_regulator_program(const struct power_domain *dom,
				  const struct power_mode_desc *mode)
{
	PMC_Type *pmc = dom->pmc;

	pmc->PDSLEEPCFG0 = (pmc->PDSLEEPCFG0 & ~PMC_PDSLEEPCFG0_PMICMODE_MASK) |
			   PMC_PDSLEEPCFG0_PMICMODE(mode->pmic_mode);

	/* Vote this domain's VDD low so aggregation yields control to the other. */
	pmc->PDSLEEPCFG0 &= ~dom->ldo_vsel_clear;

	/* Rail on PMIC -> bypass LDO in low power; rail on LDO -> LDO low-power. */
	if ((pmc->POWERCFG & PMC_POWERCFG_LDO1PD_MASK) != 0U) {
		pmc->PDSLEEPCFG0 &= ~PMC_PDSLEEPCFG0_LDO1_MODE_MASK;
	} else {
		pmc->PDSLEEPCFG0 |= PMC_PDSLEEPCFG0_LDO1_MODE_MASK;
	}

	if ((pmc->POWERCFG & PMC_POWERCFG_LDO2PD_MASK) != 0U) {
		pmc->PDSLEEPCFG0 &= ~PMC_PDSLEEPCFG0_LDO2_MODE_MASK;
	} else {
		pmc->PDSLEEPCFG0 |= PMC_PDSLEEPCFG0_LDO2_MODE_MASK;
	}
}

const struct power_regulator_ops power_ldo_regulator_ops = {
	.program = ldo_regulator_program,
};

/*
 * PDSLEEPCFG1 (analog refs / detectors / ROM / OTP) plus the PMCREF_LP decision.
 * PMCREF_LP drops the reference to low-power mode; that is only safe if nothing
 * left running needs an accurate reference. Pin it high if any clock source or
 * any detector is kept alive.
 */
static void program_pdslpcfg1(const struct power_domain *dom,
			      const struct power_resource_set *keep)
{
	PMC_Type *pmc = dom->pmc;

	pmc->PDSLEEPCFG1 = (PDSLPCFG1_DEEP_SLEEP & ~keep->detector) |
			   (pmc->PDRUNCFG1 & ~keep->detector);

	if (((keep->clk & dom->sleepcfg_pll) != 0U) || (keep->detector != 0U)) {
		pmc->PDSLEEPCFG1 &= ~PMC_PDSLEEPCFG1_PMCREF_LP_MASK;
	}
}

/* PDSLEEPCFG2..5: main-memory and peripheral-memory arrays/peripheries. */
static void program_pdslpcfg2_5(const struct power_domain *dom,
				const struct power_resource_set *keep)
{
	PMC_Type *pmc = dom->pmc;

	pmc->PDSLEEPCFG2 =
		(PDSLPCFG2_5_DEEP_SLEEP & ~keep->sram_array) | (pmc->PDRUNCFG2 & ~keep->sram_array);
	pmc->PDSLEEPCFG3 = (PDSLPCFG2_5_DEEP_SLEEP & ~keep->sram_periph) |
			   (pmc->PDRUNCFG3 & ~keep->sram_periph);
	pmc->PDSLEEPCFG4 =
		(PDSLPCFG2_5_DEEP_SLEEP & ~keep->pram_array) | (pmc->PDRUNCFG4 & ~keep->pram_array);
	pmc->PDSLEEPCFG5 = (PDSLPCFG2_5_DEEP_SLEEP & ~keep->pram_periph) |
			   (pmc->PDRUNCFG5 & ~keep->pram_periph);
}

/* Clear sticky PMC wake/power flags so the next wake reason reads cleanly. */
static void pmc_clear_event_flags(const struct power_domain *dom)
{
	dom->pmc->FLAGS = dom->pmc->FLAGS;
	dom->pmc->PWRFLAGS = dom->pmc->PWRFLAGS;
}

/*
 * Disable LVD/AGDET-driven resets across the window: the regulator LP switch
 * briefly dips the rail and would otherwise be mistaken for a brown-out. Returns
 * the saved CTRL for restore (poweroff paths do not restore).
 */
static uint32_t lvd_save_disable(const struct power_domain *dom)
{
	uint32_t saved = dom->pmc->CTRL;

	dom->pmc->CTRL = saved & ~(PMC_CTRL_LVDNRE_MASK | PMC_CTRL_LVD2RE_MASK |
				   PMC_CTRL_LVD1RE_MASK | PMC_CTRL_AGDET2RE_MASK |
				   PMC_CTRL_AGDET1RE_MASK);
	return saved;
}

/*
 * Clear the LVD/AGDET status flags set by the sleep-time rail dip, then restore
 * CTRL. Order matters: clear first, then re-enable RE, or the stale flags would
 * trip an immediate reset.
 */
static void lvd_restore(const struct power_domain *dom, uint32_t saved_ctrl)
{
	dom->pmc->FLAGS = PMC_FLAGS_LVDVDD1F_MASK | PMC_FLAGS_LVDVDD2F_MASK |
			  PMC_FLAGS_LVDVDDNF_MASK | PMC_FLAGS_AGDET1F_MASK | PMC_FLAGS_AGDET2F_MASK;
	dom->pmc->CTRL = saved_ctrl;
}

/* Latch all PMC programming above: drain any in-flight update, pulse APPLYCFG,
 * then wait for completion before WFI.
 */
static void pmc_apply_and_wait(const struct power_domain *dom)
{
	while ((dom->pmc->STATUS & PMC_STATUS_BUSY_MASK) != 0U) {
	}
	dom->pmc->CTRL |= PMC_CTRL_APPLYCFG_MASK;
	while ((dom->pmc->STATUS & PMC_STATUS_BUSY_MASK) != 0U) {
	}
}

struct power_resource_set power_keepalive_collect(const struct power_domain *dom,
						  const struct power_mode_desc *mode)
{
	ARG_UNUSED(dom);

	/*
	 * Today the keep-alive set is exactly the mode's compile-time base set.
	 * This is the single seam where device runtime PM will later OR in each
	 * powered device's retention requirement; the programmer above is unchanged.
	 */
	return mode->keep;
}

/*
 * Mask interrupts for the low-power window the way arch_pm_state_set_prepare()
 * does, minus the CONFIG_PM-only context save. BASEPRI inhibits WFI from
 * observing the wake event, so PRIMASK takes over as the IRQ lock.
 */
static ALWAYS_INLINE void pm_mask_irqs_for_wfi(void)
{
	__disable_irq();
	__set_BASEPRI(0);
	__DSB();
	__ISB();
}

AT_QUICKACCESS_SECTION_CODE(void power_enter_common(const struct power_domain *dom,
						    const struct power_mode_desc *mode))
{
	const struct power_resource_set keep = power_keepalive_collect(dom, mode);

	SCB->SCR |= SCB_SCR_SLEEPDEEP_Msk;

	program_sleepcfg(dom, &keep);
	program_pdslpcfg0(dom, mode);
	dom->regulator->program(dom, mode);
	program_pdslpcfg1(dom, &keep);
	program_pdslpcfg2_5(dom, &keep);

	if (dom->stall_dsp_if_powered_down != NULL) {
		dom->stall_dsp_if_powered_down(dom);
	}

	pmc_apply_and_wait(dom);

	pmc_clear_event_flags(dom);
	uint32_t saved_ctrl = lvd_save_disable(dom);

	/*
	 * Deep sleep / DSR return, so save arch state (and, on XIP, hand the XSPI
	 * over) around WFI. DPD/FDPD are one-way: there is no state to save, so
	 * they only mask interrupts.
	 *
	 * arch_pm_state_set_prepare()/_finish() exist only under CONFIG_PM -- both
	 * the weak fallback in arch/common/pm.c and the Cortex-M override in
	 * cortex_m/cpu_idle.c are CONFIG_PM-gated -- while this file also builds
	 * for POWEROFF-only configs. Testing mode->uses_arch_pm_hooks at run time
	 * is not enough, the reference still has to resolve at link time, so the
	 * calls need a compile-time guard. A POWEROFF-only build only ever gets
	 * here through DPD/FDPD, which do not use the hooks anyway.
	 */
	unsigned int key = 0;

#if defined(CONFIG_PM)
	if (mode->uses_arch_pm_hooks) {
		key = arch_pm_state_set_prepare();
	} else {
		pm_mask_irqs_for_wfi();
	}
#else
	pm_mask_irqs_for_wfi();
#endif

	if (dom->xip_suspend != NULL) {
		/*
		 * The V2COMP domain (XSPI logic, caches) collapses in DSR and in
		 * any core-collapse mode, so the caches lose their contents and
		 * must be flushed. In plain deep sleep only flush a cache whose
		 * domain is actually powered down; one kept alive retains contents.
		 *
		 * Mind the numbering: CPU0's system cache is the XCACHE0 block and
		 * its code cache is XCACHE1, so the PDSLEEPCFG4 SCACHE bit drives
		 * the xcache0 argument and CCACHE drives xcache1.
		 */
		bool flush_xcache0 = mode->collapse_vdd2_core ||
				     !POWER_RES_KEPT(keep.pram_array, RES_CPU0_SCACHE);
		bool flush_xcache1 = mode->collapse_vdd2_core ||
				     !POWER_RES_KEPT(keep.pram_array, RES_CPU0_CCACHE);

		dom->xip_suspend(flush_xcache0, flush_xcache1);
	}

	dom->arm_shared_clock_pdr_ignores(dom->sleepcon);

	__WFI();

	if (!mode->returns) {
		/* DPD/FDPD power the domain off; WFI never returns (cold boot). */
		CODE_UNREACHABLE;
		return;
	}

	if (dom->xip_resume != NULL) {
		dom->xip_resume();
	}

#if defined(CONFIG_PM)
	/* Only modes with returns == true get here, and those all use the hooks. */
	arch_pm_state_set_finish(key);
#else
	ARG_UNUSED(key);
#endif
	lvd_restore(dom, saved_ctrl);

	SCB->SCR &= ~SCB_SCR_SLEEPDEEP_Msk;
}
