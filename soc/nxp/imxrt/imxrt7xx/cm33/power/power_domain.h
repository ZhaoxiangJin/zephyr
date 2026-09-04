/*
 * SPDX-FileCopyrightText: Copyright 2026 NXP
 *
 * SPDX-License-Identifier: Apache-2.0
 *
 * RT7xx CM33 low-power domain / mode abstraction.
 *
 * The two CM33 cores each live in one power domain -- CPU0 in Compute
 * (PMC0/SLEEPCON0), CPU1 in Sense (PMC1/SLEEPCON1) -- and enter the same family
 * of low-power modes (deep sleep, DSR, DPD, FDPD). The per-domain differences
 * (which PMC instance, which SLEEPCFG bit set, whether DSR/XIP exist, how the
 * regulator is driven, how shared-clock power-down-ready is handled) are data,
 * carried in struct power_domain. The per-mode differences (which voltage
 * domains collapse, which override bit, what to keep alive) are data too, in
 * struct power_mode_desc. A single power_enter_common() consumes a (domain,
 * mode) pair, so there is exactly one copy of the entry sequence.
 */

#ifndef SOC_NXP_IMXRT_IMXRT7XX_CM33_POWER_POWER_DOMAIN_H_
#define SOC_NXP_IMXRT_IMXRT7XX_CM33_POWER_POWER_DOMAIN_H_

#include <stdbool.h>
#include <stdint.h>

#include <fsl_common.h>

#include "power_resources.h"

/*
 * Each CM33 core sees only its own SLEEPCON block type: core0's headers define
 * SLEEPCON0_Type, core1's define SLEEPCON1_Type, and there is no shared
 * SLEEPCON_Type. The two layouts place the fields this driver touches (SLEEPCFG
 * at 0x0, PWRDOWN_WAIT at 0x164) at identical offsets, so shared code accesses
 * whichever type this build provides through the soc_sleepcon_t alias. The
 * selecting macro is the core header's own include guard, set once fsl_common.h
 * has pulled the right device header in above.
 */
#if defined(MIMXRT798S_cm33_core0_H_)
typedef SLEEPCON0_Type soc_sleepcon_t;
#elif defined(MIMXRT798S_cm33_core1_H_)
typedef SLEEPCON1_Type soc_sleepcon_t;
#else
#error "RT7xx CM33 power: no SLEEPCON block type for this core"
#endif

struct power_domain;
struct power_mode_desc;

/* One-way override applied on top of the DSR voltage-domain votes. */
enum power_override {
	OVR_NONE = 0,
	OVR_DPD,
	OVR_FDPD,
};

/*
 * PMIC / regulator decision hook.
 *
 * Programs the PMICMODE field and the LDO/rail decision into PDSLEEPCFG0. The
 * default implementation (power_common.c) drives the on-chip LDOs from the
 * PMC POWERCFG.LDOxPD strapping, which is what the SoC does today. When a board
 * powers a rail from an external PMIC instead, its regulator driver can supply a
 * different ops table (or override the per-mode pmic_mode) without touching the
 * programmer or the mode descriptors.
 */
struct power_regulator_ops {
	void (*program)(const struct power_domain *dom, const struct power_mode_desc *mode);
};

/*
 * A power domain: the invariant, per-core hardware facts. One const instance per
 * domain (compute_domain / sense_domain), each defined in its own translation
 * unit so a build only ever links the domain it is for.
 */
struct power_domain {
	PMC_Type      *pmc;
	soc_sleepcon_t *sleepcon;

	/* SLEEPCFG bit set this domain shuts off in deep sleep. */
	uint32_t sleepcfg_pd;
	/* The PLL subset of the clocks, used by the PMCREF_LP decision. */
	uint32_t sleepcfg_pll;

	/* LDO*_VSEL bit this domain votes low so aggregation yields control of
	 * that rail's voltage to the other domain. Used by the default LDO ops.
	 */
	uint32_t ldo_vsel_clear;

	/* Stall the HiFi DSP before its rail (V2DSP) powers down, so an in-flight
	 * AHB transaction cannot hang the bus. Only the Compute domain has a DSP
	 * (and the SYSCON0 that stalls it); NULL on Sense. Confining the SYSCON0
	 * access to the Compute TU also keeps this shared file free of the
	 * core0-only register block. Called with the PMC votes already programmed,
	 * so the hook can gate on V2DSP_PD itself.
	 */
	void (*stall_dsp_if_powered_down)(const struct power_domain *dom);

	/* If this domain owns clocks that it is powering down, make SLEEPCON wait
	 * for their power-down-ready handshake -- being the sole owner, this
	 * domain's vote is enough for that signal to arrive. Only the Compute
	 * domain owns such clocks (FRO0/FRO1); NULL on Sense. Runs early (flash
	 * still live), so it need not be RAM-resident. keep_clk is the clock
	 * keep-alive mask so a kept clock is left running.
	 */
	void (*prep_owned_clock_pdr)(soc_sleepcon_t *sleepcon, uint32_t keep_clk);

	/* Tell the PMC not to wait for shared-clock power-down-ready before it
	 * lets this domain sleep. Compute keys this on being the first domain
	 * down (DSSENS) and runs from RAM; Sense does it unconditionally. The
	 * difference is absorbed behind this pointer.
	 */
	void (*arm_shared_clock_pdr_ignores)(soc_sleepcon_t *sleepcon);

	/* PMIC / regulator decision. Defaults to the on-chip LDO ops. */
	const struct power_regulator_ops *regulator;

	/* XIP suspend/resume. Non-NULL only on the Compute domain, and only when
	 * CONFIG_SOC_MIMXRT7XX_PM_XIP_HANDOVER is built. The Sense TU never links
	 * the XIP object, so these stay NULL there.
	 */
	void (*xip_suspend)(bool flush_scache, bool flush_ccache);
	void (*xip_resume)(void);
};

/*
 * A low-power mode: what the mode does, independent of which domain runs it.
 * One const table per domain (the Compute deep-sleep and Sense deep-sleep modes
 * differ only in collapse_vdd2_core, so keeping a table per domain avoids any
 * implicit domain-vs-mode coupling).
 */
struct power_mode_desc {
	/* PDSLEEPCFG0 voltage-domain layering:
	 *   base (deep sleep): vote V2DSP/V2MIPI/V2NMED/VNCOM down, keep V2COMP/V2COM.
	 *   collapse_vdd2_core: additionally collapse V2COMP + V2COM (DSR/DPD/FDPD,
	 *                       and the Sense-domain deep-sleep view).
	 */
	bool collapse_vdd2_core;
	/* Full DSR (FDSR) bit. Set only by the Compute DSR mode; deep sleep and
	 * the poweroff modes leave it clear even when they collapse the core rails.
	 */
	bool full_dsr;
	enum power_override override;

	/* Compile-time base keep-alive. When resource ownership moves to device
	 * runtime PM, power_keepalive_collect() will OR each device's requirement
	 * on top of this before programming; the programmer is unchanged.
	 */
	struct power_resource_set keep;

	uint8_t pmic_mode;         /* Per-mode PMICMODE default (regulator may override). */
	bool    uses_arch_pm_hooks; /* deep/dsr use arch_pm_state_set_*; dpd/fdpd do not. */
	bool    returns;            /* deep/dsr return; dpd/fdpd are one-way (cold boot). */
};

/*
 * Aggregate the keep-alive resource set for (domain, mode). Today it returns the
 * mode's compile-time base set unchanged; this is the single seam where device
 * runtime PM will later fold in per-device retention requirements.
 */
struct power_resource_set power_keepalive_collect(const struct power_domain *dom,
						  const struct power_mode_desc *mode);

/* The one shared low-power entry sequence, driven by (domain, mode). */
void power_enter_common(const struct power_domain *dom, const struct power_mode_desc *mode);

/* Default on-chip LDO regulator ops (power_common.c). */
extern const struct power_regulator_ops power_ldo_regulator_ops;

#endif /* SOC_NXP_IMXRT_IMXRT7XX_CM33_POWER_POWER_DOMAIN_H_ */
