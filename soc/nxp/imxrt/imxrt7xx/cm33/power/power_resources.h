/*
 * SPDX-FileCopyrightText: Copyright 2026 NXP
 *
 * SPDX-License-Identifier: Apache-2.0
 *
 * Named power resources for the RT7xx CM33 low-power driver.
 *
 * The low-power entry path decides *which blocks to keep powered* over a sleep
 * window. Historically that was expressed as an array of raw PMC register words
 * ("exclude from power down"), which forced every caller to know that, say, the
 * code cache lives in PDSLEEPCFG4. This header replaces that with named
 * resources grouped by the physical register that controls them, so callers and
 * the keep-alive aggregation speak in resources, never in register offsets.
 *
 * A resource is just a bit mask in one of the PMC/SLEEPCON registers. The values
 * are the SoC register bit masks (from the fsl register headers) -- there is no
 * indirection and no run-time cost. The two power domains do not share the same
 * clock topology (the Compute domain owns FRO0/FRO1, the Sense domain does not),
 * so each domain has its own RES_* set rather than a forced-common enum that
 * would only paper over real hardware differences.
 *
 * Keep-alive is carried as a struct power_resource_set: one mask per physical
 * register bucket. Today it is filled from a per-mode const descriptor. When
 * resource ownership moves to device runtime PM, the same struct will instead be
 * aggregated at run time from each device's retention requirement and handed to
 * the exact same programming code -- the programmer only ever consumes the set,
 * it never cares how the set was built.
 */

#ifndef SOC_NXP_IMXRT_IMXRT7XX_CM33_POWER_POWER_RESOURCES_H_
#define SOC_NXP_IMXRT_IMXRT7XX_CM33_POWER_POWER_RESOURCES_H_

#include <stdint.h>

#include <fsl_common.h>

/*
 * A set of resources to keep powered across a low-power window, one mask per
 * physical PMC/SLEEPCON register bucket. A set bit means "keep this powered".
 *
 * The buckets map 1:1 to the registers the programmer writes:
 *   clk         SLEEPCONn.SLEEPCFG    clocks / oscillators / PLLs
 *   detector    PMCn.PDSLEEPCFG1      analog references / brown-out detectors
 *   sram_array  PMCn.PDSLEEPCFG2      main-memory ARRAY      (SRAM0..SRAM29)
 *   sram_periph PMCn.PDSLEEPCFG3      main-memory PERIPHERY  (SRAM0..SRAM29)
 *   pram_array  PMCn.PDSLEEPCFG4      peripheral-memory ARRAY (caches, OCOTP)
 *   pram_periph PMCn.PDSLEEPCFG5      peripheral-memory PERIPHERY
 *
 * The PDSLEEPCFG0 voltage domains are deliberately not in this set: they are
 * governed by a strict dependency layering (see power_domain.h,
 * collapse_vdd2_core) rather than by free per-bit keep-alive, so they are
 * handled by the mode descriptor, not aggregated here.
 */
struct power_resource_set {
	uint32_t clk;
	uint32_t detector;
	uint32_t sram_array;
	uint32_t sram_periph;
	uint32_t pram_array;
	uint32_t pram_periph;
};

/*
 * Detector groups used both as keep-alive resources and as the PMCREF_LP
 * decision input: keeping any brown-out / voltage detector alive requires the
 * PMC reference to stay in its accurate (high-power) mode. Grouped per rail
 * (VDD1 / VDD2 / VDDN) to mirror the RM. Identical bit names on both domains.
 */
#define RES_DETECTOR_VDD1	(PMC_PDSLEEPCFG1_POR1_LP_MASK | PMC_PDSLEEPCFG1_LVD1_LP_MASK | \
				 PMC_PDSLEEPCFG1_HVD1_PD_MASK)
#define RES_DETECTOR_VDD2	(PMC_PDSLEEPCFG1_POR2_LP_MASK | PMC_PDSLEEPCFG1_LVD2_LP_MASK | \
				 PMC_PDSLEEPCFG1_HVD2_PD_MASK)
#define RES_DETECTOR_VDDN	(PMC_PDSLEEPCFG1_PORN_LP_MASK | PMC_PDSLEEPCFG1_LVDN_LP_MASK | \
				 PMC_PDSLEEPCFG1_HVDN_PD_MASK)
#define RES_DETECTOR_ALL	(RES_DETECTOR_VDD1 | RES_DETECTOR_VDD2 | RES_DETECTOR_VDDN)

/*
 * Peripheral-memory ARRAY resources (PDSLEEPCFG4). CPU0's code/system caches and
 * the OCOTP shadow RAM; identical bit names on both domains (the Sense domain
 * simply never keeps them alive).
 *
 * Both caches belong to CPU0 -- CPU1 has none -- and the instance numbering does
 * not follow the core numbering: the code cache is the XCACHE1 block and the
 * system cache is XCACHE0. These names therefore mirror the PMC field names
 * rather than the block names, so that reading them as "XCACHE instance 0" is
 * not possible.
 */
#define RES_CPU0_CCACHE		PMC_PDSLEEPCFG4_CPU0_CCACHE_MASK	/* -> XCACHE1 */
#define RES_CPU0_SCACHE		PMC_PDSLEEPCFG4_CPU0_SCACHE_MASK	/* -> XCACHE0 */
#define RES_OCOTP		PMC_PDSLEEPCFG4_OCOTP_MASK

/* True when resource bit(s) mask are kept powered in set-bucket bucket. */
#define POWER_RES_KEPT(bucket, mask) (((bucket) & (mask)) != 0U)

#endif /* SOC_NXP_IMXRT_IMXRT7XX_CM33_POWER_POWER_RESOURCES_H_ */
