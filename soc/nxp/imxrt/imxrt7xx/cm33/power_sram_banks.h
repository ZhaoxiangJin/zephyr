/*
 * SPDX-FileCopyrightText: Copyright 2026 NXP
 *
 * SPDX-License-Identifier: Apache-2.0
 *
 * Build-time derivation of the RT7xx main-memory (SRAM) keep-alive mask from
 * devicetree.
 *
 * The RT7xx main SRAM is one contiguous 7.5 MB window split into 30 physical
 * partitions P0..P29 (RM "System memory map"). Each partition is powered
 * independently through PMC PDSLEEPCFG2 (array) / PDSLEEPCFG3 (periphery):
 * PDSLEEPCFGn.SRAMx is bit x, so bit n of the mask maps 1:1 to partition Pn.
 * The window is contiguous and mirrored at four base aliases: 0x0000_0000 /
 * 0x1000_0000 (code alias), 0x2000_0000 (system/RM view) and 0x3000_0000 (data
 * alias via the sram node `ranges`). The aliases share their low 24 bits, so
 * once an address is known to be on-chip those bits give the window offset
 * regardless of which alias a DT node uses.
 *
 * A partition must stay powered across a low-power window exactly when the
 * linked image occupies it. What the image occupies is fixed at link time:
 *
 *   1. DT_CHOSEN(zephyr_sram) is the RAM linker region. All data, bss, noinit,
 *      thread stacks, the kernel heap and the libc malloc arena are placed
 *      inside it, so runtime malloc never escapes it -- the occupied partition
 *      set does not depend on runtime allocation.
 *   2. Every status-okay `zephyr,memory-region` node that falls inside the
 *      on-chip SRAM window is an explicitly linked region and is included too.
 *
 * The keep-alive mask is therefore the union of the partitions overlapped by
 * those regions, computed here as a compile-time constant.
 *
 * Coverage limitation: this covers everything the linker places (data/bss/heap/
 * stacks/malloc arena and declared memory-regions). It does NOT cover a raw
 * write to a physical SRAM address in a partition the image never declared --
 * such a partition can lose power in a low-power window. An application that
 * uses a partition must declare it as a `zephyr,memory-region` so it is linked
 * and retained; using an undeclared partition is an application bug.
 */

#ifndef SOC_NXP_IMXRT_IMXRT7XX_CM33_POWER_SRAM_BANKS_H_
#define SOC_NXP_IMXRT_IMXRT7XX_CM33_POWER_SRAM_BANKS_H_

#include <zephyr/devicetree.h>

/*
 * The SRAM window is mirrored at four base aliases that share their low 24 bits:
 * 0x0000_0000 / 0x1000_0000 (code), 0x2000_0000 (system/RM) and 0x3000_0000
 * (data, via the sram node `ranges`). So once an address is known to be on-chip
 * its low 24 bits give the window offset.
 *
 * Deciding on-chip needs more than the low 24 bits, because off-chip memories
 * declared as memory-regions can share them: PSRAM at 0x0800_0000 has the same
 * top nibble (0) as the 0x0000_0000 alias, and PSRAM2 at 0x7000_0000 masks to
 * offset 0. So test the address within its 256 MB alias slot (low 28 bits) and
 * require both the correct top nibble (0..3) and an in-window offset.
 */
#define POWER_SRAM_WINDOW_MASK  0x00FFFFFFU
/* Total window size (7.5 MB); offsets at or beyond this are off-chip. */
#define POWER_SRAM_WINDOW_LIMIT 0x00780000U

/* True when addr's top nibble selects one of the four SRAM aliases (0/1/2/3). */
#define POWER_SRAM_ALIAS_OK(addr) (((addr) & 0xF0000000U) <= 0x30000000U)
/*
 * True when addr lands inside the on-chip SRAM window through some alias. The
 * offset test uses the low 28 bits (the alias slot), not the 24-bit window
 * mask, so an off-chip region that merely shares the low 24 bits (e.g. PSRAM
 * at 0x0800_0000) is still rejected.
 */
#define POWER_SRAM_ADDR_ONCHIP(addr)                                                               \
	(POWER_SRAM_ALIAS_OK(addr) && (((addr) & 0x0FFFFFFFU) < POWER_SRAM_WINDOW_LIMIT))

/*
 * Physical partition table P0..P29 as {index, window offset, size} (RM
 * "System memory map"). Offsets are window-relative (address & WINDOW_MASK).
 * Contiguous: each offset == previous offset + previous size.
 */
#define POWER_SRAM_BANKS(_, roff, rsize)							\
	_(0, 0x000000U, 0x008000U, roff, rsize)  /* 32K  */					\
	_(1, 0x008000U, 0x008000U, roff, rsize)  /* 32K  */					\
	_(2, 0x010000U, 0x008000U, roff, rsize)  /* 32K  */					\
	_(3, 0x018000U, 0x008000U, roff, rsize)  /* 32K  */					\
	_(4, 0x020000U, 0x010000U, roff, rsize)  /* 64K  */					\
	_(5, 0x030000U, 0x010000U, roff, rsize)  /* 64K  */					\
	_(6, 0x040000U, 0x020000U, roff, rsize)  /* 128K */					\
	_(7, 0x060000U, 0x020000U, roff, rsize)  /* 128K */					\
	_(8, 0x080000U, 0x040000U, roff, rsize)  /* 256K */					\
	_(9, 0x0C0000U, 0x040000U, roff, rsize)  /* 256K */					\
	_(10, 0x100000U, 0x080000U, roff, rsize) /* 512K */					\
	_(11, 0x180000U, 0x080000U, roff, rsize) /* 512K */					\
	_(12, 0x200000U, 0x100000U, roff, rsize) /* 1M   */					\
	_(13, 0x300000U, 0x100000U, roff, rsize) /* 1M   */					\
	_(14, 0x400000U, 0x080000U, roff, rsize) /* 512K */					\
	_(15, 0x480000U, 0x080000U, roff, rsize) /* 512K */					\
	_(16, 0x500000U, 0x040000U, roff, rsize) /* 256K */					\
	_(17, 0x540000U, 0x040000U, roff, rsize) /* 256K */					\
	_(18, 0x580000U, 0x008000U, roff, rsize) /* 32K  */					\
	_(19, 0x588000U, 0x008000U, roff, rsize) /* 32K  */					\
	_(20, 0x590000U, 0x008000U, roff, rsize) /* 32K  */					\
	_(21, 0x598000U, 0x008000U, roff, rsize) /* 32K  */					\
	_(22, 0x5A0000U, 0x010000U, roff, rsize) /* 64K  */					\
	_(23, 0x5B0000U, 0x010000U, roff, rsize) /* 64K  */					\
	_(24, 0x5C0000U, 0x020000U, roff, rsize) /* 128K */					\
	_(25, 0x5E0000U, 0x020000U, roff, rsize) /* 128K */					\
	_(26, 0x600000U, 0x080000U, roff, rsize) /* 512K */					\
	_(27, 0x680000U, 0x080000U, roff, rsize) /* 512K */					\
	_(28, 0x700000U, 0x040000U, roff, rsize) /* 256K */					\
	_(29, 0x740000U, 0x040000U, roff, rsize) /* 256K */

/*
 * Set bit n when region [roff, roff+rsize) overlaps partition Pn [boff, boff+bsize):
 * boff < roff+rsize && boff+bsize > roff. Half-open intervals, so a zero-size
 * region contributes nothing.
 */
#define POWER_SRAM_BANK_BIT(n, boff, bsize, roff, rsize)					\
	((((boff) < ((roff) + (rsize))) && (((boff) + (bsize)) > (roff))) ? (1U << (n)) : 0U)

/*
 * OR of the bits for every partition overlapped by region [roff, roff+rsize).
 * roff/rsize are threaded through POWER_SRAM_BANKS() so the per-bank fold macro
 * receives them as ordinary arguments (no reliance on outer-macro parameters
 * leaking into a nested expansion).
 */
#define POWER_SRAM_MASK_FOR_OFFSET(roff, rsize)							\
	(0U POWER_SRAM_BANKS(_POWER_SRAM_BANK_OR, roff, rsize))
#define _POWER_SRAM_BANK_OR(n, boff, bsize, roff, rsize)					\
	| POWER_SRAM_BANK_BIT(n, boff, bsize, roff, rsize)

/*
 * Mask for a DT node's reg. A node outside on-chip SRAM (e.g. PSRAM, which can
 * alias to a low window offset once masked) contributes 0; the on-chip test is
 * done on the full translated address before reducing to the window offset, so
 * it works through any of the four SRAM address aliases.
 */
#define POWER_SRAM_MASK_FOR_NODE(node_id)							\
	(POWER_SRAM_ADDR_ONCHIP(DT_REG_ADDR(node_id))						\
		 ? POWER_SRAM_MASK_FOR_OFFSET((DT_REG_ADDR(node_id) & POWER_SRAM_WINDOW_MASK),	\
					      DT_REG_SIZE(node_id))				\
		 : 0U)

/* Fold helper: contribute a memory-region node's mask into the union. */
#define _POWER_SRAM_REGION_OR(node_id) POWER_SRAM_MASK_FOR_NODE(node_id) |

/*
 * Keep-alive mask for this image: the chosen RAM region unioned with every
 * status-okay memory-region that lands in the on-chip window. Compile-time
 * constant, usable in a static const initializer.
 */
#define POWER_SRAM_KEEPALIVE									\
	(POWER_SRAM_MASK_FOR_NODE(DT_CHOSEN(zephyr_sram)) |					\
	 (DT_FOREACH_STATUS_OKAY(zephyr_memory_region, _POWER_SRAM_REGION_OR) 0U))

#endif /* SOC_NXP_IMXRT_IMXRT7XX_CM33_POWER_SRAM_BANKS_H_ */
