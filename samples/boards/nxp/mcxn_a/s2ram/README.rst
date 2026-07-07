.. zephyr:code-sample:: nxp_mcx_s2ram
   :name: NXP MCX suspend-to-RAM
   :relevant-api: subsys_pm_states subsys_pm_device input_interface wuc_interface

   Suspend an NXP MCXA/MCXN SoC to RAM and resume on an LPTMR timer (or button)
   wakeup delivered through the WUU wakeup controller.

Overview
********

This sample exercises :c:enumerator:`PM_STATE_SUSPEND_TO_RAM` on NXP MCXA and
MCXN SoCs, where it is mapped to the SoC Deep Power Down mode. The CORE power
domain is gated and the chip wakes through the reset routine; the
:ref:`pm_s2ram <pm-guide>` resume path then returns directly to the suspend call
site without re-running kernel or CPU initialization, so on both families the
resume is transparent (resume-in-place) to the application.

A stand-in application thread models a real workload: it does its work and then
blocks waiting for its next event, with no knowledge of Deep Power Down. The
thread suspends the SoC to RAM and the wakeup resumes it transparently, right
where it blocked. A counter incremented before every suspend survives the cycle,
so the printed value demonstrates the retained RAM.

The thread repeats for ``CONFIG_SAMPLE_APP_TEST_CYCLES`` cycles (default 10) and then
stops, printing a final ``Completed N suspend-to-RAM cycles`` line so a test
harness can confirm every wakeup happened. No console input is needed. Once the
run is over the SoC stays awake (every PM state is locked, so it only ever
suspends when the sample explicitly asks it to).

The wakeup source is selectable at build time. Both branches show the intended
layering: the application never programs the :ref:`WUC (Wakeup Controller)
<wuc_api>` directly - a system component or a device driver does that on its
behalf.

* ``CONFIG_SAMPLE_S2RAM_WAKEUP_TIMER`` (default) wakes on LPTMR0, the system-timer
  companion, which arms itself as a WUU internal-module wakeup source during
  initialization. The worker thread simply blocks in :c:func:`k_sleep`, so the
  cycle repeats automatically with no wakeup-source code in the application.

* ``CONFIG_SAMPLE_S2RAM_WAKEUP_BUTTON`` resumes on a WUU external pin transition (the
  board's ``wakeup-button``, SW2). The application selects the button as a wakeup
  source once with :c:func:`pm_device_wakeup_enable` and then simply waits for the
  key's input event. Deep Power Down resets the GPIO, so there is no live GPIO edge
  on resume - the press is latched only by the WUU - but the :dtcompatible:`gpio-keys`
  driver hides that: it arms the WUU line on suspend and replays the latched press
  as a normal input event on resume. The application code is therefore identical to
  a portable STM32 or Nordic target and never references the WUU. Press SW2 to
  advance each cycle.

.. note::

   On MCXN SoCs only SRAMA (the first 32 KB, retained by the VBAT RAM LDO)
   survives Deep Power Down, so the whole retained working set must fit in SRAMA
   and ``zephyr,sram`` must point to it. On MCXA SoCs all SRAM is retained by the
   SPC SRAM retention LDO, so no placement constraint applies.

Building and Running
********************

.. zephyr-app-commands::
   :zephyr-app: samples/boards/nxp/mcxn_a/s2ram
   :board: frdm_mcxa156
   :goals: build flash
   :compact:

Sample Output
*************

.. code-block:: console

   frdm_mcxa156 suspend-to-RAM demo
   Retained S2RAM cycle counter: 0
   Entering suspend-to-RAM (cycle 1/10); wake in 3 s
   Resumed from suspend-to-RAM; retained counter is 1
   Entering suspend-to-RAM (cycle 2/10); wake in 3 s
   Resumed from suspend-to-RAM; retained counter is 2
   ...
   Entering suspend-to-RAM (cycle 10/10); wake in 3 s
   Resumed from suspend-to-RAM; retained counter is 10
   Completed 10 suspend-to-RAM cycles

With ``CONFIG_SAMPLE_S2RAM_WAKEUP_BUTTON`` each cycle instead waits for an SW2 press:

.. code-block:: console

   frdm_mcxn236 suspend-to-RAM demo
   Retained S2RAM cycle counter: 0
   Entering suspend-to-RAM (cycle 1/10); press SW2 to wake
   Resumed from suspend-to-RAM; retained counter is 1
   Entering suspend-to-RAM (cycle 2/10); press SW2 to wake
   Resumed from suspend-to-RAM; retained counter is 2
   ...
