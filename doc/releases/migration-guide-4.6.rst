:orphan:

..
  See
  https://docs.zephyrproject.org/latest/releases/index.html#migration-guides
  for details of what is supposed to go into this document.

.. _migration_4.6:

Migration guide to Zephyr v4.6.0 (Working Draft)
################################################

This document describes the changes required when migrating your application from Zephyr v4.5.0 to
Zephyr v4.6.0.

Any other changes (not directly related to migrating applications) can be found in
the :ref:`release notes<zephyr_4.6>`.

.. contents::
    :local:
    :depth: 2

Common
******

Build System
************

Kernel
******

Boards
******

Device Drivers and Devicetree
*****************************

.. Only place contents common to all device drivers here. Contents specific to one driver subsystem
   goes into its own subsection, below.

.. Group contents in this section by subsystem, e.g.:
..
.. ADC
.. ===
..
.. ...

.. zephyr-keep-sorted-start re(^\w) ignorecase

Counter
========

* :dtcompatible:`nxp,mrt-channel` nodes now name their parent
  :dtcompatible:`nxp,mrt` node as their power domain, and the MCX N devicetrees list
  the power states that stop the counter. With
  :kconfig:option:`CONFIG_PM_DEVICE_RUNTIME` the bus clock the channels share is
  gated while no channel holds a runtime reference, so an application has to call
  :c:func:`pm_device_runtime_get` on a channel before :c:func:`counter_start` and
  hold the reference for as long as it wants the timebase. Runtime power management
  has to be enabled on the parent node as well as on the channels, because only the
  parent's resume action turns the clock on. With
  :kconfig:option:`CONFIG_PM_POLICY_DEVICE_CONSTRAINTS` a running channel on MCX N
  now blocks suspend-to-idle, standby and suspend-to-ram until it is stopped or
  suspended. Builds with :kconfig:option:`CONFIG_PM_DEVICE` disabled behave as
  before.

* :c:func:`counter_get_top_value` on an :dtcompatible:`nxp,mrt-channel` device now
  reports the top value that was configured, or the maximum when none was, instead
  of reading back the hardware register. The register reads zero while the channel
  is idle, so the call used to return 0 between
  :c:func:`counter_set_top_value` and :c:func:`counter_start`, after
  :c:func:`counter_stop`, and after any transition that reset the block.

.. zephyr-keep-sorted-stop

Bluetooth
*********

Networking
**********

Other subsystems
****************

Modules
*******

Architectures
*************
