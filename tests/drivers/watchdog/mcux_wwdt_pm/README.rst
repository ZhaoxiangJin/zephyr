.. SPDX-FileCopyrightText: Copyright 2026 NXP
.. SPDX-License-Identifier: Apache-2.0

MCUX WWDT power-management tests
###############################

These tests compile the production MCUX WWDT implementation with RAM registers and
controlled HAL/clock operations. The PM core and runtime reference counting use
real Zephyr implementations.

The ``drivers.watchdog.mcux_wwdt.generic`` scenario omits the MCX family definition
and checks shared setup, install, feed and IRQ serialization. It also checks the
legacy HAL-deinit and power-domain replay paths without treating the mock as
evidence that a physical watchdog can stop or restart.

The task-watchdog tests exercise its production implementation with a failing watchdog
backend. Hardware oscillator retention, counting accuracy and reset behavior are not
emulated and require board validation.
