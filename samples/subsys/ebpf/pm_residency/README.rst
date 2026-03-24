.. zephyr:code-sample:: ebpf-pm-residency
   :name: eBPF PM Residency Profiler

   Observe which Zephyr PM states are really used at runtime, and how long the
   system stays in each of them, using the eBPF PM notifier backend.

Overview
********

This sample demonstrates the backend-aware eBPF architecture by attaching two
eBPF programs to the power-management notifier backend:

* **pm_entry** runs on :c:enumerator:`EBPF_PM_ATTACH_STATE_ENTRY` and records
  a timestamp for the state being entered while incrementing that state's entry
  counter.
* **pm_exit** runs on :c:enumerator:`EBPF_PM_ATTACH_STATE_EXIT` and accumulates
  the elapsed residency time for the state being exited.

The application changes its idle window over time so the PM policy has a chance
to select different low-power states. After each phase it reads the maps and
prints, per state:

* how many times the state was entered,
* how much residency time accumulated during that phase,
* what percentage of the reporting interval that residency represents.

This is useful when validating board PM policy decisions, checking whether a
system really reaches deeper sleep states, and confirming that expected
residency gains appear as idle windows increase.

Architecturally, the sample is a compact example of the current subsystem
shape: the PM backend bridge converts notifier callbacks into common eBPF
targets, the target runtime fans those events out to enabled programs, and the
programs exchange state through maps.

Building and Running
********************

The sample is intended for boards with real PM policy support, such as
``frdm_mcxn236``:

.. zephyr-app-commands::
   :zephyr-app: samples/subsys/ebpf/pm_residency
   :host-os: unix
   :board: frdm_mcxn236
   :goals: build run
   :compact:

Sample Output
*************

.. code-block:: console

   *** Booting Zephyr OS build v4.3.0 ***
   eBPF PM residency profiler
   ==========================

   Attached programs:
     pm_entry -> pm/state_entry
     pm_exit  -> pm/state_exit

   [Phase 1] worker sleep 10 ms
     runtime-idle      entries=  31  residency=  284 ms  interval= 7%

   [Phase 2] worker sleep 50 ms
     suspend-to-idle   entries=  15  residency=  711 ms  interval=17%

   [Phase 3] worker sleep 200 ms
     suspend-to-idle   entries=  10  residency= 1820 ms  interval=45%
     standby           entries=   2  residency=  604 ms  interval=15%

   [Phase 4] worker sleep 1 s
     suspend-to-idle   entries=   4  residency= 1651 ms  interval=41%
     standby           entries=   2  residency= 1846 ms  interval=46%

   eBPF PM residency profiler detached.

Related Documentation
*********************

For an introduction to the subsystem design and the execution model, see
:ref:`ebpf`, :doc:`/services/ebpf/architecture`, and
:doc:`/services/ebpf/components`.