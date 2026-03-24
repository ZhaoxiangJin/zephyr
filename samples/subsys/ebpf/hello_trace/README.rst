.. zephyr:code-sample:: ebpf-hello-trace
   :name: eBPF Hello Trace

   Attach an eBPF program to a Zephyr tracing target and count context switches.

Overview
********

This sample demonstrates the Zephyr eBPF subsystem by attaching a small eBPF
program to the :c:enumerator:`EBPF_TRACING_ATTACH_THREAD_SWITCHED_IN` tracing
target. The program is defined as an instruction array and uses an array map
to keep a counter that survives between invocations. Each time the scheduler
switches to a thread, the program runs, looks up entry ``0`` in the map, and
increments the counter. Before the program is enabled, the application patches
the runtime map handle into the bytecode.

To generate frequent context switches, the sample starts a worker thread that
periodically sleeps. The main thread reads the map once per second and prints
the current counter value together with the average execution time recorded for
the eBPF program.

Building and Running
********************

The sample can be built and run on boards that support the Zephyr eBPF sample
configuration, including ``frdm_mcxn236``:

.. zephyr-app-commands::
   :zephyr-app: samples/subsys/ebpf/hello_trace
   :host-os: unix
   :board: frdm_mcxn236
   :goals: build run
   :compact:

Sample Output
*************

.. code-block:: console

   *** Booting Zephyr OS build 900f3361f860 ***
   eBPF hello_trace sample
   =======================

   eBPF program 'count_switches' enabled on THREAD_SWITCHED_IN.
   Counting context switches...

   [ 1] Context switches: 21 (avg exec: 10140 ns)
   [ 2] Context switches: 42 (avg exec: 10110 ns)
   [ 3] Context switches: 63 (avg exec: 10101 ns)
   [ 4] Context switches: 84 (avg exec: 10096 ns)
   [ 5] Context switches: 105 (avg exec: 10093 ns)
   [ 6] Context switches: 126 (avg exec: 10091 ns)
   [ 7] Context switches: 147 (avg exec: 10089 ns)
   [ 8] Context switches: 168 (avg exec: 10088 ns)
   [ 9] Context switches: 189 (avg exec: 10088 ns)
   [10] Context switches: 210 (avg exec: 10087 ns)

   eBPF program detached. Sample complete.
