.. zephyr:code-sample:: ebpf-isr-latency
   :name: eBPF ISR Latency Profiler

   Measure interrupt service routine execution time with two cooperating
   eBPF programs and a ring buffer map.


Overview
********

This sample demonstrates usage of the Zephyr eBPF subsystem by profiling
interrupt service routine (ISR) latency at runtime. Two eBPF programs of type
``EBPF_PROG_TYPE_ISR`` cooperate through two shared maps — an array map that
holds a timestamp and a ring buffer that streams duration records to user space:

* **isr_entry** — attached to :c:enumerator:`EBPF_TRACING_ATTACH_ISR_ENTER`,
  captures a nanosecond timestamp via the ``ktime_get_ns`` helper and stores
  it in the array map.

* **isr_exit** — attached to :c:enumerator:`EBPF_TRACING_ATTACH_ISR_EXIT`,
  reads the entry timestamp, computes the elapsed time, and writes the
  duration to the ring buffer using ``ringbuf_output``.

The application thread drains the ring buffer once per second and prints
min / avg / max latency statistics.

.. note::

   A single timestamp slot is used, so nested interrupts may cause the outer
   ISR's duration to be measured inaccurately.

Building and Running
********************

The sample can be built and run on boards that support the Zephyr eBPF
configuration, including ``frdm_mcxn236``:

.. zephyr-app-commands::
   :zephyr-app: samples/subsys/ebpf/isr_latency
   :host-os: unix
   :board: frdm_mcxn236
   :goals: build run
   :compact:

Sample Output
*************

.. code-block:: console

   *** Booting Zephyr OS build 900f3361f860 ***
   eBPF ISR latency profiler
   ========================

   eBPF programs enabled on ISR_ENTER and ISR_EXIT.
   Profiling ISR latency...

   [ 1] ISRs: 9  avg: 16628 ns  min: 16054 ns  max: 18654 ns
   [ 2] ISRs: 9  avg: 16391 ns  min: 16086 ns  max: 18427 ns
   [ 3] ISRs: 9  avg: 16391 ns  min: 16086 ns  max: 18420 ns
   [ 4] ISRs: 9  avg: 16390 ns  min: 16086 ns  max: 18420 ns
   [ 5] ISRs: 9  avg: 16391 ns  min: 16086 ns  max: 18420 ns
   [ 6] ISRs: 9  avg: 16388 ns  min: 16080 ns  max: 18420 ns
   [ 7] ISRs: 9  avg: 16391 ns  min: 16080 ns  max: 18420 ns
   [ 8] ISRs: 9  avg: 16390 ns  min: 16086 ns  max: 18420 ns
   [ 9] ISRs: 9  avg: 16391 ns  min: 16086 ns  max: 18420 ns
   [10] ISRs: 9  avg: 16390 ns  min: 16080 ns  max: 18420 ns

   eBPF programs detached. Profiling complete.
