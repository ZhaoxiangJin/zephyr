Overview
########

The Zephyr eBPF subsystem lets an application run small, verified bytecode
programs when selected kernel events occur. Instead of patching subsystem C
code every time you need another counter, state table, or event export path,
you define:

1. an eBPF program,
2. any maps the program needs,
3. a concrete attachment target,
4. and normal application code that consumes the results.

This model is useful for observability, prototype instrumentation, state
aggregation, and backend-specific measurements such as scheduler activity or
power-management residency.

Why Zephyr Has eBPF
*******************

Zephyr systems often need to answer questions such as:

* How often is the scheduler switching threads?
* Which interrupt path is firing too frequently?
* Which PM states are entered, and how long do they last?
* What state should persist across repeated events without adding new kernel
  code for each experiment?

Without eBPF, each question tends to become a new subsystem patch. Zephyr eBPF
shifts part of that work into a reusable runtime with explicit limits that fit
embedded systems.

The goal is not to reproduce the entire Linux BPF ecosystem. The goal is to
provide a practical subset with:

* static registration,
* predictable memory use,
* bounded execution,
* controlled helper access,
* and backend-aware attachment to real Zephyr events.

Typical Lifecycle
*****************

A typical Zephyr eBPF workflow is:

1. Define a bytecode array and register it with :c:macro:`EBPF_PROG_DEFINE`.
2. Define any maps with :c:macro:`EBPF_MAP_DEFINE`.
3. Let subsystem initialization assign runtime map IDs and initialize map
   backends.
4. Attach the program with :c:func:`ebpf_prog_attach`.
5. Enable the program with :c:func:`ebpf_prog_enable`. This verifies the
   program for the current attachment if needed.
6. When the target fires, the backend bridge dispatches the event to the VM.
7. The program uses helpers and maps to read context, keep state, and export
   results.
8. Normal application code, tests, or shell commands read those results.

The :zephyr:code-sample:`ebpf-hello-trace` sample follows this model with a
tracing target. The :zephyr:code-sample:`ebpf-pm-residency` sample applies the
same model to the PM notifier backend.

What Zephyr eBPF Is, and Is Not
*******************************

Zephyr eBPF is:

* a lightweight event-driven programmability layer,
* a practical tool for tracing, counting, filtering, and exporting data,
* a subsystem designed to fit Zephyr's resource model.

Zephyr eBPF is not:

* a full replacement for the Linux BPF subsystem,
* a complete Linux userspace tooling environment,
* a promise of broad Linux helper or program-type compatibility.

Configuration
*************

The subsystem is enabled through :kconfig:option:`CONFIG_EBPF`. Related options
control tracing support, PM support, map types, the shell interface, VM stack
size, program size, and optional runtime bounds checking.

For backend-oriented usage, the most relevant options are:

* :kconfig:option:`CONFIG_EBPF`
* :kconfig:option:`CONFIG_EBPF_TRACING`
* :kconfig:option:`CONFIG_TRACING_USER`
* :kconfig:option:`CONFIG_EBPF_PM`
* :kconfig:option:`CONFIG_EBPF_STATS`
