.. _ebpf:

eBPF (extended Berkeley Packet Filter)
######################################

The Zephyr eBPF subsystem is a lightweight runtime for event-driven,
in-kernel programmability. It borrows the core mental model of Linux eBPF,
including bytecode, a verifier, helper calls, maps, and backend-aware
attachment, but scopes those ideas to Zephyr's predictability and resource
limits.

The pages below explain the subsystem from a beginner-friendly architecture
view: what each component owns, how components collaborate, and which design
limits matter when you build on top of them.

.. toctree::
  :maxdepth: 2

  overview
  architecture
  components
  constraints
  api

Overview
********

Start with :doc:`overview` for the problem statement and the basic lifecycle.
Continue with :doc:`architecture` to see the control path and event path, then
use :doc:`components` as the component-by-component reference for the
subsystem internals.

API Reference
*************

The public API reference is available in :doc:`api`.

See Also
********

* :zephyr:code-sample:`ebpf-hello-trace`
* :zephyr:code-sample:`ebpf-pm-residency`
* :ref:`tracing`
* :zephyr_file:`include/zephyr/ebpf/ebpf_insn.h`
* :zephyr_file:`include/zephyr/ebpf/ebpf_map.h`
* :zephyr_file:`include/zephyr/ebpf/ebpf_prog.h`
* :zephyr_file:`include/zephyr/ebpf/ebpf_attach_target.h`

This is especially useful for observability, lightweight tracing, and prototype
instrumentation on constrained systems.

The subsystem is easiest to understand as two paths that meet in the runtime:

* the control path prepares programs to run,
* the event path executes enabled programs when a backend target fires.

The short mental model is:

* :zephyr_file:`subsys/ebpf/ebpf_prog.c` is the eBPF program lifecycle
  orchestrator,
* :zephyr_file:`subsys/ebpf/ebpf_attach_target.c` is the target registry and dispatch
  runtime,
* :zephyr_file:`subsys/ebpf/ebpf_verifier.c` is the safety gate,
* :zephyr_file:`subsys/ebpf/backends/ebpf_tracing.c` and
  :zephyr_file:`subsys/ebpf/backends/ebpf_pm.c` are backend bridges,
* :zephyr_file:`subsys/ebpf/ebpf_vm.c` is the execution engine,
* :zephyr_file:`subsys/ebpf/ebpf_helpers.c` is the service switchboard,
* :zephyr_file:`subsys/ebpf/ebpf_maps.c` is the shared state store.

Why Zephyr Has eBPF
*******************

Zephyr applications often need to answer questions such as:

* How often is the scheduler switching threads?
* Which ISR path is firing too frequently?
* Which PM states are actually being entered, and for how long?
* What state should be accumulated across repeated events?
* How can I add instrumentation without rewriting subsystem code?

Without eBPF, each new question tends to require a new patch to kernel or
subsystem source code. The Zephyr eBPF subsystem shifts part of that work into
data-driven programs that can be defined once, attached to a kernel event, and
reused with a stable runtime model.

The design goal is not to reproduce the entire Linux BPF ecosystem. The goal is
to provide a practical Zephyr-friendly subset with:

* static registration,
* predictable memory use,
* bounded execution,
* clear integration with multiple Zephyr event backends,
* enough helpers and map types to support useful observability workflows.

Subsystem Architecture
**********************

The diagram below shows the complete runtime in one view.

.. figure:: images/ebpf_architecture.svg
  :alt: Zephyr eBPF subsystem architecture
  :width: 100%

  Zephyr eBPF subsystem architecture.

Read it from left to right:

* Attach backends are the event sources. Today the subsystem ships with a
  tracing backend and a PM notifier backend. Each backend emits a backend-
  specific event context when a system event occurs.

* :zephyr_file:`subsys/ebpf/ebpf_attach_target.c` is the target runtime hub. It owns
  attach-target validity checks, target naming, program-to-target attach
  policy, enabled-program discovery, and forwarding of event contexts to the
  VM. A program owns at most one attached target at a time, and each attach
  starts a new attachment. One target may fan out to multiple enabled
  programs.

* :zephyr_file:`subsys/ebpf/backends/ebpf_tracing.c` and
  :zephyr_file:`subsys/ebpf/backends/ebpf_pm.c` are backend bridges. They translate
  backend-native hooks into :c:type:`ebpf_attach_target` plus a context struct,
  then call into the common target dispatcher. The tracing backend implements
  Zephyr tracing-user callbacks instead of injecting eBPF logic into the generic
  custom-tracing header.

* :zephyr_file:`subsys/ebpf/ebpf_vm.c` is the execution engine. For each event,
  it creates a fresh register set and stack, passes the event context in
  register ``R1``, and interprets the program bytecode.

* :zephyr_file:`subsys/ebpf/ebpf_helpers.c` is the service switchboard. Helper
  IDs used by the program are translated into controlled runtime services such
  as map lookup, time queries, and ring-buffer output.

* :zephyr_file:`subsys/ebpf/ebpf_maps.c` is the shared state store. Maps hold
  persistent state across events and provide the main data exchange path
  between eBPF programs and normal application code.

* :zephyr_file:`subsys/ebpf/ebpf_prog.c` owns program-level state such as
  attachment-session lifecycle, enablement, verification handoff, and static
  lookup.

* :zephyr_file:`subsys/ebpf/ebpf_verifier.c` is the safety gate. A program is
  checked before it is enabled so malformed bytecode does not reach the event
  path.

This split is deliberate: program management stays out of the hot event path,
while the event path stays short and predictable.

Typical Lifecycle
*****************

A typical eBPF workflow in Zephyr is:

1. Define a bytecode array and register it with :c:macro:`EBPF_PROG_DEFINE`.
2. Define any maps with :c:macro:`EBPF_MAP_DEFINE`.
3. Let subsystem initialization assign runtime map IDs and initialize map
   backends.
4. Attach the program with :c:func:`ebpf_prog_attach`.
5. Enable the program with :c:func:`ebpf_prog_enable`; this verifies the
   program if needed.
6. When the target fires, the backend bridge dispatches the event to the VM.
7. The program uses helpers and maps to read context, keep state, and export
   results.
8. Normal application code, test code, or shell commands read those results.

The :zephyr:code-sample:`ebpf-hello-trace` sample follows exactly this model.
It binds a small scheduler-oriented program to
:c:enumerator:`EBPF_TRACING_ATTACH_THREAD_SWITCHED_IN`, increments a counter in
an array map, and prints that counter from normal application code. The
:zephyr:code-sample:`ebpf-pm-residency` sample applies the same model to the
PM notifier backend.

Core Concepts
*************

Programs
========

An eBPF program in Zephyr is defined as an instruction array together with a
descriptor in :zephyr_file:`include/zephyr/ebpf/ebpf_prog.h`. Programs are
statically registered and later attached to a concrete target.

The most useful way to think about a program is as bytecode plus type
information. Verification, enablement, and execution statistics are scoped to
the current attachment, while the attach target identifies where that
attachment runs. In the descriptor layout, the immutable program definition
stays at the top level while current runtime state is grouped under the
program's current attachment.

Targets
-------

The target object is the public attachment abstraction. It binds one program to
one concrete backend hook while keeping backend namespaces explicit.

The public target model is:

* :c:type:`ebpf_attach_target` identifies ``backend + point``.
* :c:macro:`EBPF_ATTACH_TARGET_TRACING` and :c:macro:`EBPF_ATTACH_TARGET_PM` construct
  concrete targets.
* :c:func:`ebpf_prog_attach`, :c:func:`ebpf_prog_enable`,
  :c:func:`ebpf_prog_disable`, and :c:func:`ebpf_prog_detach` manage the
  program lifecycle for one attachment at that target.

Program Types
-------------

Program type is meaningful because it defines the program family, the target
families it may bind to, and the target-specific execution contract that
should evolve around it.

The key distinction is:

* :c:type:`ebpf_attach_target` identifies a concrete backend target such as a
  tracing hook or a PM notifier phase.
* :c:type:`ebpf_prog_type` identifies a program family such as generic,
  scheduler, ISR, or PM.

The current architecture baseline is:

.. list-table:: Program-type contract baseline
   :header-rows: 1

   * - Program type
     - Allowed targets
     - Current ``R1`` contract
     - Architectural role
   * - ``EBPF_PROG_TYPE_GENERIC``
     - Any :c:type:`ebpf_attach_target`
     - Backend-specific context chosen by the target
     - Generic observability and an escape hatch for new targets that do not
       yet have a dedicated typed family
   * - ``EBPF_PROG_TYPE_SCHED``
     - Thread and scheduler-related tracing targets only
     - Currently thread-event context; should evolve toward a scheduler-focused
       context layout where appropriate
     - Scheduler analysis and future scheduler-policy assistance
   * - ``EBPF_PROG_TYPE_ISR``
     - :c:enumerator:`EBPF_TRACING_ATTACH_ISR_ENTER` and
       :c:enumerator:`EBPF_TRACING_ATTACH_ISR_EXIT`
     - :c:struct:`ebpf_ctx_isr`
     - ISR latency analysis and future interrupt-focused tooling
   * - ``EBPF_PROG_TYPE_PM``
     - :c:enumerator:`EBPF_PM_ATTACH_STATE_ENTRY` and
       :c:enumerator:`EBPF_PM_ATTACH_STATE_EXIT`
     - :c:struct:`ebpf_ctx_pm`
     - PM state auditing, residency profiling, and future PM policy hooks

For thread-oriented tracing targets, the current context exposes an opaque
thread cookie and the current priority. The cookie is suitable for correlating
events within one system image, but it is not a stable cross-build or
cross-reboot thread identifier.

Idle tracing targets use :c:struct:`ebpf_ctx_idle`, which currently exposes
only the CPU index associated with the idle transition.

Today the runtime uses program types primarily to enforce program-target
compatibility. Over time, helper allowlists, verifier refinements, and any
return-value semantics should follow the same taxonomy rather than being
inferred from target numbering or ad hoc hook logic.

The current shared contract table is deliberately narrower than that long-term
vision. Today it is keyed by ``(prog_type, backend, point)`` and enforces only
two runtime rules shared by the verifier and VM:

* which helpers are allowed for the attachment,
* whether the event context in ``R1`` is read-only.

The concrete ``R1`` layout remains part of the backend target definition. For example,
thread-oriented tracing uses :c:struct:`ebpf_ctx_thread` and PM notifications
use :c:struct:`ebpf_ctx_pm`.

Verifier
========

Before a program is enabled, the verifier checks that it is well-formed and
safe enough for the current attachment. The verifier validates things
such as:

* program size,
* supported opcodes,
* register indices,
* valid jump targets,
* helper IDs,
* bounded stack usage.

Today the verifier still inspects the program as a whole, but the runtime does
not treat verification as a lifetime property of the program descriptor.
Changing the target starts a new attachment, invalidates the previous
verification result, and resets the current-attachment execution statistics. This
keeps the control path ready for future target-aware verifier rules without
changing the public lifecycle model.

This verifier is intentionally lightweight. Its job is to prevent obviously
unsafe or malformed program.

Its role is not to optimize programs or prove every runtime property. Its role
is to be the subsystem's safety gate.

VM (Virtual Machine)
====================

The VM is the execution engine. Each invocation creates a fresh execution
context containing registers, a program counter, and a private stack. The VM
supports the instruction families currently needed by the subsystem:

* 64-bit ALU operations,
* 32-bit ALU operations,
* memory load/store,
* jumps,
* helper calls,
* exit.

Optional runtime bounds checking can further constrain memory accesses to the
VM stack, the event context, and registered map storage.

This keeps the hot path simple: the VM only needs to execute one prepared
program against one event context.

Helpers
=======

Helpers are the subsystem's controlled extension surface. A program cannot call
arbitrary Zephyr internals directly. Instead, it issues a helper call, and the
runtime resolves that helper ID to a specific implementation.

The helper layer is therefore the service switchboard between bytecode and the
rest of the kernel runtime.

Current helpers include operations for:

* map lookup, update, and delete,
* timestamp retrieval,
* tracing-oriented debug output,
* current task or CPU information,
* ring buffer output.

Maps
====

Maps provide persistent state across repeated invocations. They let eBPF
programs accumulate counters, share state with application code, and export
records.

The current implementation supports:

* array maps,
* ring buffer maps.

The map layer is intentionally static-first: maps are defined at build time,
assigned runtime IDs during initialization, and then accessed through a common
operations table.

This makes maps the subsystem's shared state store: they are where transient
event handling turns into reusable counters, tables, and exported records.

Attach Backends
===============

Attach backends are where programs connect to real system activity. Each
backend owns native hook integration, but they all converge on the same
target-plus-program runtime contract.

Today the subsystem includes:

* the tracing backend for scheduler, ISR, and idle hooks,
* the PM notifier backend for state entry and exit events.

This keeps the event source separate from the program logic. A backend decides
*when* to call into eBPF, while the eBPF runtime decides *how* to execute the
enabled programs bound to that target.

Design Philosophy
*****************

Experienced developers will notice that this subsystem is not trying to be a
verbatim Linux BPF port. That is deliberate.

The design philosophy is:

* Linux-inspired semantics where they add familiarity and leverage,
* Zephyr-oriented implementation choices where they improve predictability,
* explicit limits instead of implicit dynamism,
* enough power for multi-backend observability without importing unnecessary
  complexity.

Concretely, that means:

* static registration instead of runtime loaders,
* a small interpreter instead of JIT compilation,
* a lightweight verifier instead of a Linux-scale verifier,
* bounded helper and map support chosen for practical observability workflows,
* explicit program attachment to backend-aware targets instead of backend-
  specific hook APIs.

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
control tracing support, PM support, map types, the shell interface, VM stack size, program
size, and optional runtime bounds checking.

For backend-oriented usage, the most relevant options are:

* :kconfig:option:`CONFIG_EBPF`
* :kconfig:option:`CONFIG_EBPF_TRACING`
* :kconfig:option:`CONFIG_EBPF_PM`
* :kconfig:option:`CONFIG_EBPF_STATS`

API Reference
*************

.. doxygengroup:: ebpf

See Also
********

* :zephyr:code-sample:`ebpf-hello-trace`
* :zephyr:code-sample:`ebpf-pm-residency`
* :ref:`tracing`
* :zephyr_file:`include/zephyr/ebpf/ebpf_insn.h`
* :zephyr_file:`include/zephyr/ebpf/ebpf_map.h`
* :zephyr_file:`include/zephyr/ebpf/ebpf_prog.h`
* :zephyr_file:`include/zephyr/ebpf/ebpf_attach_target.h`
