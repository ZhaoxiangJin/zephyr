Components
##########

This page describes each major eBPF subsystem component as a separate runtime
building block. For each component, focus on four questions:

* What problem does it solve?
* What state or policy does it own?
* Which neighboring components does it depend on?
* Which design limits should a new contributor keep in mind?

Program Lifecycle Component
***************************

File: :zephyr_file:`subsys/ebpf/ebpf_prog.c`

Role
====

This component is the control-plane owner for eBPF programs. It does not run
program instructions itself. Instead, it manages the lifecycle of one program's
current attachment.

Owns
====

* attach and detach transitions,
* verify and enable transitions,
* current-attachment state and statistics,
* static lookup of registered program descriptors.

Collaborates With
=================

* :zephyr_file:`subsys/ebpf/ebpf_attach_target.c` for attach-target validity checks
  and program-to-target attach policy.
* :zephyr_file:`subsys/ebpf/ebpf_verifier.c` for safety checks before enable.
* public definitions in :zephyr_file:`include/zephyr/ebpf/ebpf_prog.h`.

Design Limits
=============

* One program owns one current target at a time.
* Reattaching starts a new session instead of reusing the old one.
* Verification and statistics are intentionally not cached across sessions.

Target Runtime Component
************************

File: :zephyr_file:`subsys/ebpf/ebpf_attach_target.c`

Role
====

This component is the common runtime hub for attachment targets shared by all
backends. It owns the backend namespace tables and the logic that decides
whether a concrete target is supported and which programs should receive an
event.

Owns
====

* backend target naming,
* attach-target validity checks,
* active-target checks,
* program-type attach-policy checks,
* discovery of enabled programs on a target,
* event fan-out from one target to many programs.

Collaborates With
=================

* :zephyr_file:`subsys/ebpf/ebpf_prog.c` on the control path.
* backend bridges such as :zephyr_file:`subsys/ebpf/backends/ebpf_tracing.c`
  and :zephyr_file:`subsys/ebpf/backends/ebpf_pm.c` on the event path.
* :zephyr_file:`subsys/ebpf/ebpf_vm.c` to execute each matching program.

Design Limits
=============

* Targets are statically described by backend-local name tables.
* Compatibility policy is type-driven, not inferred from arbitrary runtime
  metadata.
* The dispatcher assumes backend hooks are synchronous and should stay short.

Verifier Component
******************

File: :zephyr_file:`subsys/ebpf/ebpf_verifier.c`

Role
====

The verifier is the subsystem's safety gate. Its job is to reject obviously
unsafe or malformed bytecode before the runtime allows that program onto the
event path.

Owns
====

* instruction-count checks,
* opcode and register validation,
* jump-target validation,
* helper-ID validation,
* stack-usage checks,
* contract-driven helper allowlists,
* target-aware attachment and pointer-safety checks.

Collaborates With
=================

* :zephyr_file:`subsys/ebpf/ebpf_prog.c` for verify-on-enable semantics.
* :zephyr_file:`subsys/ebpf/ebpf_attach_target.c` for attach-target validity checks
  that decide when target-aware verifier policy should apply.
* :zephyr_file:`subsys/ebpf/ebpf_helpers.c` because helper policy must match
  real helper availability.

Design Limits
=============

* The verifier is intentionally lightweight compared to Linux eBPF.
* Current target policy is driven by a shared contract table indexed by
  program type, backend, and target point.
* The current table intentionally stores only the policy consumed by common
  code: helper allowlists and whether the event context is read-only.
* The current implementation enforces read-only event contexts and basic
  register provenance for context-derived pointers, but it is not a full
  symbolic verifier.
* Verification is scoped to the current attachment.

Virtual Machine Component
*************************

File: :zephyr_file:`subsys/ebpf/ebpf_vm.c`

Role
====

The VM is the execution engine. It interprets verified bytecode for one event
delivery.

Owns
====

* register state for one invocation,
* the private stack,
* the program counter,
* instruction decoding and execution,
* optional runtime bounds checks.

Collaborates With
=================

* :zephyr_file:`subsys/ebpf/ebpf_attach_target.c` to receive dispatched work.
* :zephyr_file:`subsys/ebpf/ebpf_helpers.c` for helper resolution.
* :zephyr_file:`subsys/ebpf/ebpf_maps.c` indirectly through helper calls and
  memory checks.

Design Limits
=============

* Each invocation starts from a clean VM state.
* The VM is an interpreter, not a JIT compiler.
* Execution runs in the backend's calling context, so long-running programs
  directly affect event latency.
* The VM re-checks contract helper allowlists and context write rules at
  runtime so verifier bypasses do not silently widen the event-context rules.

Helper Component
****************

File: :zephyr_file:`subsys/ebpf/ebpf_helpers.c`

Role
====

The helper layer is the controlled service surface between bytecode and the
rest of the kernel. Programs cannot call arbitrary kernel functions directly.
In eBPF terminology, a "helper" is not a generic utility function. It is a
whitelisted kernel service that bytecode may invoke through the eBPF ``CALL``
instruction.

Owns
====

* helper-ID to implementation mapping,
* map-operation helpers,
* time-query helpers,
* ring-buffer output helpers.

Collaborates With
=================

* :zephyr_file:`subsys/ebpf/ebpf_vm.c`, which resolves helper calls here.
* :zephyr_file:`subsys/ebpf/ebpf_maps.c` for map-backed helpers.
* :zephyr_file:`subsys/ebpf/ebpf_verifier.c`, which must allow only helpers
  that are semantically valid for the current contract.

Design Limits
=============

* Helper coverage is intentionally small and explicit.
* Helper semantics are Zephyr-oriented, not Linux-compatibility promises.
* Helper availability is not globally uniform; the resolved backend/program-type
  contract decides which helpers a program may call.
* The event-context layout itself is still defined by the attach target documentation
  and backend context structure, not by extra runtime metadata fields.

Map Component
*************

File: :zephyr_file:`subsys/ebpf/ebpf_maps.c`

Role
====

Maps are the subsystem's persistent shared state store. They let programs keep
state across events and share that state with non-eBPF code.

Owns
====

* concrete map implementations,
* map lookup, update, and delete operations,
* static map registration and runtime initialization,
* runtime map ID assignment.

Collaborates With
=================

* :zephyr_file:`subsys/ebpf/ebpf_helpers.c` for map-related helpers.
* :zephyr_file:`subsys/ebpf/ebpf_vm.c` when bounds checks recognize map memory.
* application code and samples that consume persistent results.

Design Limits
=============

* Maps are build-time registered, not dynamically created.
* Supported map types are deliberately limited.
* Map memory usage is explicit and must fit the target system.

Tracing Backend Component
*************************

File: :zephyr_file:`subsys/ebpf/backends/ebpf_tracing.c`

Role
====

This backend bridge translates Zephyr tracing hooks into the common eBPF target
and context model. It does so by implementing Zephyr tracing-user callbacks,
which keeps generic tracing headers free of eBPF-specific logic.

Owns
====

* tracing-target constants,
* tracing-user callback integration,
* conversion from tracing events to eBPF dispatch calls.

Collaborates With
=================

* :zephyr_file:`subsys/tracing/user/tracing_user.c`, which forwards generic
  tracing events into backend-specific user callbacks.
* :zephyr_file:`subsys/ebpf/ebpf_attach_target.c` for target dispatch.
* current event context layouts such as :c:type:`ebpf_ctx_thread`,
  :c:type:`ebpf_ctx_idle`, and :c:type:`ebpf_ctx_isr`.

Design Limits
=============

* Event shape is constrained by what the tracing hooks expose.
* Context layout stability should be designed intentionally per target family.

PM Backend Component
********************

File: :zephyr_file:`subsys/ebpf/backends/ebpf_pm.c`

Role
====

This backend bridge translates PM notifier events into the common eBPF target
and context model.

Owns
====

* PM-target constants,
* notifier registration,
* conversion from PM state entry and exit events to eBPF dispatch calls.

Collaborates With
=================

* Zephyr PM notifiers as the event source.
* :zephyr_file:`subsys/ebpf/ebpf_attach_target.c` for common dispatch.
* :c:type:`ebpf_ctx_pm` as the current PM event context layout.

Design Limits
=============

* PM helpers and context policy must reflect notifier execution semantics.
* PM event handlers should remain lightweight because they run on a sensitive
  system path.

Support Components
******************

Files: :zephyr_file:`subsys/ebpf/ebpf_init.c`,
:zephyr_file:`subsys/ebpf/ebpf_shell.c`

Role
====

These components are not part of the core execution chain, but they are part
of the subsystem story.

* :zephyr_file:`subsys/ebpf/ebpf_init.c` performs subsystem startup and map
  initialization.
* :zephyr_file:`subsys/ebpf/ebpf_shell.c` exposes inspection and control
  commands that make current-attachment state visible during debugging.

These files matter because they are often where a new user first interacts with
the subsystem, even though the core architecture lives elsewhere.
