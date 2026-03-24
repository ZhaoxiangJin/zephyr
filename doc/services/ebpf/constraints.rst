Design Constraints
##################

This page records the main architectural constraints that shape the current
subsystem. These are not accidental implementation details. They are part of
the design contract new work should respect unless the architecture itself is
being revised.

Static-First Registration
*************************

Programs and maps are registered at build time. The subsystem does not provide
Linux-style runtime loaders or dynamic object lifecycles.

Why it exists:

* it keeps memory ownership explicit,
* it reduces runtime complexity,
* it fits Zephyr deployment models.

What it means for contributors:

* new features should not assume dynamic loading infrastructure exists,
* registration and discovery paths should remain predictable.

One Program, One Current Attachment
********************************

A program owns one current attachment at a time. One target may have
multiple enabled programs, but one program does not keep several simultaneous
target bindings.

Why it exists:

* it keeps program state readable,
* it avoids conflating program identity with multiple runtime attachments,
* it keeps current-attachment verification and statistics unambiguous.

What it means for contributors:

* features that need multi-attach semantics should be treated as architecture
  work, not as a small local extension.

Session-Scoped Verification and Statistics
******************************************

Verification and runtime statistics are properties of the current attachment
attachment, not permanent properties of the program descriptor.

Why it exists:

* target changes can change the semantic contract seen by the program,
* this keeps the control path ready for richer target-aware verification,
* it prevents old statistics from looking valid after a retarget.

What it means for contributors:

* do not treat a past verification result as globally reusable,
* do not merge statistics across unrelated sessions unless the API is changed
  intentionally.

Interpreter-Only Execution
**************************

The runtime uses a small interpreter. There is no JIT compiler.

Why it exists:

* simpler implementation,
* easier portability,
* better alignment with constrained systems.

What it means for contributors:

* event-path cost matters,
* hot-path changes should be evaluated with latency in mind.

Backend-Owned Event Capture
***************************

Backends own native hook integration. The common runtime owns validation,
target discovery, and fan-out.

Why it exists:

* it isolates backend-specific details,
* it keeps the common runtime generic,
* it makes new backends additive instead of invasive.

What it means for contributors:

* backend glue should translate native events into the common target-plus-
  context model,
* backend-specific policy should not leak arbitrarily into unrelated runtime
  files.

Constrained Helper and Map Surface
**********************************

The helper set and map set are intentionally small.

Why it exists:

* each new helper expands the verifier and runtime contract,
* each new map type adds memory and behavioral complexity,
* the subsystem is focused on practical observability rather than maximal API
  coverage.

What it means for contributors:

* new helpers should have a clear architectural justification,
* helper policy and verifier policy must evolve together,
* map additions should include memory-model and initialization analysis.

Backend-Specific Event Context
******************************

Register ``R1`` carries the backend-specific event context. That context is not
uniform across all target families.

Why it exists:

* different event families expose different useful state,
* a single generic context would either lose information or become vague.

What it means for contributors:

* new target families should define their event context deliberately,
* event contexts are read-only from eBPF programs and must stay safe to expose
  directly as input buffers,
* documentation and verifier policy should be updated together when the
  context layout
  changes.

Contract-Driven Helper Policy
*****************************

Helper availability is part of the attachment contract, not just a property of
the global helper registry.

Why it exists:

* tracing, ISR, and PM paths have different latency tolerance,
* helper side effects must match the execution environment,
* this keeps target semantics explicit instead of relying on ad hoc verifier
  rules.

What it means for contributors:

* adding a helper requires updating the shared contract table,
* verifier checks and VM runtime checks must continue to agree,
* the contract key is ``(prog_type, backend, point)``,
* the current contract table is intentionally narrow and stores only helper
  allowlists plus the read-only/writeable rule for the ``R1`` event context,
* backend and program-type semantics should stay clear enough that reviewers
  can reason about which helpers are safe on a given path.

Event-Context Layout
********************

In this subsystem, "event-context layout" means the concrete object layout
exposed to bytecode through register ``R1`` for a given attach target. For
example:

* thread-switch tracing passes :c:struct:`ebpf_ctx_thread`,
* ISR tracing passes :c:struct:`ebpf_ctx_isr`,
* idle tracing passes :c:struct:`ebpf_ctx_idle`,
* PM notifications pass :c:struct:`ebpf_ctx_pm`.

The current contract table does not repeat that metadata because verifier and
VM code do not consume it yet. Today the executable policy is narrower:

* which helpers are allowed for the attachment,
* whether the ``R1`` event context must remain read-only.

If future verifier logic needs per-context-layout offset or field validation,
that metadata can be promoted into the contract once it becomes executable
policy rather than descriptive data.
