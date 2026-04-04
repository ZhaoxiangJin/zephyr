Design Constraints
##################

This page records the architectural rules that shape the current subsystem.
They are not accidental implementation details. They are the design contract
new work should respect unless the architecture itself is being revised.

One Loader And Bundle Architecture
**********************************

Bundle loading and runtime execution are one architecture. They should not grow
separate hook, verifier, VM, or dispatch stacks.

Why it exists:

* it keeps the mental model coherent,
* it lets all loaded probes share the same safety rules,
* it avoids duplicating hot-path machinery.

What it means for contributors:

* new features should extend the common runtime where possible,
* public workflows should target stable hooks, bundles, and loader APIs,
* image-format, loader, and bundle-runtime changes should preserve one
  coherent control path.

Stable Hook Names Front The Public Model
****************************************

Public attachment semantics should center on stable hook IDs and names rather
than raw backend numbering.

Why it exists:

* runtime-loaded images need stable names that survive internal refactoring,
* hook-based APIs are easier for users than backend-specific point numbers,
* it keeps backend internals behind a smaller public surface.

What it means for contributors:

* new attachment points should be exposed through the hook layer,
* loader images and public hook APIs must not depend on backend-local numeric
  details,
* changes to hook names or context sizes are architectural changes.

One Program, One Current Attachment
***********************************

A program owns one current attachment at a time. One target may have multiple
enabled programs, but one program does not keep several simultaneous target
bindings.

Why it exists:

* it keeps runtime state readable,
* it keeps verification rules unambiguous,
* it matches the current bundle attachment model.

What it means for contributors:

* features that need multi-attach semantics should be treated as architecture
  work,
* new APIs should preserve the current session model unless the design is being
  intentionally expanded.

Immutable Target Snapshots On The Hot Path
******************************************

Enabled dispatch state is published as immutable per-target snapshots.

Why it exists:

* it prevents control-plane races with synchronous backend dispatch,
* it keeps event delivery simple and bounded,
* it allows bundle-owned teardown to wait for quiescence explicitly.

What it means for contributors:

* do not add mutable per-attachment control fields that the event path rereads,
* enable, disable, detach, and unload operations should publish a new snapshot,
* hot-path changes should be reviewed for latency and reader-drain behavior.

Attachment-Scoped Verification
******************************

Verification belongs to the current attachment session, not to the lifetime of
the program descriptor.

Why it exists:

* different targets imply different helper and context contracts,
* reattachment must invalidate stale verification results.

What it means for contributors:

* do not treat prior verification results as globally reusable,
* session sequence handling is part of the correctness model.

Interpreter-Only Execution
**************************

The runtime uses an interpreter. There is no JIT compiler.

Why it exists:

* simpler implementation,
* easier portability,
* better fit for constrained systems.

What it means for contributors:

* event-path cost matters,
* new instruction handling should remain straightforward to reason about,
* hot backends should not gain helper or VM work casually.

Contract-Driven Helper Policy
*****************************

Helper availability is part of the resolved attachment contract, not just a
property of the global helper registry.

Why it exists:

* tracing, ISR, and PM paths have different latency tolerance,
* helper side effects must match the execution environment,
* verifier and VM must agree on the same policy.

What it means for contributors:

* adding a helper requires updating the shared contract table,
* the contract key is ``(prog_type, backend, point)``,
* helper policy and runtime helper behavior must evolve together.

Backend-Owned Event Capture And Context Layout
**********************************************

Backends own native event capture and the concrete layout of the context object
passed in register ``R1``.

Why it exists:

* different event families expose different useful state,
* it isolates backend-specific details from the generic runtime,
* it keeps new backends additive instead of invasive.

What it means for contributors:

* backend glue should translate native events into the common target-plus-
  context model,
* new context layouts should be documented together with their helper policy,
* backend-specific policy should not leak into unrelated runtime files.

Narrow Helper And Map Surface
*****************************

The helper set and map set are intentionally small.

Why it exists:

* each helper expands the verifier and runtime contract,
* each map type adds memory and behavioral complexity,
* the subsystem is focused on practical observability rather than maximal API
  coverage.

What it means for contributors:

* new helpers need a clear architectural justification,
* map additions should include ownership and memory-model analysis,
* Linux feature parity is not a sufficient reason by itself.

Transactional Runtime Loading
*****************************

Runtime loading should either produce a fully instantiated named bundle or fail
without partially activating anything.

Why it exists:

* field diagnostics need predictable operational behavior,
* authentication and format failures must fail closed,
* unload must leave the registry in a coherent state.

What it means for contributors:

* loader-side changes should preserve all-or-nothing semantics,
* bundle teardown must continue to quiesce live dispatch before freeing owned
  state,
* transport code should stage uploads until the full image is available.
