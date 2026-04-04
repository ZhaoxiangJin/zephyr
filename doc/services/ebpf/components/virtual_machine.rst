Virtual Machine
###############

Files:

* :zephyr_file:`subsys/ebpf/vm/ebpf_vm.c`
* :zephyr_file:`subsys/ebpf/vm/ebpf_vm.h`

Role
****

The VM is the execution engine. It interprets verified bytecode for one event
delivery and provides the per-invocation register file, private stack, program
counter, and instruction dispatch logic.

Execution Model
***************

For every dispatched event:

1. the VM starts with a clean register file and a fresh private stack,
2. register ``R1`` receives the backend-defined event context,
3. the interpreter executes the program instruction stream,
4. helper calls are resolved through :doc:`helpers`,
5. any accepted return value is handed back to the caller.

Each program execution is independent. There is no persistent per-invocation VM
state shared between events.

Owns
****

* instruction decoding and execution,
* register and stack state for one invocation,
* immediate and memory access handling,
* runtime contract checks for helper use and context write attempts.

Collaborates With
*****************

* :doc:`dispatch_runtime` supplies the program and event context to execute.
* :doc:`helpers` resolves ``CALL`` instructions.
* :doc:`maps` is reached indirectly through helper calls and accepted memory
  accesses.
* :doc:`verifier_and_contracts` establishes the structural and contract rules
  the VM enforces at runtime.

Design Limits
*************

* The VM is an interpreter, not a JIT compiler.
* Execution runs in the backend's calling context, so long-running programs
  directly affect event latency.
* Runtime checks intentionally mirror the resolved contract so verifier bypasses
  do not silently widen the effective policy.