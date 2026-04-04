Helpers
#######

Files:

* :zephyr_file:`include/zephyr/ebpf/ebpf_helpers.h`
* :zephyr_file:`subsys/ebpf/helpers/helpers.c`

Role
****

Helpers are the controlled kernel service surface exposed to eBPF bytecode.
Programs cannot call arbitrary kernel functions directly. They can only invoke
helpers the runtime registers and the current attachment contract allows.

Current Helper Set
******************

The current helper IDs are:

* ``0``: reserved invalid helper ID,
* ``1``: map lookup,
* ``2``: monotonic time in nanoseconds.

Owns
****

* helper ID to function mapping,
* helper implementations for map lookup and time reads,
* the single lookup point used by the VM for helper dispatch.

Collaborates With
*****************

* :doc:`virtual_machine` resolves helper calls here.
* :doc:`maps` backs the map lookup helper.
* :doc:`verifier_and_contracts` uses the same helper IDs and must reject calls
  that are not permitted for the current attachment.
* :doc:`authoring` exposes host-safe wrappers for the same helper IDs in
  :zephyr_file:`include/zephyr/ebpf/ebpf_helpers.h`.

How a Helper Call Travels End-to-End
************************************

A helper call crosses three layers, linked by a single integer helper ID:

1. **Probe source (host-side compilation)**

   The probe ``.c`` file includes ``ebpf_helpers.h`` and calls a wrapper such as
   ``ebpf_map_lookup_elem()``.  This is not a real function â€?it is a static
   function pointer whose value equals the helper ID cast to a pointer:

   .. code-block:: c

      /* ebpf_helpers.h */
      static void *(*ebpf_map_lookup_elem)(const void *map, const void *key) =
                      (void *)(uintptr_t)EBPF_HELPER_MAP_LOOKUP_ELEM;  /* = 1 */

   When clang compiles this for the eBPF target, the constant address becomes the
   immediate field of a ``CALL`` instruction: ``CALL imm=1``.

2. **VM execution (target-side runtime)**

   When the VM reaches a ``CALL`` instruction it reads ``insn->imm`` and calls
   ``ebpf_get_helper(insn->imm)`` to obtain the real C function pointer.

3. **Helper dispatch (``helpers/ebpf_helpers.c``)**

   ``ebpf_get_helper()`` is a simple switch that maps the integer ID to the
   kernel-side implementation:

   .. code-block:: c

      switch (id) {
      case EBPF_HELPER_MAP_LOOKUP_ELEM: return &ebpf_helper_map_lookup_elem;
      case EBPF_HELPER_KTIME_GET_NS:   return &ebpf_helper_ktime_get_ns;
      }

   The implementation executes, and its return value is placed in register R0 for
   the eBPF program to consume.

In short, the helper ID is the ABI contract between host-compiled bytecode and
the target-side VM.  Probe sources use the wrapper function pointers and never
need to write raw ID numbers.

Design Limits
*************

* Helper coverage is intentionally small and explicit.
* Helper semantics are Zephyr-oriented, not Linux-compatibility promises.
* Helper availability remains contract-governed even when the current targets
  share the same helper set.
* Adding a helper always expands the verifier contract and the runtime ABI.