Components
##########

This section is the component-by-component reference for the current runtime.
Read it top to bottom if you are new to the code, or jump directly to the part
you are reviewing.

.. toctree::
   :maxdepth: 1

   components/hook_model
   components/program_lifecycle
   components/dispatch_runtime
   components/verifier_and_contracts
   components/virtual_machine
   components/helpers
   components/maps
   components/bundle_runtime
   components/loader
   components/operations
   components/backends

Recommended Reading Order
*************************

* :doc:`components/hook_model` explains the stable public attachment surface.
* :doc:`components/program_lifecycle` explains how one program session moves
  through attach, verify, enable, disable, and detach.
* :doc:`components/dispatch_runtime` explains the immutable snapshot model that
  protects the hot path.
* :doc:`components/verifier_and_contracts` and
  :doc:`components/virtual_machine` explain the safety gate and execution path.
* :doc:`components/bundle_runtime`, :doc:`components/loader`, and
  :doc:`components/operations` explain runtime-loaded bundles and their control
  surfaces.

Component Map
*************

* :doc:`components/hook_model` covers stable hook IDs, names, and hook-based
  attach APIs.
* :doc:`components/program_lifecycle` covers session ownership in
  :zephyr_file:`subsys/ebpf/prog/ebpf_prog.c`.
* :doc:`components/dispatch_runtime` covers target validation, immutable
  snapshots, and event fan-out.
* :doc:`components/verifier_and_contracts` covers structural checks and the
  shared helper and context policy table.
* :doc:`components/virtual_machine` covers the interpreter and per-event
  invocation model.
* :doc:`components/helpers` covers the controlled service surface behind eBPF
  ``CALL`` instructions.
* :doc:`components/maps` covers bundle-instantiated maps and their runtime
  semantics.
* :doc:`components/bundle_runtime` covers bundle-owned attachments and
  coordinated teardown.
* :doc:`components/loader` covers the image parser, authentication, registry,
  and TTL behavior.
* :doc:`components/operations` covers loader control and the MCUmgr eBPF
  transport.
* :doc:`components/backends` covers tracing and PM backend bridges.
