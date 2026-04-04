Stable Hook Model
#################

Files:

* :zephyr_file:`include/zephyr/ebpf/ebpf_hook.h`
* :zephyr_file:`subsys/ebpf/attach/ebpf_hook.c`

Role
****

The hook layer is the stable public attachment surface for the subsystem. It
maps user-facing hook IDs and names onto concrete :c:type:`ebpf_attach_target`
values and records the context size each hook exposes in register ``R1``.

This is what lets bundle metadata, loader control paths, and hook-based APIs
talk about the same attachment points without depending on backend-local
numbering.

Current Hook Set
****************

The current implementation exposes these stable hook names:

* ``kernel/thread_switched_in`` with :c:struct:`ebpf_ctx_thread`
* ``kernel/thread_switched_out`` with :c:struct:`ebpf_ctx_thread`
* ``kernel/isr_enter`` with :c:struct:`ebpf_ctx_isr`
* ``kernel/isr_exit`` with :c:struct:`ebpf_ctx_isr`
* ``kernel/idle_enter`` with :c:struct:`ebpf_ctx_idle`
* ``kernel/idle_exit`` with :c:struct:`ebpf_ctx_idle`
* ``pm/state_entry`` with :c:struct:`ebpf_ctx_pm`
* ``pm/state_exit`` with :c:struct:`ebpf_ctx_pm`

Owns
****

* hook ID validation,
* name-to-ID and name-to-target translation,
* target-to-hook translation for diagnostics,
* context-size metadata for the stable hook catalog,
* the stable hook-name contract consumed by bundle and loader attachment specs.

Collaborates With
*****************

* :doc:`../architecture` uses the hook layer as the public attachment model for
  runtime-loaded probes.
* :doc:`program_lifecycle` enables runtime-owned attachments that are already
  named in terms of stable hooks.
* :doc:`loader` passes stable hook names from bundle metadata into attachment
  creation.
* :doc:`backends` still dispatch concrete targets; the hook layer does not own
  native event capture.

Design Limits
*************

* Stable hook names are part of the public subsystem contract.
* The hook layer is a translation layer, not a second dispatch runtime.
* New backends should normally expose new stable hooks instead of asking users
  to attach by backend-local point numbers.
* Changing a hook's context size or semantic meaning is an architectural change
  that affects both authoring and runtime loading.