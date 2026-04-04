.. _ebpf:

eBPF (extended Berkeley Packet Filter)
######################################

Zephyr eBPF is a bounded, verifier-backed runtime for observability code that
runs inside the kernel when stable hooks fire. The subsystem now centers on a
single loader-and-bundle architecture.

Probes are authored offline, built into a bundle image, and loaded through the
loader API.

The old static registration model is no longer part of the product-facing
architecture.

Why It Exists
*************

Zephyr systems repeatedly need answers to questions such as:

* How often is the scheduler switching threads?
* Which ISR path is firing too frequently?
* Which PM states are actually being entered, and for how long?
* Which temporary measurement should be deployed in the field without shipping
  a new firmware image?

Without eBPF, each question tends to become a new kernel or subsystem patch.
Zephyr eBPF shifts that work into a reusable runtime with explicit safety and
resource limits.

Loader And Bundle Model
***********************

Runtime-loaded probes are built on the host with :command:`west ebpf build`
and loaded through :c:func:`ebpf_loader_load`. They are the right choice for
signed field diagnostics and temporary investigation probes.

Current Scope
*************

The current implementation provides:

* stable hook names for thread switch, ISR, idle, and PM state transitions,
* two backends: tracing and PM notifier integration,
* one map type: array,
* two helper services: map lookup and monotonic time,
* a runtime loader with image authentication and named bundle control.

.. toctree::
   :maxdepth: 2

   architecture
   components
   authoring
   constraints

How To Read This Section
************************

* This page is the problem statement and the shallow overview.
* Continue with :doc:`architecture` for the authoritative subsystem design:
  stable hooks, lifecycle, hot-path dispatch, verifier, VM, maps, bundles, and
  control-plane flow.
* Use :doc:`components` as the deep-dive reference. Each major component now
  has its own page.
* Read :doc:`authoring` when you need to build or sign runtime-loadable probe
  bundles.
* Keep :doc:`constraints` nearby when reviewing changes to the runtime model.
* The public API reference is included at the end of this page.

Typical Workflows
*****************

Bundle workflow
===============

1. Write restricted C against the public authoring headers such as
  :zephyr_file:`include/zephyr/ebpf/ebpf_map.h`,
  :zephyr_file:`include/zephyr/ebpf/ebpf_prog.h`, and
  :zephyr_file:`include/zephyr/ebpf/ebpf_helpers.h`.
2. Build a bundle with :command:`west ebpf build`.
3. Optionally sign the bundle with ECDSA P-256 plus SHA-256.
4. Load the bundle with :c:func:`ebpf_loader_load`.
5. Enable, inspect, disable, and unload the named bundle as needed.

What Zephyr eBPF Is, and Is Not
*******************************

Zephyr eBPF is:

* a lightweight event-driven programmability layer,
* a practical tool for tracing, counting, aggregating, and exporting data,
* a runtime meant to fit Zephyr's memory and latency constraints.

Zephyr eBPF is not:

* a full replacement for the Linux BPF subsystem,
* a complete Linux userspace tooling environment,
* a promise of broad Linux helper, map, or program-type compatibility.

API Reference
*************

The public eBPF API is documented through the ``ebpf`` Doxygen group.

.. doxygengroup:: ebpf

For the contract-driven rules behind helper availability and event-context
semantics, see :doc:`architecture`, :doc:`components`, and :doc:`constraints`.
For bundle construction and runtime-loading workflow, see :doc:`authoring`.

See Also
********

* :zephyr:code-sample:`ebpf-thread-switch-counter`
* :ref:`tracing`
* :zephyr_file:`include/zephyr/ebpf/ebpf_prog.h`
* :zephyr_file:`include/zephyr/ebpf/ebpf_loader.h`
* :zephyr_file:`include/zephyr/ebpf/ebpf_map.h`