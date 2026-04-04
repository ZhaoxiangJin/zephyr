Authoring Runtime-Loadable Probes
#################################

Runtime-loadable probes are authored off target and delivered to the device as
loader image version 2 bundles. The target never parses C or ELF directly.

Build Workflow
**************

The host-side entry point is :command:`west ebpf build`.

.. code-block:: console

   west ebpf build my_probe.c -o my_probe.bundle
   west ebpf build my_probe.c -o my_probe.bundle --auth ecdsa-p256-sha256 --signing-key probe_key.pem --ttl-ms 600000

The command accepts either:

* a restricted-C probe source file, compiled with ``clang -target bpf``, or
* an already-built eBPF ELF object.

The output is a loader image accepted by :c:func:`ebpf_loader_load`. That image
contains the bundle header, map records, attachment records, relocation
records, string table, and authentication block.

Useful builder options include:

* ``--bundle-name`` to override the runtime bundle name,
* ``--ttl-ms`` to embed a default auto-unload timeout,
* ``--auth`` to select ``none``, ``crc32``, or
  ``ecdsa-p256-sha256`` authentication,
* ``--signing-key`` or ``--signature-file`` for ECDSA bundles,
* ``--emit-elf`` to keep the intermediate ELF object when compiling C input.

Restricted-C Surface
********************

The authoring surface is split by responsibility:

* :zephyr_file:`include/zephyr/ebpf/ebpf_map.h` provides ``EBPF_MAP(...)`` for
  declaring loader-visible maps in the ``.maps`` section,
* :zephyr_file:`include/zephyr/ebpf/ebpf_prog.h` provides
  ``EBPF_PROGRAM(...)``, ``EBPF_PROGRAM_SCHED(...)``,
  ``EBPF_PROGRAM_ISR(...)``, and ``EBPF_PROGRAM_PM(...)`` for hook-bound
  programs,
* :zephyr_file:`include/zephyr/ebpf/ebpf_helpers.h` provides the host-safe
  helper wrappers for map lookup and time reads.

Section Naming
**************

The current builder uses section names as the attachment manifest.

Supported patterns are:

* ``ebpf/<hook-name>``
* ``ebpf.generic/<hook-name>``
* ``ebpf.sched/<hook-name>``
* ``ebpf.isr/<hook-name>``
* ``ebpf.pm/<hook-name>``

For example, ``EBPF_PROGRAM("kernel/thread_switched_in")`` emits a program in
the ``ebpf/kernel/thread_switched_in`` section. The builder converts that into
a runtime attachment targeting the stable hook name
``kernel/thread_switched_in``.

Current stable hook names are documented in :doc:`components/hook_model`.

Example
*******

.. code-block:: c

  #include <zephyr/ebpf/ebpf_helpers.h>
  #include <zephyr/ebpf/ebpf_map.h>
  #include <zephyr/ebpf/ebpf_prog.h>

   EBPF_MAP(counter_map, EBPF_MAP_TYPE_ARRAY, uint32_t, uint32_t, 1);

   EBPF_PROGRAM("kernel/thread_switched_in")
   int count_switches(void *ctx)
   {
       uint32_t key = 0;
       uint32_t *value = ebpf_map_lookup_elem(&counter_map, &key);

       if (value != 0) {
           *value += 1;
       }

       return 0;
   }

Loading And Control
*******************

Once built, a bundle can be delivered in two main ways:

* direct application or test code can pass the bundle bytes to
  :c:func:`ebpf_loader_load`,
* remote tooling can stage the image through the MCUmgr eBPF group and then use
  its load, enable, disable, unload, and dump operations.

There is currently no dedicated :command:`west ebpf load` command. Loading and
transport are separate from host-side bundle construction.

For an end-to-end example that builds a bundle during the application build and
loads it through :c:func:`ebpf_loader_load`, see
:zephyr:code-sample:`ebpf-thread-switch-counter`.

Authentication Modes
********************

The loader currently supports three authentication modes:

* ``none`` for unsecured development images,
* ``crc32`` for corruption detection,
* ``ecdsa-p256-sha256`` for signature verification against the configured
  pinned public key.

For production-style field workflows, ECDSA is the intended mode.

Current Limits
**************

The current authoring path is intentionally narrow.

Today it supports:

* map definitions from ``.maps``,
* program-to-hook binding through section names,
* map relocations from ELF into the runtime loader image,
* bundle TTL metadata,
* CRC32 or ECDSA authentication blocks,
* MCUmgr transport to the in-target loader.

It does not yet provide:

* target-side ELF parsing,
* BTF- or schema-driven field relocation,
* richer manifest metadata such as per-probe budgets or permissions,
* a full host CLI for remote lifecycle control beyond bundle construction.