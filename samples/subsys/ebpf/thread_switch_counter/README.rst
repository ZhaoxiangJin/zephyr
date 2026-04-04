.. zephyr:code-sample:: ebpf-thread-switch-counter
   :name: eBPF Thread Switch Counter

   Build a restricted-C eBPF probe bundle on the host, then load and enable it
   through the runtime loader and count scheduler thread-switch events.


Overview
********

This sample demonstrates a concrete runtime-loader workflow end to end.

During the application build, a restricted-C probe source is compiled with
``west ebpf build`` into a loader image bundle. The application embeds that
bundle as raw bytes, then at run time:

* calls :c:func:`ebpf_loader_load` to instantiate the bundle,
* finds the runtime-owned ``counter_map`` by name,
* enables the runtime-loaded attachment,
* starts a worker thread that periodically forces thread-switch events,
* reads the counter map from normal application code,
* disables and unloads the bundle.

The probe itself attaches to the stable hook ``kernel/thread_switched_in``
and increments an array map entry each time the hook fires.

This is a loader sample, not a remote transport sample. Real products may
deliver the same kind of bundle through MCUmgr or another management channel,
but this sample keeps transport out of the way so the runtime loader path is
easy to understand.

Prerequisites
*************

The sample build requires:

* ``west`` with the eBPF extension command available,
* ``clang`` with the BPF target enabled.

Building and Running
********************

The sample can be built and run on platforms with the tracing backend enabled,
for example ``qemu_x86``:

.. zephyr-app-commands::
   :zephyr-app: samples/subsys/ebpf/thread_switch_counter
   :host-os: unix
   :board: qemu_x86
   :goals: build run
   :compact:

Sample Output
*************

.. code-block:: console

   *** Booting Zephyr OS build ... ***
   eBPF thread-switch counter
   ==========================

   Loaded bundle: thread_switch_probe
   Runtime-loaded probe enabled.
   [1] thread_switched_in count=103 (+103)
   [2] thread_switched_in count=205 (+102)
   [3] thread_switched_in count=308 (+103)
   [4] thread_switched_in count=410 (+102)
   [5] thread_switched_in count=513 (+103)
   Runtime-loaded bundle unloaded.
   Thread-switch counter sample complete.

Related Documentation
*********************

For the runtime architecture and authoring model, see :ref:`ebpf`,
:doc:`/services/ebpf/architecture`, and :doc:`/services/ebpf/authoring`.