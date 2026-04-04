.. zephyr:code-sample:: ebpf-thread-switch-counter-mcumgr
   :name: eBPF Thread Switch Counter over MCUmgr

   Upload and control a runtime eBPF probe over MCUmgr, then read its map
   remotely through the same management plane.


Overview
********

This sample demonstrates the remote-delivery side of the Zephyr eBPF runtime
loader flow.

The firmware image only contains the runtime loader, tracing backend, and the
MCUmgr eBPF management group. It does not embed any probe bytes. At run time
the application simply keeps generating scheduler thread-switch events while
the management plane handles:

* loading a bundle named ``thread_switch_probe`` remotely,
* enabling or disabling that bundle,
* dumping loader state,
* reading the runtime-owned ``counter_map`` by bundle and map name.

The probe source is shipped next to the sample for convenience, but it is built
separately on the host with ``west ebpf build`` and uploaded later through the
MCUmgr eBPF group. This keeps the target image and the probe bundle as two
independent artifacts, which matches the intended field workflow.

Unlike :doc:`/samples/subsys/ebpf/thread_switch_counter/README`, this sample is
explicitly about remote transport and control.

Prerequisites
*************

The workflow requires:

* a board supported by this sample, such as ``frdm_mcxa156``,
* ``west`` with the eBPF extension command available,
* ``clang`` with the BPF target enabled for bundle generation,
* Python 3 with ``pyserial`` available for the host helper script.

``pyserial`` is already part of Zephyr's base Python requirements. If needed,
install it manually with:

.. code-block:: console

   python -m pip install pyserial

Building and Flashing
*********************

Build and flash the target application:

.. zephyr-app-commands::
   :tool: west
   :zephyr-app: samples/subsys/ebpf/thread_switch_counter_mcumgr
   :board: frdm_mcxa156
   :goals: build flash
   :compact:

Build the runtime probe bundle separately on the host:

.. code-block:: console

   west ebpf build samples/subsys/ebpf/thread_switch_counter_mcumgr/probe/thread_switch_counter.c \
     -o build/frdm_mcxa156_thread_switch_counter_mcumgr/thread_switch_counter.bundle \
     --bundle-name thread_switch_probe

Remote Upload and Control
*************************

The sample includes a small host helper that speaks Zephyr's SMP-over-UART
framing directly, so no external ``mcumgr`` CLI plugin is required for the
custom eBPF group.

Load and auto-enable the bundle, then keep the port open for 5 seconds to
watch the target console banner:

.. code-block:: console

   python samples/subsys/ebpf/thread_switch_counter_mcumgr/host/ebpf_mcumgr_client.py \
     --port COM7 load \
     --bundle build/frdm_mcxa156_thread_switch_counter_mcumgr/thread_switch_counter.bundle \
     --enable --follow 10

Query the current runtime-loader state:

.. code-block:: console

   python samples/subsys/ebpf/thread_switch_counter_mcumgr/host/ebpf_mcumgr_client.py \
     --port COM7 dump

Read one map entry directly through the MCUmgr eBPF group:

.. code-block:: console

    python samples/subsys/ebpf/thread_switch_counter_mcumgr/host/ebpf_mcumgr_client.py \
       --port COM7 map-read --name thread_switch_probe --map counter_map --key-hex 00000000

Poll the same 32-bit counter once per second and print deltas on the host:

.. code-block:: console

    python samples/subsys/ebpf/thread_switch_counter_mcumgr/host/ebpf_mcumgr_client.py \
       --port COM7 watch-u32 --name thread_switch_probe --map counter_map --key-u32 0 \
       --interval 1 --samples 10

Disable or unload the bundle by name:

.. code-block:: console

   python samples/subsys/ebpf/thread_switch_counter_mcumgr/host/ebpf_mcumgr_client.py \
     --port COM7 disable --name thread_switch_probe

   python samples/subsys/ebpf/thread_switch_counter_mcumgr/host/ebpf_mcumgr_client.py \
     --port COM7 unload --name thread_switch_probe

.. note::

   On boards where the console and MCUmgr transport share the same UART, only
   one host process can own the serial port at a time. The ``--follow`` option
   is the easiest way to observe console output immediately after a command.

Sample Output
*************

.. code-block:: console

   *** Booting Zephyr OS build ... ***
   eBPF thread-switch counter over MCUmgr
   ====================================

      This firmware only generates thread-switch activity.
      Use the MCUmgr eBPF group to load probes and read maps remotely.

      $ python samples/subsys/ebpf/thread_switch_counter_mcumgr/host/ebpf_mcumgr_client.py \
         --port COM7 watch-u32 --name thread_switch_probe --map counter_map --key-u32 0
      [1] counter_map[0] = 106 (+0)
      [2] counter_map[0] = 210 (+104)
      [3] counter_map[0] = 316 (+106)

Related Documentation
*********************

For the runtime architecture and authoring model, see :ref:`ebpf`,
:doc:`/services/ebpf/architecture`, :doc:`/services/ebpf/authoring`, and
:doc:`/services/ebpf/components/operations`.