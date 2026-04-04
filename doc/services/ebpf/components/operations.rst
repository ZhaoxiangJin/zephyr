Operations
##########

Files:

* :zephyr_file:`include/zephyr/ebpf/ebpf_loader.h`
* :zephyr_file:`subsys/ebpf/loader/ebpf_loader.c`
* :zephyr_file:`subsys/mgmt/mcumgr/grp/ebpf_mgmt/src/ebpf_mgmt.c`
* :zephyr_file:`include/zephyr/mgmt/mcumgr/grp/ebpf_mgmt/ebpf_mgmt.h`

Role
****

These components provide the operator-facing control surfaces around the core
runtime.

The loader APIs are the local control surface. The MCUmgr group is the remote
transport and control surface for runtime-loaded bundles.

Local Loader Surface
********************

The loader API surface exposes operations to:

* load a bundle from in-memory bytes,
* enable or disable a named bundle,
* unload a named bundle,
* inspect current bundle status and owned attachments and maps.

MCUmgr Surface
**************

The MCUmgr eBPF group exposes commands for:

* staged bundle upload and load,
* enable by bundle name,
* disable by bundle name,
* unload by bundle name,
* dump of loaded bundle status.

Uploads are staged in RAM and verified only after the final chunk arrives.
This preserves the loader's all-or-nothing semantics.

Collaborates With
*****************

* :doc:`loader` backs the local and remote named-bundle lifecycle.
* :doc:`bundle_runtime` owns the objects created after a successful load.

Design Limits
*************

* The loader and MCUmgr control surfaces operate on named bundles.
* Remote uploads are bounded by MCUmgr configuration and must preserve chunk
  order.