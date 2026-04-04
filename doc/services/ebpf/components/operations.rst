Operations
##########

Files:

* :zephyr_file:`include/zephyr/ebpf/ebpf_loader.h`
* :zephyr_file:`subsys/ebpf/loader/loader.c`

Role
****

This component is the local, in-process control surface around the core
runtime. It lets application code load, enable, disable, and unload
runtime-loaded bundles, and enumerate what is currently loaded.

Local Loader Surface
********************

The loader API exposes operations to:

* load a bundle from in-memory bytes,
* enable or disable a loaded bundle via its handle,
* unload a loaded bundle via its handle,
* enumerate currently loaded bundles and inspect their status.

Collaborates With
*****************

* :doc:`loader` backs the bundle lifecycle and registry.
* :doc:`bundle_runtime` owns the objects created after a successful load.

Design Limits
*************

* Callers own the handle returned by :c:func:`ebpf_loader_load` for the
  lifetime of the loaded bundle.
* A remote transport for these operations is intentionally out of scope for
  this revision and may be layered on later.