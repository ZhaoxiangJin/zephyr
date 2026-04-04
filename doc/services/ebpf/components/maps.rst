Maps
####

Files:

* :zephyr_file:`include/zephyr/ebpf/ebpf_map.h`
* :zephyr_file:`subsys/ebpf/map/core.c`
* :zephyr_file:`subsys/ebpf/map/backend/array.c`
* :zephyr_file:`subsys/ebpf/init.c`

Role
****

Maps are the subsystem's persistent shared state store. They let programs keep
state across events and share that state with non-eBPF code.

The same map runtime serves the maps instantiated for a bundle during load.
The current implementation is split between a common map core and the array
backend.

Supported Map Types
*******************

The current implementation supports:

* array maps for fixed-size indexed state.

Each live map receives a small runtime ID at creation time. ID ``0`` is
reserved as invalid.

Owns
****

* map lookup, update, and delete operations,
* runtime map creation and destruction,
* runtime ID assignment,
* ownership tracking for bundle-owned maps.

Collaborates With
*****************

* :doc:`helpers` exposes map services to programs.
* :doc:`bundle_runtime` claims ownership of bundle-instantiated maps.
* :doc:`loader` resolves relocation records against runtime map IDs.
* :doc:`operations` and application code inspect map contents after programs
  run.

Design Limits
*************

* The map set is intentionally small.
* Map memory usage is explicit and must fit the target system.
* Bundle-owned maps are destroyed as part of bundle unload.
* Map additions should be reviewed as both an ABI expansion and a memory-model
  change.