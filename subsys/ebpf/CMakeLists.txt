# SPDX-FileCopyrightText: Copyright 2026 NXP
# SPDX-License-Identifier: Apache-2.0

zephyr_library()

zephyr_library_sources(
  ebpf_init.c
  bundle/ebpf_bundle.c
  ebpf_contract.c
  attach/ebpf_hook.c
  loader/ebpf_loader.c
  vm/ebpf_vm.c
  ebpf_verifier.c
  map/ebpf_map_core.c
  map/ebpf_map_array.c
  helpers/ebpf_helpers.c
  attach/ebpf_attach_target.c
  prog/ebpf_prog.c
)

zephyr_library_sources_ifdef(CONFIG_EBPF_TRACING attach/backends/ebpf_tracing.c)
zephyr_library_sources_ifdef(CONFIG_EBPF_PM attach/backends/ebpf_pm.c)
