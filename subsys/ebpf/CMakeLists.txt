# SPDX-FileCopyrightText: Copyright 2026 NXP
# SPDX-License-Identifier: Apache-2.0

zephyr_library()

zephyr_library_sources(
  ebpf_init.c
  ebpf_contract.c
  ebpf_vm.c
  ebpf_verifier.c
  ebpf_maps.c
  ebpf_helpers.c
  ebpf_attach_target.c
  ebpf_prog.c
)

zephyr_library_sources_ifdef(CONFIG_EBPF_TRACING backends/ebpf_tracing.c)
zephyr_library_sources_ifdef(CONFIG_EBPF_PM backends/ebpf_pm.c)
zephyr_library_sources_ifdef(CONFIG_EBPF_SHELL ebpf_shell.c)
