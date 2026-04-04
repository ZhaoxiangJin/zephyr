# SPDX-FileCopyrightText: Copyright 2026 NXP
# SPDX-License-Identifier: Apache-2.0

zephyr_library()

zephyr_library_sources(
  init.c
  bundle/bundle.c
  contract.c
  attach/attachment.c
  attach/hook/hook.c
  loader/loader.c
  loader/image.c
  vm/vm.c
  verifier.c
  map/core.c
  map/backends/array.c
  helpers/helpers.c
  attach/target/target.c
  prog/prog.c
)

zephyr_library_sources_ifdef(CONFIG_EBPF_TRACING attach/backends/tracing.c)
zephyr_library_sources_ifdef(CONFIG_EBPF_PM attach/backends/pm.c)
