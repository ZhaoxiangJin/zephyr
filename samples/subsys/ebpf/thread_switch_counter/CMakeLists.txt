# SPDX-FileCopyrightText: Copyright 2026 NXP
# SPDX-License-Identifier: Apache-2.0

cmake_minimum_required(VERSION 3.20.0)
find_package(Zephyr REQUIRED HINTS $ENV{ZEPHYR_BASE})
project(ebpf_thread_switch_counter)

if(WEST STREQUAL "WEST-NOTFOUND")
  message(FATAL_ERROR "The eBPF thread-switch counter sample requires west to build the probe bundle")
endif()

set(gen_dir ${ZEPHYR_BINARY_DIR}/include/generated)
set(probe_src ${CMAKE_CURRENT_SOURCE_DIR}/probe/thread_switch_counter.c)
set(probe_bundle ${PROJECT_BINARY_DIR}/thread_switch_counter.bundle)
set(probe_bundle_inc ${gen_dir}/thread_switch_counter.bundle.inc)

add_custom_command(
  OUTPUT ${probe_bundle}
  COMMAND ${WEST} ebpf build ${probe_src} -o ${probe_bundle}
  --bundle-name thread_switch_probe
  DEPENDS
  ${probe_src}
  ${ZEPHYR_BASE}/scripts/west_commands/ebpf.py
  ${ZEPHYR_BASE}/include/zephyr/ebpf/ebpf_helpers.h
  ${ZEPHYR_BASE}/include/zephyr/ebpf/ebpf_map.h
  ${ZEPHYR_BASE}/include/zephyr/ebpf/ebpf_prog.h
  WORKING_DIRECTORY ${CMAKE_CURRENT_SOURCE_DIR}
  COMMENT "Building thread-switch counter eBPF probe bundle"
  VERBATIM
)

generate_inc_file_for_target(app ${probe_bundle} ${probe_bundle_inc})

target_sources(app PRIVATE src/main.c)