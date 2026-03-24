/*
 * SPDX-FileCopyrightText: Copyright 2026 NXP
 *
 * SPDX-License-Identifier: Apache-2.0
 */

#include <zephyr/kernel.h>
#include <zephyr/shell/shell.h>
#include <string.h>

#include <zephyr/ebpf/ebpf_attach_target.h>
#include <zephyr/ebpf/ebpf_map.h>
#include <zephyr/ebpf/ebpf_prog.h>

static struct ebpf_prog *ebpf_shell_prog_find_by_name(const char *name)
{
	STRUCT_SECTION_FOREACH(ebpf_prog, prog) {
		if (strcmp(prog->name, name) == 0) {
			return prog;
		}
	}

	return NULL;
}

static struct ebpf_map *ebpf_shell_map_find_by_name(const char *name)
{
	STRUCT_SECTION_FOREACH(ebpf_map, map) {
		if (strcmp(map->name, name) == 0) {
			return map;
		}
	}

	return NULL;
}

static const char *ebpf_prog_type_str(enum ebpf_prog_type type)
{
	switch (type) {
	case EBPF_PROG_TYPE_GENERIC:    return "generic";
	case EBPF_PROG_TYPE_SCHED:      return "sched";
	case EBPF_PROG_TYPE_ISR:        return "isr";
	case EBPF_PROG_TYPE_PM:         return "pm";
	default:                        return "unknown";
	}
}

static const char *ebpf_prog_state_str(enum ebpf_prog_state state)
{
	switch (state) {
	case EBPF_PROG_STATE_DETACHED: return "detached";
	case EBPF_PROG_STATE_ATTACHED: return "attached";
	case EBPF_PROG_STATE_VERIFIED: return "verified";
	case EBPF_PROG_STATE_ENABLED:  return "enabled";
	default:                       return "unknown";
	}
}

static const char *ebpf_map_type_str(enum ebpf_map_type type)
{
	switch (type) {
	case EBPF_MAP_TYPE_ARRAY:         return "array";
	case EBPF_MAP_TYPE_RINGBUF:       return "ringbuf";
	default:                          return "unknown";
	}
}

/* ebpf progs */
static int cmd_ebpf_progs(const struct shell *sh, size_t argc, char **argv)
{
	ARG_UNUSED(argc);
	ARG_UNUSED(argv);

	shell_print(sh, "%-20s %-10s %-10s %-26s %-10s",
		    "Name", "Type", "State", "Target", "Runs(cur)");
	shell_print(sh, "%-20s %-10s %-10s %-26s %-10s",
		    "----", "----", "-----", "------", "---------");

	STRUCT_SECTION_FOREACH(ebpf_prog, prog) {
		struct ebpf_prog_stats stats = ebpf_prog_get_stats(prog);
		struct ebpf_attach_target target = ebpf_prog_get_target(prog);
		enum ebpf_prog_state state = ebpf_prog_get_state(prog);

		shell_print(sh, "%-20s %-10s %-10s %-26s %-10llu",
			    prog->name,
			    ebpf_prog_type_str(prog->type),
			    ebpf_prog_state_str(state),
			    ebpf_attach_target_name(&target),
			    stats.run_count);
	}

	return 0;
}

/* ebpf enable <prog_name> */
static int cmd_ebpf_enable(const struct shell *sh, size_t argc, char **argv)
{
	struct ebpf_prog *prog = ebpf_shell_prog_find_by_name(argv[1]);

	if (!prog) {
		shell_error(sh, "Program '%s' not found", argv[1]);

		return -ENOENT;
	}

	ARG_UNUSED(argc);

	if (ebpf_prog_get_target(prog).backend == EBPF_ATTACH_BACKEND_MAX) {
		shell_error(sh, "Program '%s' is not attached", prog->name);

		return -EINVAL;
	}

	int ret = ebpf_prog_enable(prog);

	if (ret) {
		shell_error(sh, "Enable failed: %d", ret);

		return ret;
	}

	shell_print(sh, "Program '%s' enabled", prog->name);

	return 0;
}

/* ebpf disable <prog_name> */
static int cmd_ebpf_disable(const struct shell *sh, size_t argc, char **argv)
{
	struct ebpf_prog *prog = ebpf_shell_prog_find_by_name(argv[1]);

	if (!prog) {
		shell_error(sh, "Program '%s' not found", argv[1]);

		return -ENOENT;
	}

	ebpf_prog_disable(prog);
	shell_print(sh, "Program '%s' disabled", prog->name);

	return 0;
}

/* ebpf stats <prog_name> */
static int cmd_ebpf_stats(const struct shell *sh, size_t argc, char **argv)
{
	struct ebpf_prog *prog = ebpf_shell_prog_find_by_name(argv[1]);

	if (!prog) {
		shell_error(sh, "Program '%s' not found", argv[1]);

		return -ENOENT;
	}

	struct ebpf_prog_stats stats = ebpf_prog_get_stats(prog);
	struct ebpf_attach_target target = ebpf_prog_get_target(prog);
	enum ebpf_prog_state state = ebpf_prog_get_state(prog);

	shell_print(sh, "Program: %s", prog->name);
	shell_print(sh, "  Type:    %s", ebpf_prog_type_str(prog->type));
	shell_print(sh, "  State:   %s", ebpf_prog_state_str(state));
	shell_print(sh, "  Target:  %s", ebpf_attach_target_name(&target));
	shell_print(sh, "  Insns:   %u", prog->insn_cnt);
	shell_print(sh, "  Runs(cur):  %u", stats.run_count);
	shell_print(sh, "  RunNs(cur): %llu", stats.run_time_ns);

	if (stats.run_count > 0) {
		shell_print(sh, "  Avg(ns): %llu",
			    stats.run_time_ns / stats.run_count);
	}

	return 0;
}

/* ebpf maps */
static int cmd_ebpf_maps(const struct shell *sh, size_t argc, char **argv)
{
	ARG_UNUSED(argc);
	ARG_UNUSED(argv);

	shell_print(sh, "%-20s %-8s %-6s %-6s %-6s",
		    "Name", "Type", "KeySz", "ValSz", "MaxEnt");
	shell_print(sh, "%-20s %-8s %-6s %-6s %-6s",
		    "----", "----", "-----", "-----", "------");

	STRUCT_SECTION_FOREACH(ebpf_map, map) {
		shell_print(sh, "%-20s %-8s %-6u %-6u %-6u",
			    map->name,
			    ebpf_map_type_str(map->type),
			    map->key_size,
			    map->value_size,
			    map->max_entries);
	}

	return 0;
}

/* ebpf dump <map_name> */
static int cmd_ebpf_dump(const struct shell *sh, size_t argc, char **argv)
{
	struct ebpf_map *map = ebpf_shell_map_find_by_name(argv[1]);

	if (!map) {
		shell_error(sh, "Map '%s' not found", argv[1]);

		return -ENOENT;
	}

	if (map->type == EBPF_MAP_TYPE_ARRAY) {
		for (uint32_t i = 0; i < map->max_entries; i++) {
			void *val = ebpf_map_lookup_elem(map, &i);

			if (val) {
				shell_print(sh, "[%u]:", i);
				shell_hexdump(sh, val, map->value_size);
			}
		}
	} else {
		shell_print(sh, "Dump not yet supported for %s maps", ebpf_map_type_str(map->type));
	}

	return 0;
}

SHELL_STATIC_SUBCMD_SET_CREATE(sub_ebpf,
	SHELL_CMD(progs, NULL, SHELL_HELP("List all eBPF programs", NULL), cmd_ebpf_progs),
	SHELL_CMD_ARG(enable, NULL, SHELL_HELP("Enable program", "<prog_name>"),
		      cmd_ebpf_enable, 2, 0),
	SHELL_CMD_ARG(disable, NULL, SHELL_HELP("Disable program", "<prog_name>"),
		      cmd_ebpf_disable, 2, 0),
	SHELL_CMD_ARG(stats, NULL, SHELL_HELP("Show program stats", "<prog_name>"),
		      cmd_ebpf_stats, 2, 0),
	SHELL_CMD(maps, NULL, SHELL_HELP("List all eBPF maps", NULL), cmd_ebpf_maps),
	SHELL_CMD_ARG(dump, NULL, SHELL_HELP("Dump map", "<map_name>"),
		      cmd_ebpf_dump, 2, 0),
	SHELL_SUBCMD_SET_END
);

SHELL_CMD_REGISTER(ebpf, &sub_ebpf, "eBPF subsystem commands", NULL);
