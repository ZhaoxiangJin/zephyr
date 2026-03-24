import fs from "node:fs/promises";
import path from "node:path";
import { fileURLToPath } from "node:url";

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

function escapeXml(text) {
  return text
    .replaceAll("&", "&amp;")
    .replaceAll("<", "&lt;")
    .replaceAll(">", "&gt;")
    .replaceAll('"', "&quot;");
}

function textBlock({ x, y, lines, className, anchor = "middle", lineHeight = 18 }) {
    const items = lines
    .map((line, index) => {
      const dy = index === 0 ? 0 : lineHeight;
        return `<tspan x="${x}" dy="${dy}">${escapeXml(line)}</tspan>`;
    })
    .join("");

    return `<text class="${className}" x="${x}" y="${y}" text-anchor="${anchor}">${items}</text>`;
}

function estimateWidth(text, unit = 7.2) {
  return text.length * unit;
}

function wrapLine(text, maxWidth, unit = 7.2) {
    if (estimateWidth(text, unit) <= maxWidth) {
    return [text];
  }

  const words = text.split(/\s+/);
  const lines = [];
  let current = "";

  for (const word of words) {
      const next = current ? `${current} ${word}` : word;

      if (!current || estimateWidth(next, unit) <= maxWidth) {
          current = next;
      continue;
    }

    lines.push(current);
    current = word;
  }

  if (current) {
    lines.push(current);
  }

  return lines;
}

function wrapLines(lines, maxWidth, unit = 7.2) {
  return lines.flatMap((line) => wrapLine(line, maxWidth, unit));
}

function panel({ x, y, width, height, title, subtitle, tone = "runtime" }) {
  return [
    `<rect class="panel panel-${tone}" x="${x}" y="${y}" width="${width}" height="${height}" rx="22" ry="22" />`,
      `<line class="panel-divider" x1="${x}" y1="${y + 56}" x2="${x + width}" y2="${y + 56}" />`,
    textBlock({
      x: x + 18,
        y: y + 30,
        lines: [title],
      className: "panel-title",
      anchor: "start",
      lineHeight: 18,
    }),
    textBlock({
      x: x + 18,
      y: y + 82,
        lines: wrapLines([subtitle], width - 36, 6.8),
      className: "panel-subtitle",
      anchor: "start",
      lineHeight: 16,
    }),
  ].join("\n");
}

function card({ x, y, width, height, title, meta, tone, badge }) {
    const titleLines = wrapLines(Array.isArray(title) ? title : [title], width - 32, 8.2);
    const metaLines = wrapLines(Array.isArray(meta) ? meta : [meta], width - 36, 6.7);
    const badgeWidth = Math.max(88, estimateWidth(badge, 6.5) + 20);
    const titleY = y + 62;
    const metaY = titleY + (titleLines.length * 19) + 10;

  return [
      `<rect class="card card-${tone}" x="${x}" y="${y}" width="${width}" height="${height}" rx="18" ry="18" />`,
      `<rect class="badge badge-${tone}" x="${x + 16}" y="${y + 14}" width="${badgeWidth}" height="24" rx="12" ry="12" />`,
      textBlock({
          x: x + 26,
          y: y + 30,
          lines: [badge],
          className: `badge-text badge-text-${tone}`,
          anchor: "start",
          lineHeight: 14,
    }),
    textBlock({
      x: x + width / 2,
      y: titleY,
      lines: titleLines,
        className: `card-title card-title-${tone}`,
        lineHeight: 19,
    }),
      textBlock({
          x: x + width / 2,
          y: metaY,
          lines: metaLines,
          className: "card-meta",
          lineHeight: 15,
    }),
  ].join("\n");
}

function sectionTag({ x, y, text, tone, minWidth = 92 }) {
  const width = Math.max(minWidth, estimateWidth(text, 5.8) + 22);

  return [
    `<rect class="section-tag section-tag-${tone}" x="${x}" y="${y}" width="${width}" height="28" rx="14" ry="14" />`,
    textBlock({
      x: x + width / 2,
      y: y + 19,
      lines: [text],
      className: `section-tag-text section-tag-text-${tone}`,
      lineHeight: 14,
    }),
  ].join("\n");
}

function connectorLabel({ x, y, text, minWidth = 108 }) {
  const width = Math.max(minWidth, estimateWidth(text, 5.7) + 22);
  const left = x - width / 2;

  return [
    `<rect class="connector-label" x="${left}" y="${y - 14}" width="${width}" height="28" rx="14" ry="14" />`,
    textBlock({
      x,
      y: y + 5,
      lines: [text],
      className: "connector-label-text",
      lineHeight: 14,
    }),
  ].join("\n");
}

function pathFromPoints(points) {
  return points
    .map(([x, y], index) => `${index === 0 ? "M" : "L"} ${x} ${y}`)
    .join(" ");
}

function edgeFromPoints({ points, dashed = false }) {
  return `<path class="edge${dashed ? " edge-dashed" : ""}" d="${pathFromPoints(points)}" fill="none" marker-end="url(#arrow)" />`;
}

function centerX(box) {
    return box.x + box.width / 2;
}

function centerY(box) {
    return box.y + box.height / 2;
}

function right(box) {
    return box.x + box.width;
}

function bottom(box) {
    return box.y + box.height;
}

function renderArchitecture() {
    const parts = [];

    const layout = {
      kernelPanel: { x: 44, y: 58, width: 286, height: 500 },
      runtimePanel: { x: 362, y: 58, width: 938, height: 500 },
      appPanel: { x: 1332, y: 58, width: 304, height: 820 },
      controlPanel: { x: 362, y: 602, width: 938, height: 276 },

      tracingHooks: { x: 72, y: 180, width: 230, height: 122 },
      pmNotifier: { x: 72, y: 338, width: 230, height: 122 },

      tracingBridge: { x: 414, y: 176, width: 208, height: 122 },
      pmBridge: { x: 414, y: 338, width: 208, height: 122 },
      targetHub: { x: 688, y: 230, width: 256, height: 176 },
      vm: { x: 1012, y: 176, width: 230, height: 122 },
      helpers: { x: 1012, y: 338, width: 230, height: 122 },
      maps: { x: 738, y: 444, width: 264, height: 96 },

      prog: { x: 458, y: 716, width: 286, height: 118 },
      verifier: { x: 832, y: 716, width: 286, height: 118 },

      definitions: { x: 1370, y: 206, width: 228, height: 126 },
      consumers: { x: 1370, y: 434, width: 228, height: 126 },
    };

    parts.push(`<?xml version="1.0" encoding="UTF-8"?>
<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 1680 920" role="img" aria-labelledby="title desc">
  <title id="title">Zephyr eBPF subsystem architecture</title>
  <desc id="desc">System architecture diagram showing separate tracing and PM event sources, a shared eBPF runtime hub, an explicit control plane, and application-side integration.</desc>
  <defs>
    <marker id="arrow" viewBox="0 0 10 10" refX="9" refY="5" markerWidth="9" markerHeight="9" orient="auto-start-reverse">
      <path d="M 0 0 L 10 5 L 0 10 z" fill="#294157" />
    </marker>
    <style>
      .bg { fill: #ffffff; }
      .frame { fill: none; stroke: #d7dee7; stroke-width: 1.5; }
      .panel { stroke-width: 1.5; }
      .panel-kernel { fill: #fcfaf6; stroke: #d6cab8; }
      .panel-runtime { fill: #fbfcfe; stroke: #ced8e3; }
      .panel-control { fill: #fcfaf6; stroke: #d6cab8; }
      .panel-app { fill: #f9fbfe; stroke: #d3dae3; }
      .panel-divider { stroke: #dde4ed; stroke-width: 1; }
      .panel-title { fill: #243447; font: 600 18px Cambria, "Times New Roman", serif; letter-spacing: 0.2px; }
      .panel-subtitle { fill: #627389; font: 16px "Segoe UI", Arial, sans-serif; }
      .section-tag { stroke-width: 0; }
      .section-tag-runtime { fill: #e5eef9; }
      .section-tag-control { fill: #efe7d7; }
      .section-tag-data { fill: #e5efe3; }
      .section-tag-text { font: 600 11px "Segoe UI", Arial, sans-serif; letter-spacing: 0.8px; }
      .section-tag-text-runtime { fill: #35597a; }
      .section-tag-text-control { fill: #6f5b30; }
      .section-tag-text-data { fill: #496548; }
      .card { stroke-width: 1.7; }
      .card-kernel { fill: #fffdfa; stroke: #c6a582; }
      .card-runtime { fill: #f8fbff; stroke: #8ea9c4; }
      .card-data { fill: #f6faf5; stroke: #91a88d; }
      .card-control { fill: #fbfaf6; stroke: #b7a47b; }
      .card-app { fill: #f7f9fc; stroke: #93a6bb; }
      .card-title { fill: #243447; font: 600 19px "Segoe UI", Arial, sans-serif; }
      .card-meta { fill: #66768a; font: 13px Consolas, "Courier New", monospace; }
      .badge { stroke-width: 0; }
      .badge-kernel { fill: #f1e5d9; }
      .badge-runtime { fill: #e5eef9; }
      .badge-data { fill: #e5efe3; }
      .badge-control { fill: #efe7d7; }
      .badge-app { fill: #e8edf4; }
      .badge-text { font: 600 11px "Segoe UI", Arial, sans-serif; letter-spacing: 0.8px; }
      .badge-text-kernel { fill: #7a5c3c; }
      .badge-text-runtime { fill: #35597a; }
      .badge-text-data { fill: #496548; }
      .badge-text-control { fill: #6f5b30; }
      .badge-text-app { fill: #495d73; }
      .edge { stroke: #294157; stroke-width: 2.3; stroke-linecap: round; stroke-linejoin: round; }
      .edge-dashed { stroke-dasharray: 7 6; }
      .connector-label { fill: #ffffff; stroke: #d7dee7; stroke-width: 1; }
      .connector-label-text { fill: #45586f; font: 12.5px "Segoe UI", Arial, sans-serif; }
      .caption { fill: #5f7187; font: 15px "Segoe UI", Arial, sans-serif; }
    </style>
  </defs>
  <rect class="bg" x="0" y="0" width="1680" height="920" rx="20" ry="20" />
  <rect class="frame" x="12" y="12" width="1656" height="896" rx="18" ry="18" />`);

    parts.push(panel({
      ...layout.kernelPanel,
      title: "Zephyr Kernel Event Sources",
      subtitle: "Tracing hooks and PM notifiers stay separate here. They only converge after backend-specific callbacks are translated into the common eBPF target model.",
      tone: "kernel",
  }));

    parts.push(panel({
      ...layout.runtimePanel,
      title: "Common eBPF Runtime",
      subtitle: "A shared runtime hub validates targets, finds enabled programs, executes them in the VM, and exposes controlled services and persistent state.",
      tone: "runtime",
  }));

    parts.push(panel({
      ...layout.appPanel,
      title: "Application Integration",
      subtitle: "Static program and map definitions enter through the public API. Application logic, shell commands, and tests consume state exported through maps or ring buffers.",
      tone: "app",
  }));

    parts.push(panel({
      ...layout.controlPanel,
      title: "Program Control Plane",
      subtitle: "Program lifecycle management stays off the hot event path. Each attach starts one session, and verification gates enablement for that session.",
      tone: "control",
    }));

  parts.push(sectionTag({ x: 388, y: 140, text: "event plane", tone: "runtime" }));
  parts.push(sectionTag({ x: 388, y: 640, text: "control plane", tone: "control" }));
  parts.push(sectionTag({ x: 736, y: 418, text: "data plane", tone: "data" }));

  parts.push(card({
    ...layout.tracingHooks,
    title: ["Tracing Hooks"],
    meta: ["scheduler, ISR, idle", "native tracing callbacks"],
    tone: "kernel",
    badge: "kernel source",
  }));

  parts.push(card({
    ...layout.pmNotifier,
    title: ["PM Notifier"],
    meta: ["state entry and exit", "native PM callbacks"],
    tone: "kernel",
    badge: "kernel source",
  }));

    parts.push(card({
      ...layout.tracingBridge,
      title: ["ebpf_tracing"],
      meta: ["tracing backend bridge", "hook callback -> target + ctx"],
      tone: "runtime",
      badge: "backend bridge",
    }));

    parts.push(card({
      ...layout.pmBridge,
      title: ["ebpf_pm"],
      meta: ["PM backend bridge", "notifier callback -> target + ctx"],
      tone: "runtime",
      badge: "backend bridge",
    }));

  parts.push(card({
      ...layout.targetHub,
      title: ["ebpf_target"],
    meta: ["shared target runtime", "check attach-target validity", "apply prog attach policy and fan-out"],
      tone: "runtime",
      badge: "shared hub",
    }));

    parts.push(card({
      ...layout.vm,
      title: ["ebpf_vm"],
      meta: ["execution engine", "fresh stack and registers", "interpret verified bytecode"],
      tone: "runtime",
      badge: "execution",
  }));

    parts.push(card({
      ...layout.helpers,
      title: ["ebpf_helpers"],
      meta: ["service switchboard", "helper ID -> runtime service"],
      tone: "runtime",
      badge: "service layer",
  }));

    parts.push(card({
      ...layout.maps,
      title: ["ebpf_maps"],
      meta: ["persistent shared state", "array, hash, ringbuf, per-CPU array"],
      tone: "data",
      badge: "shared state",
  }));

    parts.push(card({
      ...layout.prog,
      title: ["ebpf_prog"],
      meta: ["program lifecycle orchestrator", "attach, detach, enable", "current attachment state"],
      tone: "control",
      badge: "runtime API core",
  }));

    parts.push(card({
      ...layout.verifier,
      title: ["ebpf_verifier"],
      meta: ["safety gate", "opcode, jump, helper, stack checks"],
      tone: "control",
      badge: "safety gate",
  }));

    parts.push(card({
      ...layout.definitions,
      title: ["Program and Map", "Definitions"],
      meta: ["EBPF_PROG_DEFINE", "EBPF_MAP_DEFINE", "public eBPF headers"],
      tone: "app",
      badge: "static inputs",
    }));

  parts.push(card({
    ...layout.consumers,
    title: ["Consumers and Tools"],
    meta: ["application logic, shell, tests", "read counters or ring buffers"],
    tone: "app",
    badge: "normal code",
  }));

    parts.push(textBlock({
      x: 830,
      y: 576,
      lines: ["Separate backend sources converge into one target hub; program lifecycle stays below the event path."],
      className: "caption",
      lineHeight: 16,
  }));

  parts.push(edgeFromPoints({
    points: [
      [right(layout.tracingHooks), centerY(layout.tracingHooks)],
      [layout.tracingBridge.x, centerY(layout.tracingHooks)],
    ],
    }));

  parts.push(edgeFromPoints({
    points: [
      [right(layout.pmNotifier), centerY(layout.pmNotifier)],
      [layout.pmBridge.x, centerY(layout.pmNotifier)],
    ],
    }));

  parts.push(edgeFromPoints({
    points: [
      [right(layout.tracingBridge), centerY(layout.tracingBridge)],
      [652, centerY(layout.tracingBridge)],
      [652, 274],
      [layout.targetHub.x, 274],
    ],
    }));

  parts.push(edgeFromPoints({
    points: [
      [right(layout.pmBridge), centerY(layout.pmBridge)],
      [652, centerY(layout.pmBridge)],
      [652, 364],
      [layout.targetHub.x, 364],
    ],
    }));

  parts.push(edgeFromPoints({
    points: [
      [right(layout.targetHub), centerY(layout.targetHub)],
      [layout.vm.x, centerY(layout.targetHub)],
    ],
    }));

  parts.push(edgeFromPoints({
    points: [
      [centerX(layout.vm), bottom(layout.vm)],
      [centerX(layout.vm), layout.helpers.y],
    ],
  }));

  parts.push(edgeFromPoints({
    points: [
      [centerX(layout.helpers), bottom(layout.helpers)],
      [centerX(layout.helpers), 492],
      [right(layout.maps), 492],
    ],
  }));

  parts.push(edgeFromPoints({
    points: [
      [right(layout.maps), centerY(layout.maps)],
      [1284, centerY(layout.maps)],
      [1284, centerY(layout.consumers)],
      [layout.consumers.x, centerY(layout.consumers)],
    ],
  }));

  parts.push(edgeFromPoints({
    points: [
      [layout.definitions.x, centerY(layout.definitions)],
      [1262, centerY(layout.definitions)],
      [1262, centerY(layout.prog)],
      [right(layout.prog), centerY(layout.prog)],
    ],
    dashed: true,
  }));

  parts.push(edgeFromPoints({
    points: [
      [layout.definitions.x, centerY(layout.definitions) + 24],
      [1294, centerY(layout.definitions) + 24],
      [1294, centerY(layout.maps)],
      [right(layout.maps), centerY(layout.maps)],
    ],
    dashed: true,
    }));

  parts.push(edgeFromPoints({
    points: [
      [right(layout.prog), centerY(layout.prog)],
      [layout.verifier.x, centerY(layout.verifier)],
    ],
    }));

  parts.push(edgeFromPoints({
    points: [
      [centerX(layout.prog), layout.prog.y],
      [centerX(layout.prog), 674],
      [centerX(layout.targetHub), 674],
      [centerX(layout.targetHub), bottom(layout.targetHub)],
    ],
    dashed: true,
    }));

  parts.push(connectorLabel({
    x: 527,
    y: 156,
    text: "target + context",
    minWidth: 118,
    }));

  parts.push(connectorLabel({
    x: 972,
    y: 230,
    text: "dispatch enabled program",
    minWidth: 166,
  }));

  parts.push(connectorLabel({
    x: 1149,
    y: 316,
    text: "CALL helpers",
    minWidth: 102,
    }));

  parts.push(connectorLabel({
    x: 1172,
    y: 492,
    text: "shared state exchange",
    minWidth: 152,
    }));

  parts.push(connectorLabel({
    x: 1250,
    y: 650,
    text: "attach / enable / detach",
    minWidth: 164,
    }));

  parts.push(connectorLabel({
    x: 1248,
    y: 418,
    text: "read exported state",
    minWidth: 144,
    }));

    parts.push("</svg>");
    return parts.join("\n");
}

async function main() {
    const architecturePath = path.join(__dirname, "ebpf_architecture.svg");

    await fs.writeFile(architecturePath, renderArchitecture(), "utf8");
}

main().catch((error) => {
    console.error(error);
    process.exitCode = 1;
});
