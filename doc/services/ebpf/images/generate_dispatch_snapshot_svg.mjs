import {
  bottom,
  card,
  centerX,
  centerY,
  edge,
  headline,
  isDirectRun,
  labelBubble,
  note,
  panel,
  right,
  svgDocument,
  textBlock,
  writeSvg,
  zone,
} from "./svg_common.mjs";

export function renderDispatchSnapshotSvg() {
  const body = [];

  const hotPanel = { x: 48, y: 170, width: 1384, height: 242 };
  const updatePanel = { x: 48, y: 442, width: 1384, height: 304 };

  const event = { x: 94, y: 254, width: 196, height: 92 };
  const currentPtr = { x: 428, y: 254, width: 214, height: 92 };
  const active = { x: 748, y: 226, width: 258, height: 140 };
  const vm = { x: 1134, y: 244, width: 220, height: 102 };

  const update = { x: 94, y: 548, width: 214, height: 108 };
  const alternate = { x: 566, y: 536, width: 258, height: 140 };
  const retired = { x: 1090, y: 536, width: 248, height: 140 };

  body.push(headline({
    x: 52,
    y: 78,
    title: "Dispatch runtime snapshot publication",
    subtitle: "The event path reads one immutable snapshot while the control path prepares the alternate buffer. Publication is a pointer swap, not an in-place edit.",
    width: 1040,
  }));

  body.push(panel({
    ...hotPanel,
    title: "Hot event path",
    subtitle: "Readers stay short: capture the current pointer, increment reader count, iterate the compact attachment list, and execute matching programs.",
    tone: "green",
  }));

  body.push(panel({
    ...updatePanel,
    title: "Control-plane update path",
    subtitle: "Enable, disable, and unload operations build the next snapshot off-path, then publish it atomically when ready.",
    tone: "blue",
  }));

  body.push(zone({ x: 708, y: 206, width: 342, height: 490, label: "two preallocated buffers per target", tone: "slate" }));

  body.push(card({
    ...event,
    title: ["Backend event"],
    body: ["target + typed ctx", "synchronous callback"],
    tone: "green",
    badge: "reader",
  }));

  body.push(card({
    ...currentPtr,
    title: ["current_snapshot"],
    body: ["atomic pointer", "one target at a time"],
    tone: "green",
    badge: "reader",
  }));

  body.push(card({
    ...active,
    title: ["Active snapshot"],
    body: ["attachments[]", "reader count", "visible to the hot path"],
    tone: "green",
    badge: "buffer A or B",
  }));

  body.push(card({
    ...vm,
    title: ["VM fan-out"],
    body: ["one invocation per enabled entry", "fresh stack and registers"],
    tone: "green",
    badge: "execution",
  }));

  body.push(card({
    ...update,
    title: ["Control update"],
    body: ["lock target", "copy active state into alternate buffer"],
    tone: "blue",
    badge: "writer",
  }));

  body.push(card({
    ...alternate,
    title: ["Alternate snapshot"],
    body: ["edit attachment array", "prepare next published view"],
    tone: "blue",
    badge: "buffer A or B",
  }));

  body.push(card({
    ...retired,
    title: ["Retired snapshot"],
    body: ["old reader-visible state", "wait only when quiescence matters"],
    tone: "slate",
    badge: "drain",
  }));

  body.push(note({
    x: 326,
    y: 520,
    width: 196,
    title: "Why not edit in place?",
    lines: [
      "Readers would observe half-written state and race enable or unload.",
      "Snapshots keep event delivery deterministic.",
    ],
    tone: "rose",
  }));

  body.push(note({
    x: 860,
    y: 560,
    width: 192,
    title: "Publish step",
    lines: [
      "A single atomic pointer swap makes the next snapshot visible.",
      "Readers already in flight keep using the old one.",
    ],
    tone: "blue",
  }));

  body.push(edge({
    points: [
      [right(event), centerY(event)],
      [currentPtr.x, centerY(currentPtr)],
    ],
  }));

  body.push(edge({
    points: [
      [right(currentPtr), centerY(currentPtr)],
      [active.x, centerY(active)],
    ],
  }));

  body.push(edge({
    points: [
      [right(active), centerY(active)],
      [vm.x, centerY(vm)],
    ],
  }));

  body.push(edge({
    points: [
      [right(update), centerY(update)],
      [alternate.x, centerY(alternate)],
    ],
  }));

  body.push(edge({
    points: [
      [centerX(alternate), alternate.y],
      [centerX(alternate), 470],
      [centerX(currentPtr), 470],
      [centerX(currentPtr), bottom(currentPtr)],
    ],
  }));

  body.push(edge({
    points: [
      [right(active), centerY(active) + 38],
      [1060, centerY(active) + 38],
      [1060, centerY(retired)],
      [retired.x, centerY(retired)],
    ],
    dashed: true,
  }));

  body.push(labelBubble({ x: 360, y: 300, text: "capture pointer", tone: "green", minWidth: 126 }));
  body.push(labelBubble({ x: 630, y: 390, text: "reader-visible state", tone: "green", minWidth: 140 }));
  body.push(labelBubble({ x: 588, y: 696, text: "copy then edit", tone: "blue", minWidth: 118 }));
  body.push(labelBubble({ x: 644, y: 428, text: "atomic publish", tone: "blue", minWidth: 126 }));
  body.push(labelBubble({ x: 1188, y: 454, text: "sync disable waits here", tone: "slate", minWidth: 164 }));
  body.push(textBlock({
    x: 740,
    y: 756,
    lines: ["This is the core hot-path guarantee: readers see a compact immutable list, writers prepare the next list somewhere else."],
    className: "caption",
    anchor: "middle",
    lineHeight: 16,
  }));

  return svgDocument({
    width: 1480,
    height: 800,
    title: "Dispatch runtime snapshot publication",
    desc: "Diagram showing hot-path readers using an active snapshot while the control path prepares and atomically publishes an alternate snapshot.",
    body: body.join("\n"),
  });
}

export async function generateDispatchSnapshotSvg() {
  return writeSvg("ebpf_dispatch_snapshots.svg", renderDispatchSnapshotSvg());
}

if (isDirectRun(import.meta.url)) {
  await generateDispatchSnapshotSvg();
}