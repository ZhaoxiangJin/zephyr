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
} from "./svg_common.mjs";

export function renderProgramLifecycleSvg() {
  const body = [];

  const statePanel = { x: 52, y: 170, width: 920, height: 590 };
  const notePanel = { x: 1004, y: 170, width: 282, height: 590 };

  const detached = { x: 116, y: 258, width: 224, height: 116 };
  const attached = { x: 604, y: 258, width: 224, height: 116 };
  const verified = { x: 726, y: 500, width: 224, height: 116 };
  const enabled = { x: 246, y: 500, width: 224, height: 116 };

  body.push(headline({
    x: 56,
    y: 80,
    title: "Program session lifecycle",
    subtitle: "One eBPF program owns one current attachment session. The diagram shows the real runtime rollback rules: disable returns to VERIFIED, while detach ends the session entirely.",
    width: 920,
  }));

  body.push(panel({
    ...statePanel,
    title: "State machine",
    subtitle: "Attach selects one concrete target. Enable runs verification and only publishes after the current session is still valid.",
    tone: "blue",
  }));

  body.push(panel({
    ...notePanel,
    title: "Session facts",
    subtitle: "These details matter when reasoning about reloads, stats, and bundle teardown.",
    tone: "slate",
  }));

  body.push(card({
    ...detached,
    title: ["DETACHED"],
    body: ["no current target", "safe idle baseline"],
    tone: "slate",
    badge: "state",
  }));

  body.push(card({
    ...attached,
    title: ["ATTACHED"],
    body: ["target selected", "not yet verified for this session"],
    tone: "blue",
    badge: "state",
  }));

  body.push(card({
    ...verified,
    title: ["VERIFIED"],
    body: ["verification passed", "not yet published on the hot path"],
    tone: "sand",
    badge: "state",
  }));

  body.push(card({
    ...enabled,
    title: ["ENABLED"],
    body: ["published in target snapshot", "can execute on native events"],
    tone: "green",
    badge: "state",
  }));

  body.push(note({
    x: 1028,
    y: 258,
    width: 232,
    title: "Attach starts a new session",
    lines: [
      "session_seq increments when a target is attached.",
	      "A new attachment session starts at that point.",
    ],
    tone: "blue",
  }));

  body.push(note({
    x: 1028,
    y: 414,
    width: 232,
    title: "Enable is guarded",
    lines: [
      "Verification runs without holding the program lock.",
      "Publication succeeds only if the same session is still current.",
    ],
    tone: "sand",
  }));

  body.push(note({
    x: 1028,
    y: 586,
    width: 232,
    title: "Disable vs detach",
    lines: [
      "disable removes the program from dispatch and returns to VERIFIED.",
      "detach clears the target and returns to DETACHED.",
    ],
    tone: "green",
  }));

  body.push(edge({
    points: [
      [right(detached), centerY(detached)],
      [attached.x, centerY(attached)],
    ],
  }));

  body.push(edge({
    points: [
      [centerX(attached), centerY(attached) + 58],
      [centerX(attached), 442],
      [centerX(verified), 442],
      [centerX(verified), verified.y],
    ],
  }));

  body.push(edge({
    points: [
      [verified.x, centerY(verified)],
      [560, centerY(verified)],
      [560, centerY(enabled)],
      [right(enabled), centerY(enabled)],
    ],
  }));

  body.push(edge({
    points: [
      [centerX(enabled), enabled.y],
      [centerX(enabled), 432],
      [262, 432],
      [262, 394],
      [226, 394],
      [226, bottom(detached)],
    ],
    dashed: true,
  }));

  body.push(edge({
    points: [
      [centerX(enabled), enabled.y],
      [centerX(enabled), 458],
      [centerX(verified), 458],
      [centerX(verified), verified.y],
    ],
  }));

  body.push(edge({
    points: [
      [attached.x, centerY(attached) + 28],
      [480, centerY(attached) + 28],
      [480, 640],
      [detached.x + 40, 640],
      [detached.x + 40, bottom(detached)],
    ],
    dashed: true,
  }));

  body.push(edge({
    points: [
      [verified.x + 40, bottom(verified)],
      [verified.x + 40, 660],
      [228, 660],
      [228, bottom(detached)],
    ],
  }));

  body.push(labelBubble({ x: 472, y: 316, text: "attach(target)", tone: "blue", minWidth: 126 }));
  body.push(labelBubble({ x: 752, y: 450, text: "enable() runs verifier", tone: "sand", minWidth: 172 }));
  body.push(labelBubble({ x: 622, y: 558, text: "publish immutable snapshot", tone: "green", minWidth: 188 }));
  body.push(labelBubble({ x: 600, y: 448, text: "disable", tone: "green", minWidth: 92 }));
  body.push(labelBubble({ x: 302, y: 646, text: "detach / unload", tone: "slate", minWidth: 136 }));
  body.push(labelBubble({ x: 480, y: 480, text: "detach before enable", tone: "slate", minWidth: 150 }));
  body.push(textBlock({
    x: 512,
    y: 738,
    lines: ["The important architectural idea is session-scoping: verification and publication both belong to the current attachment, not to the program forever."],
    className: "caption",
    anchor: "middle",
    lineHeight: 16,
  }));

  return svgDocument({
    width: 1340,
    height: 810,
    title: "Program session lifecycle",
    desc: "Diagram of the eBPF program session states Detached, Attached, Verified, and Enabled, including disable and detach rollback behavior.",
    body: body.join("\n"),
  });
}

export async function generateProgramLifecycleSvg() {
  return writeSvg("ebpf_program_lifecycle.svg", renderProgramLifecycleSvg());
}

if (isDirectRun(import.meta.url)) {
  await generateProgramLifecycleSvg();
}