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

export function renderVerifierRuntimeSvg() {
  const body = [];

  const verifyPanel = { x: 48, y: 170, width: 632, height: 574 };
  const executePanel = { x: 716, y: 170, width: 720, height: 574 };

  const bytecode = { x: 96, y: 284, width: 208, height: 96 };
  const target = { x: 96, y: 446, width: 208, height: 96 };
  const verifier = { x: 368, y: 344, width: 252, height: 128 };
  const contract = { x: 620, y: 282, width: 200, height: 98 };
  const verifiedSession = { x: 832, y: 296, width: 180, height: 96 };
  const vm = { x: 1032, y: 296, width: 220, height: 112 };
  const eventCtx = { x: 748, y: 478, width: 220, height: 96 };
  const helpers = { x: 1032, y: 466, width: 176, height: 92 };
  const maps = { x: 1260, y: 466, width: 136, height: 92 };

  body.push(headline({
    x: 52,
    y: 80,
    title: "Verifier and runtime safety boundary",
    subtitle: "The verifier is not a one-off parser. It establishes the same attachment-aware contract that the VM later enforces for helper use and context writes.",
    width: 1020,
  }));

  body.push(panel({
    ...verifyPanel,
    title: "Verify-time",
    subtitle: "Structural checks happen before publication. The result only matters for the current attachment session.",
    tone: "sand",
  }));

  body.push(panel({
    ...executePanel,
    title: "Run-time",
    subtitle: "Once a session is enabled, the VM still consults the same contract so execution cannot silently widen policy.",
    tone: "blue",
  }));

  body.push(zone({ x: 598, y: 258, width: 440, height: 146, label: "shared contract hinge", tone: "green" }));

  body.push(card({
    ...bytecode,
    title: ["Program bytecode"],
    body: ["instruction stream", "helper IDs and jumps"],
    tone: "sand",
    badge: "input",
  }));

  body.push(card({
    ...target,
    title: ["Attachment target"],
    body: ["prog_type, backend, point", "context semantics"],
    tone: "sand",
    badge: "input",
  }));

  body.push(card({
    ...verifier,
    title: ["Verifier"],
    body: ["opcode, jump, stack, pointer provenance", "helper allowlist, read-only R1 context"],
    tone: "sand",
    badge: "gate",
  }));

  body.push(card({
    ...contract,
    title: ["Contract table"],
    body: ["helper allowlist", "context write policy"],
    tone: "green",
    badge: "shared policy",
  }));

  body.push(card({
    ...verifiedSession,
    title: ["Verified session"],
    body: ["current target + session_seq", "safe to publish if still current"],
    tone: "blue",
    badge: "handoff",
  }));

  body.push(card({
    ...vm,
    title: ["Interpreter VM"],
    body: ["fresh stack", "runtime contract rechecks"],
    tone: "blue",
    badge: "execution",
  }));

  body.push(card({
    ...eventCtx,
    title: ["Event context in R1"],
    body: ["backend-defined struct", "read-only or writable by contract"],
    tone: "blue",
    badge: "runtime input",
  }));

  body.push(card({
    ...helpers,
    title: ["Helpers"],
    body: ["controlled service entry"],
    tone: "blue",
    badge: "CALL",
  }));

  body.push(card({
    ...maps,
    title: ["Maps"],
    body: ["shared state"],
    tone: "blue",
    badge: "data",
  }));

  body.push(note({
    x: 100,
    y: 590,
    width: 520,
    title: "Why keep the contract table small?",
    lines: [
      "Because helper policy and context mutability are architectural commitments.",
      "Adding either is a subsystem design change, not a local verifier tweak.",
    ],
    tone: "rose",
  }));

  body.push(note({
    x: 1030,
    y: 590,
    width: 360,
    title: "Runtime backstop",
    lines: [
      "The VM rechecks helper IDs and context writes against the resolved contract.",
      "That preserves the effective policy even if verification logic is incomplete.",
    ],
    tone: "green",
  }));

  body.push(edge({
    points: [
      [right(bytecode), centerY(bytecode)],
      [verifier.x, centerY(verifier) - 26],
    ],
  }));

  body.push(edge({
    points: [
      [right(target), centerY(target)],
      [verifier.x, centerY(verifier) + 26],
    ],
  }));

  body.push(edge({
    points: [
      [right(verifier), centerY(verifier)],
      [contract.x, centerY(contract)],
    ],
  }));

  body.push(edge({
    points: [
      [right(contract), centerY(contract)],
      [verifiedSession.x, centerY(verifiedSession)],
    ],
  }));

  body.push(edge({
    points: [
      [right(verifiedSession), centerY(verifiedSession)],
      [vm.x, centerY(vm)],
    ],
  }));

  body.push(edge({
    points: [
      [right(eventCtx), centerY(eventCtx)],
      [1020, centerY(eventCtx)],
      [1020, centerY(vm)],
      [vm.x, centerY(vm)],
    ],
  }));

  body.push(edge({
    points: [
      [centerX(contract), bottom(contract)],
      [centerX(contract), 430],
      [centerX(vm), 430],
      [centerX(vm), bottom(vm)],
    ],
    dashed: true,
  }));

  body.push(edge({
    points: [
      [right(vm), centerY(vm)],
      [helpers.x, centerY(helpers)],
    ],
  }));

  body.push(edge({
    points: [
      [right(helpers), centerY(helpers)],
      [maps.x, centerY(maps)],
    ],
  }));

  body.push(labelBubble({ x: 242, y: 398, text: "static structure", tone: "sand", minWidth: 116 }));
  body.push(labelBubble({ x: 238, y: 560, text: "attachment semantics", tone: "sand", minWidth: 150 }));
  body.push(labelBubble({ x: 734, y: 448, text: "policy shared by verifier and VM", tone: "green", minWidth: 220 }));
  body.push(labelBubble({ x: 1118, y: 430, text: "runtime recheck", tone: "green", minWidth: 120 }));
  body.push(labelBubble({ x: 1236, y: 444, text: "CALL", tone: "blue", minWidth: 74 }));
  body.push(textBlock({
    x: 742,
    y: 754,
    lines: ["This is the subsystem's safety story in one sentence: verify once for the session, then keep the same policy alive at runtime."],
    className: "caption",
    anchor: "middle",
    lineHeight: 16,
  }));

  return svgDocument({
    width: 1480,
    height: 800,
    title: "Verifier and runtime safety boundary",
    desc: "Diagram showing program bytecode and attachment target flowing into the verifier and contract table, then into the VM with runtime contract enforcement.",
    body: body.join("\n"),
  });
}

export async function generateVerifierRuntimeSvg() {
  return writeSvg("ebpf_verifier_runtime.svg", renderVerifierRuntimeSvg());
}

if (isDirectRun(import.meta.url)) {
  await generateVerifierRuntimeSvg();
}