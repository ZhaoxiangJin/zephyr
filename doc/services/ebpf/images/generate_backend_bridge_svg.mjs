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

export function renderBackendBridgeSvg() {
  const body = [];

  const nativePanel = { x: 48, y: 172, width: 348, height: 522 };
  const bridgePanel = { x: 432, y: 172, width: 402, height: 522 };
  const commonPanel = { x: 870, y: 172, width: 562, height: 522 };

  const tracingNative = { x: 86, y: 284, width: 272, height: 112 };
  const pmNative = { x: 86, y: 468, width: 272, height: 112 };
  const tracingBridge = { x: 492, y: 278, width: 282, height: 124 };
  const pmBridge = { x: 492, y: 462, width: 282, height: 124 };
  const target = { x: 926, y: 274, width: 200, height: 98 };
  const typedCtx = { x: 1172, y: 274, width: 204, height: 98 };
  const dispatch = { x: 1042, y: 568, width: 222, height: 118 };

  body.push(headline({
    x: 52,
    y: 82,
    title: "Backend bridge model",
    subtitle: "Backends are adapters, not alternate runtimes. Each backend captures native Zephyr events once, translates them into one concrete target plus one typed context object, and then reuses the common dispatch path.",
    width: 1080,
  }));

  body.push(panel({
    ...nativePanel,
    title: "Native callback spaces",
    subtitle: "These are backend-specific capture mechanisms owned by Zephyr subsystems outside the common eBPF runtime.",
    tone: "sand",
  }));

  body.push(panel({
    ...bridgePanel,
    title: "Backend translation layer",
    subtitle: "Each backend bridges native callback arguments into the common target and context representation.",
    tone: "green",
  }));

  body.push(panel({
    ...commonPanel,
    title: "Shared runtime entry",
    subtitle: "Once translation is done, backend-specific logic ends and the common runtime owns validation, fan-out, and execution.",
    tone: "blue",
  }));

  body.push(card({
    ...tracingNative,
    title: ["Tracing callbacks"],
    body: ["thread in or out, ISR enter or exit, idle enter or exit"],
    tone: "sand",
    badge: "native",
  }));

  body.push(card({
    ...pmNative,
    title: ["PM notifier callbacks"],
    body: ["state entry and exit notifications from Zephyr power management"],
    tone: "sand",
    badge: "native",
  }));

  body.push(card({
    ...tracingBridge,
    title: ["ebpf_tracing"],
    body: ["choose concrete target", "build ebpf_ctx_thread, ebpf_ctx_isr, or ebpf_ctx_idle"],
    tone: "green",
    badge: "bridge",
  }));

  body.push(card({
    ...pmBridge,
    title: ["ebpf_pm"],
    body: ["choose PM target", "build ebpf_ctx_pm"],
    tone: "green",
    badge: "bridge",
  }));

  body.push(card({
    ...target,
    title: ["Concrete target"],
    body: ["backend + point", "runtime dispatch key"],
    tone: "blue",
    badge: "common model",
  }));

  body.push(card({
    ...typedCtx,
    title: ["Typed context"],
    body: ["one backend-defined struct", "passed to the VM in R1"],
    tone: "blue",
    badge: "common model",
  }));

  body.push(card({
    ...dispatch,
    title: ["Dispatch runtime"],
    body: ["immutable snapshot lookup", "fan-out to enabled sessions"],
    tone: "blue",
    badge: "shared hub",
  }));

  body.push(note({
    x: 936,
    y: 404,
    width: 430,
    title: "Design rule for new backends",
    lines: [
      "Translate once into target plus context, then reuse the common runtime.",
      "Do not build a backend-specific verifier, VM path, or side execution model.",
    ],
    tone: "rose",
  }));

  body.push(edge({
    points: [
      [right(tracingNative), centerY(tracingNative)],
      [tracingBridge.x, centerY(tracingBridge)],
    ],
  }));

  body.push(edge({
    points: [
      [right(pmNative), centerY(pmNative)],
      [pmBridge.x, centerY(pmBridge)],
    ],
  }));

  body.push(edge({
    points: [
      [right(tracingBridge), centerY(tracingBridge)],
      [888, centerY(tracingBridge)],
      [888, centerY(target)],
      [target.x, centerY(target)],
    ],
  }));

  body.push(edge({
    points: [
      [right(pmBridge), centerY(pmBridge)],
      [888, centerY(pmBridge)],
      [888, centerY(target) + 44],
      [target.x, centerY(target) + 44],
    ],
  }));

  body.push(edge({
    points: [
      [right(target), centerY(target)],
      [typedCtx.x, centerY(typedCtx)],
    ],
    dashed: true,
  }));

  body.push(edge({
    points: [
      [centerX(target), bottom(target)],
      [centerX(target), bottom(target) + 18],
      [912, bottom(target) + 18],
      [912, centerY(dispatch)],
      [dispatch.x, centerY(dispatch)],
    ],
  }));

  body.push(edge({
    points: [
      [centerX(typedCtx), bottom(typedCtx)],
      [centerX(typedCtx), bottom(typedCtx) + 22],
      [920, bottom(typedCtx) + 22],
      [920, centerY(dispatch) + 20],
      [dispatch.x, centerY(dispatch) + 20],
    ],
  }));

  body.push(labelBubble({ x: 426, y: 420, text: "native callback arguments", tone: "sand", minWidth: 186 }));
  body.push(labelBubble({ x: 852, y: 636, text: "bridge chooses target", tone: "green", minWidth: 164 }));
  body.push(labelBubble({ x: 1272, y: 392, text: "common runtime starts here", tone: "blue", minWidth: 194 }));
  body.push(textBlock({
    x: 740,
    y: 726,
    lines: ["This split is what keeps the system understandable: backend-specific capture on the left, shared runtime semantics on the right."],
    className: "caption",
    anchor: "middle",
    lineHeight: 16,
  }));

  return svgDocument({
    width: 1480,
    height: 760,
    title: "Backend bridge model",
    desc: "Diagram showing tracing and PM native callbacks flowing through backend bridge layers into the common target, typed context, and dispatch runtime.",
    body: body.join("\n"),
  });
}

export async function generateBackendBridgeSvg() {
  return writeSvg("ebpf_backend_bridge.svg", renderBackendBridgeSvg());
}

if (isDirectRun(import.meta.url)) {
  await generateBackendBridgeSvg();
}