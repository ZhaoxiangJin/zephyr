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

export function renderArchitectureOverviewSvg() {
  const body = [];

  const inputsPanel = { x: 44, y: 126, width: 322, height: 280 };
  const sourcesPanel = { x: 44, y: 438, width: 322, height: 338 };
  const runtimePanel = { x: 406, y: 126, width: 854, height: 650 };
  const controlPanel = { x: 1298, y: 126, width: 268, height: 290 };
  const outcomesPanel = { x: 1298, y: 448, width: 268, height: 328 };

  const restrictedC = { x: 78, y: 214, width: 254, height: 86 };
  const buildBundle = { x: 78, y: 312, width: 254, height: 86 };
  const tracing = { x: 78, y: 526, width: 254, height: 102 };
  const pm = { x: 78, y: 648, width: 254, height: 102 };

  const stableHooks = { x: 446, y: 226, width: 202, height: 92 };
  const loader = { x: 686, y: 214, width: 220, height: 116 };
  const bundle = { x: 946, y: 214, width: 274, height: 116 };
  const prog = { x: 446, y: 404, width: 222, height: 124 };
  const dispatch = { x: 714, y: 404, width: 244, height: 124 };
  const verifier = { x: 446, y: 590, width: 222, height: 110 };
  const vm = { x: 714, y: 590, width: 188, height: 110 };
  const helpersMaps = { x: 946, y: 556, width: 274, height: 144 };

  const loaderApi = { x: 1324, y: 214, width: 216, height: 86 };
  const mcumgr = { x: 1324, y: 318, width: 216, height: 86 };
  const appLogic = { x: 1324, y: 536, width: 216, height: 90 };
  const diagnostics = { x: 1324, y: 646, width: 216, height: 90 };

  body.push(headline({
    x: 48,
    y: 72,
    title: "Zephyr eBPF architecture overview",
    subtitle: "A single runtime-loaded bundle model: authoring and control stay outside the hot path, while backends converge on the same verifier, dispatch, VM, helpers, and maps.",
    width: 980,
  }));

  body.push(panel({
    ...inputsPanel,
    title: "Bundle authoring",
    subtitle: "Host tooling produces one signed or unsigned bundle image from restricted C or eBPF ELF input.",
    tone: "sand",
  }));

  body.push(panel({
    ...sourcesPanel,
    title: "Native event sources",
    subtitle: "Tracing and PM backends remain distinct at capture time, then translate into the common target-plus-context model.",
    tone: "green",
  }));

  body.push(panel({
    ...runtimePanel,
    title: "Common runtime core",
    subtitle: "One runtime resolves stable hooks, owns named bundles, verifies sessions, publishes enabled programs, and executes them with controlled services.",
    tone: "blue",
  }));

  body.push(panel({
    ...controlPanel,
    title: "Control surfaces",
    subtitle: "Local and remote operators both talk to the same loader and bundle registry.",
    tone: "slate",
  }));

  body.push(panel({
    ...outcomesPanel,
    title: "Consumers",
    subtitle: "Normal Zephyr code and operations tooling consume exported counters, buffers, and lifecycle state.",
    tone: "rose",
  }));

  body.push(card({
    ...restrictedC,
    title: ["Restricted C", "or eBPF ELF"],
    body: ["authoring input", "portable probe logic"],
    tone: "sand",
    badge: "host input",
  }));

  body.push(card({
    ...buildBundle,
    title: ["west ebpf build"],
    body: ["bundle image v2", "relocs + auth block"],
    tone: "sand",
    badge: "build step",
  }));

  body.push(card({
    ...tracing,
    title: ["Tracing backend"],
    body: ["thread switch, ISR, idle", "native callback bridge"],
    tone: "green",
    badge: "event adapter",
  }));

  body.push(card({
    ...pm,
    title: ["PM backend"],
    body: ["state entry and exit", "notifier callback bridge"],
    tone: "green",
    badge: "event adapter",
  }));

  body.push(card({
    ...stableHooks,
    title: ["Stable hooks"],
    body: ["public hook IDs + names", "target metadata and ctx size"],
    tone: "blue",
    badge: "public surface",
  }));

  body.push(card({
    ...loader,
    title: ["Loader registry"],
    body: ["validate image", "authenticate, name registry, TTL"],
    tone: "blue",
    badge: "control plane",
  }));

  body.push(card({
    ...bundle,
    title: ["Bundle runtime"],
    body: ["own maps + attachments", "destroy coherently on unload"],
    tone: "blue",
    badge: "owned objects",
  }));

  body.push(card({
    ...prog,
    title: ["Program lifecycle"],
    body: ["attach, verify, enable", "session sequence + stats"],
    tone: "blue",
    badge: "session state",
  }));

  body.push(card({
    ...dispatch,
    title: ["Dispatch runtime"],
    body: ["immutable snapshots", "fan-out by concrete target"],
    tone: "blue",
    badge: "hot path hub",
  }));

  body.push(card({
    ...verifier,
    title: ["Verifier + contracts"],
    body: ["attachment-aware safety gate", "helper and context policy"],
    tone: "blue",
    badge: "safety gate",
  }));

  body.push(card({
    ...vm,
    title: ["Interpreter VM"],
    body: ["fresh stack", "per-event execution"],
    tone: "blue",
    badge: "execution",
  }));

  body.push(card({
    ...helpersMaps,
    title: ["Helpers + maps"],
    body: ["controlled services", "shared counters, state, and ring buffers"],
    tone: "blue",
    badge: "data plane",
  }));

  body.push(card({
    ...loaderApi,
    title: ["Loader API"],
    body: ["load, enable, disable", "unload, inspect by name"],
    tone: "slate",
    badge: "local",
  }));

  body.push(card({
    ...mcumgr,
    title: ["MCUmgr eBPF"],
    body: ["upload, verify, operate", "remote named-bundle control"],
    tone: "slate",
    badge: "remote",
  }));

  body.push(card({
    ...appLogic,
    title: ["Application logic"],
    body: ["reads maps", "reacts to exported state"],
    tone: "rose",
    badge: "normal code",
  }));

  body.push(card({
    ...diagnostics,
    title: ["Field diagnostics"],
    body: ["observability, tracing", "power and latency insight"],
    tone: "rose",
    badge: "operations",
  }));

  body.push(note({
    x: 964,
    y: 360,
    width: 252,
    title: "Hot path stays narrow",
    lines: [
      "Backends deliver one target and one typed context.",
      "Only enabled sessions reach the VM on the event path.",
    ],
    tone: "green",
  }));

  body.push(edge({
    points: [
      [centerX(restrictedC), bottom(restrictedC)],
      [centerX(restrictedC), buildBundle.y],
    ],
  }));

  body.push(edge({
    points: [
      [right(buildBundle), centerY(buildBundle)],
      [384, centerY(buildBundle)],
      [384, centerY(loader)],
      [loader.x, centerY(loader)],
    ],
  }));

  body.push(edge({
    points: [
      [right(loaderApi), centerY(loaderApi)],
      [1564, centerY(loaderApi)],
      [1564, 174],
      [796, 174],
      [796, loader.y],
    ],
  }));

  body.push(edge({
    points: [
      [loaderApi.x, centerY(loaderApi)],
      [1268, centerY(loaderApi)],
      [1268, 200],
      [840, 200],
      [840, loader.y],
    ],
    dashed: true,
  }));

  body.push(edge({
    points: [
      [mcumgr.x, centerY(mcumgr)],
      [1268, centerY(mcumgr)],
      [1268, 206],
      [870, 206],
      [870, loader.y],
    ],
    dashed: true,
  }));

  body.push(edge({
    points: [
      [loader.x, centerY(loader)],
      [right(stableHooks), centerY(stableHooks)],
    ],
  }));

  body.push(edge({
    points: [
      [right(loader), centerY(loader) + 28],
      [bundle.x, centerY(bundle)],
    ],
  }));

  body.push(edge({
    points: [
      [centerX(stableHooks), bottom(stableHooks)],
      [centerX(stableHooks), prog.y],
    ],
    dashed: true,
  }));

  body.push(edge({
    points: [
      [centerX(bundle), bottom(bundle)],
      [centerX(bundle), 368],
      [centerX(prog), 368],
      [centerX(prog), prog.y],
    ],
  }));

  body.push(edge({
    points: [
      [centerX(prog), bottom(prog)],
      [centerX(prog), verifier.y],
    ],
  }));

  body.push(edge({
    points: [
      [right(verifier), centerY(verifier)],
      [690, centerY(verifier)],
      [690, centerY(prog)],
      [prog.x + prog.width, centerY(prog)],
    ],
  }));

  body.push(edge({
    points: [
      [right(prog), centerY(prog)],
      [dispatch.x, centerY(dispatch)],
    ],
  }));

  body.push(edge({
    points: [
      [right(tracing), centerY(tracing)],
      [388, centerY(tracing)],
      [388, 454],
      [dispatch.x, 454],
    ],
  }));

  body.push(edge({
    points: [
      [right(pm), centerY(pm)],
      [388, centerY(pm)],
      [388, 510],
      [dispatch.x, 510],
    ],
  }));

  body.push(edge({
    points: [
      [centerX(dispatch), bottom(dispatch)],
      [centerX(dispatch), vm.y],
    ],
  }));

  body.push(edge({
    points: [
      [right(vm), centerY(vm)],
      [helpersMaps.x, centerY(helpersMaps)],
    ],
  }));

  body.push(edge({
    points: [
      [right(helpersMaps), centerY(helpersMaps)],
      [1270, centerY(helpersMaps)],
      [1270, centerY(diagnostics)],
      [diagnostics.x, centerY(diagnostics)],
    ],
  }));

  body.push(edge({
    points: [
      [right(helpersMaps), centerY(helpersMaps) - 28],
      [1270, centerY(helpersMaps) - 28],
      [1270, centerY(appLogic)],
      [appLogic.x, centerY(appLogic)],
    ],
    dashed: true,
  }));

  body.push(labelBubble({ x: 550, y: 356, text: "resolve stable names", tone: "blue", minWidth: 150 }));
  body.push(labelBubble({ x: 1080, y: 348, text: "instantiate bundle-owned objects", tone: "blue", minWidth: 198 }));
  body.push(labelBubble({ x: 592, y: 560, text: "verify then publish session", tone: "blue", minWidth: 176 }));
  body.push(labelBubble({ x: 680, y: 392, text: "target + context", tone: "green", minWidth: 120 }));
  body.push(labelBubble({ x: 830, y: 716, text: "CALL helpers and map ops", tone: "blue", minWidth: 182 }));
  body.push(labelBubble({ x: 1212, y: 568, text: "shared state", tone: "rose", minWidth: 108 }));
  body.push(textBlock({
    x: 970,
    y: 752,
    lines: ["Control operations stay off-path; runtime execution converges through one shared dispatch and VM core."],
    className: "caption",
    anchor: "middle",
    lineHeight: 16,
  }));

  return svgDocument({
    width: 1610,
    height: 820,
    title: "Zephyr eBPF architecture overview",
    desc: "Slide-friendly architecture diagram showing bundle authoring, control surfaces, common runtime core, native event sources, and downstream consumers.",
    body: body.join("\n"),
  });
}

export async function generateArchitectureOverviewSvg() {
  return writeSvg("ebpf_architecture_overview.svg", renderArchitectureOverviewSvg());
}

if (isDirectRun(import.meta.url)) {
  await generateArchitectureOverviewSvg();
}