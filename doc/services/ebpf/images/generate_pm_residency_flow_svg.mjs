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

export function renderPmResidencyFlowSvg() {
  const body = [];

  const buildPanel = { x: 44, y: 148, width: 330, height: 322 };
  const backendPanel = { x: 406, y: 148, width: 540, height: 322 };
  const mapsPanel = { x: 406, y: 500, width: 540, height: 312 };
  const reportPanel = { x: 978, y: 148, width: 518, height: 720 };

  const probePair = { x: 82, y: 244, width: 254, height: 96 };
  const runtimeLoad = { x: 82, y: 364, width: 254, height: 92 };

  const stateEntry = { x: 442, y: 236, width: 156, height: 96 };
  const pmEntry = { x: 642, y: 224, width: 244, height: 112 };
  const stateExit = { x: 442, y: 370, width: 156, height: 96 };
  const pmExit = { x: 642, y: 358, width: 244, height: 112 };

  const entryTs = { x: 442, y: 620, width: 148, height: 102 };
  const entryCount = { x: 602, y: 620, width: 156, height: 102 };
  const residency = { x: 770, y: 620, width: 148, height: 102 };

  const phases = { x: 1014, y: 236, width: 444, height: 116 };
  const lookup = { x: 1014, y: 434, width: 214, height: 102 };
  const report = { x: 1260, y: 434, width: 198, height: 116 };
  const reportNote = { x: 1014, y: 570, width: 444 };
  const teardown = { x: 1136, y: 742, width: 200, height: 92 };

  body.push(headline({
    x: 52,
    y: 82,
    title: "PM residency profiler: entry, exit, and reporting flow",
    subtitle: "The runtime-loaded PM bundle carries two programs: pm_entry timestamps each state entry and counts it, while pm_exit accumulates elapsed residency for the state being exited.",
    width: 1120,
  }));

  body.push(panel({
    ...buildPanel,
    title: "Bundle preparation",
    subtitle: "One restricted-C probe pair becomes one embedded runtime bundle that the sample loads and enables at startup.",
    tone: "sand",
  }));

  body.push(panel({
    ...backendPanel,
    title: "PM backend event handling",
    subtitle: "The PM backend translates entry and exit callbacks into ebpf_ctx_pm sessions. Each eBPF program updates a different piece of shared measurement state.",
    tone: "blue",
  }));

  body.push(panel({
    ...mapsPanel,
    title: "Runtime-owned measurement maps",
    subtitle: "The probe keeps one timestamp map for internal bookkeeping and exposes per-state counts and accumulated residency through normal map reads.",
    tone: "green",
  }));

  body.push(panel({
    ...reportPanel,
    title: "Application reporting loop",
    subtitle: "The sample changes its worker sleep window over time, then reads entry_count_map and residency_map and prints per-state totals for each interval.",
    tone: "rose",
  }));

  body.push(card({
    ...probePair,
    title: ["pm_entry + pm_exit"],
    body: ["restricted-C PM probe pair", "west ebpf build -> pm_residency.bundle"],
    tone: "sand",
    badge: "host-built bundle",
  }));

  body.push(card({
    ...runtimeLoad,
    title: ["ebpf_loader_load + enable"],
    body: ["pm_residency_probe", "runtime-loaded PM probe enabled"],
    tone: "sand",
    badge: "startup",
  }));

  body.push(card({
    ...stateEntry,
    title: ["pm/state_entry"],
    body: ["PM notifier callback", "one concrete state"],
    tone: "blue",
    badge: "entry event",
  }));

  body.push(card({
    ...pmEntry,
    title: ["pm_entry()"],
    body: ["record entry_ts_map[state] = now", "increment entry_count_map[state]"],
    tone: "blue",
    badge: "entry program",
  }));

  body.push(card({
    ...stateExit,
    title: ["pm/state_exit"],
    body: ["PM notifier callback", "same state key on exit"],
    tone: "blue",
    badge: "exit event",
  }));

  body.push(card({
    ...pmExit,
    title: ["pm_exit()"],
    body: ["load entry_ts_map[state]", "add elapsed ns into residency_map[state]"],
    tone: "blue",
    badge: "exit program",
  }));

  body.push(card({
    ...entryTs,
    title: ["entry_ts_map"],
    body: ["internal start timestamp", "per PM state"],
    tone: "green",
    badge: "runtime map",
  }));

  body.push(card({
    ...entryCount,
    title: ["entry_count_map"],
    body: ["entry count per state"],
    tone: "green",
    badge: "runtime map",
  }));

  body.push(card({
    ...residency,
    title: ["residency_map"],
    body: ["accumulated ns per state"],
    tone: "green",
    badge: "runtime map",
  }));

  body.push(card({
    ...phases,
    title: ["phase loop"],
    body: ["10 ms -> 50 ms -> 200 ms -> 1000 ms", "longer idle windows let PM policy choose deeper states"],
    tone: "rose",
    badge: "stimulus",
  }));

  body.push(card({
    ...lookup,
    title: ["map lookups"],
    body: ["read entry_count_map", "read residency_map"],
    tone: "rose",
    badge: "normal code",
  }));

  body.push(card({
    ...report,
    title: ["phase report"],
    body: ["entries, residency ms", "interval percentage per state"],
    tone: "rose",
    badge: "console output",
  }));

  body.push(note({
    x: reportNote.x,
    y: reportNote.y,
    width: reportNote.width,
    title: "What the sample proves",
    lines: [
      "The probe's own timestamp map stays internal, while normal application code reads the exported count and residency maps.",
      "As the worker sleep interval grows, the printed report shows whether deeper PM states are actually reached.",
    ],
    tone: "slate",
  }));

  body.push(card({
    ...teardown,
    title: ["disable + unload"],
    body: ["remove PM session", "destroy runtime-owned state coherently"],
    tone: "rose",
    badge: "teardown",
  }));

  body.push(edge({
    points: [
      [centerX(probePair), bottom(probePair)],
      [centerX(probePair), runtimeLoad.y],
    ],
  }));

  body.push(edge({
    points: [
      [right(runtimeLoad), centerY(runtimeLoad)],
      [390, centerY(runtimeLoad)],
      [390, 214],
      [centerX(pmEntry), 214],
      [centerX(pmEntry), pmEntry.y],
    ],
    dashed: true,
  }));

  body.push(edge({
    points: [
      [right(runtimeLoad), centerY(runtimeLoad)],
      [390, centerY(runtimeLoad)],
      [390, 480],
      [centerX(pmExit), 480],
      [centerX(pmExit), bottom(pmExit)],
    ],
    dashed: true,
  }));

  body.push(edge({
    points: [
      [right(stateEntry), centerY(stateEntry)],
      [pmEntry.x, centerY(pmEntry)],
    ],
  }));

  body.push(edge({
    points: [
      [right(stateExit), centerY(stateExit)],
      [pmExit.x, centerY(pmExit)],
    ],
  }));

  body.push(edge({
    points: [
      [centerX(pmEntry), bottom(pmEntry)],
      [centerX(pmEntry), bottom(pmEntry) + 6],
      [615, bottom(pmEntry) + 6],
      [615, 540],
      [centerX(entryTs) - 16, 540],
      [centerX(entryTs) - 16, entryTs.y],
    ],
  }));

  body.push(edge({
    points: [
      [centerX(pmEntry) + 28, bottom(pmEntry)],
      [centerX(pmEntry) + 28, bottom(pmEntry) + 12],
      [625, bottom(pmEntry) + 12],
      [625, 570],
      [centerX(entryCount), 570],
      [centerX(entryCount), entryCount.y],
    ],
  }));

  body.push(edge({
    points: [
      [centerX(pmExit), bottom(pmExit)],
      [centerX(pmExit), bottom(pmExit) + 10],
      [615, bottom(pmExit) + 10],
      [615, 555],
      [centerX(entryTs) + 16, 555],
      [centerX(entryTs) + 16, entryTs.y],
    ],
    dashed: true,
  }));

  body.push(edge({
    points: [
      [centerX(pmExit) + 46, bottom(pmExit)],
      [centerX(pmExit) + 46, 585],
      [centerX(residency), 585],
      [centerX(residency), residency.y],
    ],
  }));

  body.push(edge({
    points: [
      [phases.x, centerY(phases)],
      [960, centerY(phases)],
      [960, 130],
      [centerX(stateEntry), 130],
      [centerX(stateEntry), stateEntry.y],
    ],
    dashed: true,
  }));

  body.push(edge({
    points: [
      [right(entryCount), centerY(entryCount)],
      [760, centerY(entryCount)],
      [760, 600],
      [960, 600],
      [960, centerY(lookup)],
      [lookup.x, centerY(lookup)],
    ],
  }));

  body.push(edge({
    points: [
      [right(residency), centerY(residency)],
      [960, centerY(residency)],
      [960, 420],
      [centerX(report), 420],
      [centerX(report), report.y],
    ],
  }));

  body.push(edge({
    points: [
      [right(lookup), centerY(lookup)],
      [report.x, centerY(report)],
    ],
  }));

  body.push(edge({
    points: [
      [right(teardown), centerY(teardown)],
      [1510, centerY(teardown)],
      [1510, 130],
      [centerX(runtimeLoad), 130],
      [centerX(runtimeLoad), runtimeLoad.y],
    ],
    dashed: true,
  }));

  body.push(labelBubble({ x: 392, y: 484, text: "embed runtime bundle", tone: "sand", minWidth: 158 }));
  body.push(labelBubble({ x: 1120, y: 378, text: "phase changes idle window", tone: "rose", minWidth: 176 }));
  body.push(labelBubble({ x: 1340, y: 398, text: "entries and residency per phase", tone: "rose", minWidth: 208 }));
  body.push(textBlock({
    x: 770,
    y: 880,
    lines: ["This diagram is the PM sample's key narrative: one runtime bundle listens on PM entry and exit, records per-state timing, and lets normal code report what the platform PM policy really did."],
    className: "caption",
    anchor: "middle",
    lineHeight: 16,
  }));

  return svgDocument({
    width: 1540,
    height: 920,
    title: "PM residency profiler flow",
    desc: "Scenario diagram for the PM residency sample, showing the two PM programs, the three runtime-owned maps, the changing idle windows, and the normal application-side reporting path.",
    body: body.join("\n"),
  });
}

export async function generatePmResidencyFlowSvg() {
  return writeSvg("ebpf_pm_residency_flow.svg", renderPmResidencyFlowSvg());
}

if (isDirectRun(import.meta.url)) {
  await generatePmResidencyFlowSvg();
}