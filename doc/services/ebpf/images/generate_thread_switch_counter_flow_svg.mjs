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

export function renderThreadSwitchCounterFlowSvg() {
  const body = [];

  const buildPanel = { x: 44, y: 148, width: 330, height: 322 };
  const controlPanel = { x: 406, y: 148, width: 540, height: 322 };
  const eventPanel = { x: 406, y: 500, width: 540, height: 312 };
  const consumerPanel = { x: 978, y: 148, width: 518, height: 664 };

  const source = { x: 82, y: 244, width: 254, height: 96 };
  const bundle = { x: 82, y: 364, width: 254, height: 92 };

  const load = { x: 442, y: 236, width: 210, height: 98 };
  const runtimeBundle = { x: 700, y: 236, width: 210, height: 98 };
  const findMap = { x: 442, y: 360, width: 210, height: 98 };
  const enable = { x: 700, y: 360, width: 210, height: 98 };

  const hook = { x: 442, y: 610, width: 150, height: 96 };
  const program = { x: 614, y: 580, width: 164, height: 156 };
  const counterMap = { x: 800, y: 610, width: 108, height: 96 };

  const worker = { x: 1014, y: 236, width: 204, height: 102 };
  const sampleNote = { x: 1242, y: 236, width: 216 };
  const lookup = { x: 1014, y: 432, width: 214, height: 102 };
  const consoleCard = { x: 1260, y: 456, width: 198, height: 102 };
  const teardown = { x: 1136, y: 670, width: 200, height: 102 };

  body.push(headline({
    x: 52,
    y: 82,
    title: "Thread-switch counter: end-to-end flow",
    subtitle: "One host-built runtime bundle becomes one enabled tracing session. The probe increments counter_map on kernel/thread_switched_in, and normal Zephyr code reads that map back out.",
    width: 1080,
  }));

  body.push(panel({
    ...buildPanel,
    title: "Host-built input",
    subtitle: "The sample starts from one restricted-C probe and embeds the resulting bundle bytes into the application image.",
    tone: "sand",
  }));

  body.push(panel({
    ...controlPanel,
    title: "Runtime control path",
    subtitle: "Loader operations instantiate one named bundle, keep a stable map name, and enable the attachment only after the handle is coherent.",
    tone: "blue",
  }));

  body.push(panel({
    ...eventPanel,
    title: "Tracing event path",
    subtitle: "Once enabled, scheduler callbacks enter through one stable hook name and the eBPF program updates the shared counter map on each thread switch.",
    tone: "green",
  }));

  body.push(panel({
    ...consumerPanel,
    title: "Application-side observation",
    subtitle: "The sample's own worker thread forces scheduler activity, reads counter_map once per second through named loader helpers, then disables and unloads the bundle by name.",
    tone: "rose",
  }));

  body.push(card({
    ...source,
    title: ["thread_switch_counter.c"],
    body: ["EBPF_PROGRAM_SCHED", "kernel/thread_switched_in", "counter_map array probe"],
    tone: "sand",
    badge: "restricted C",
  }));

  body.push(card({
    ...bundle,
    title: ["thread_switch_probe_bundle[]"],
    body: ["west ebpf build output", "embedded loader image bytes"],
    tone: "sand",
    badge: "bundle bytes",
  }));

  body.push(card({
    ...load,
    title: ["ebpf_loader_load"],
    body: ["parse bundle image", "instantiate runtime objects"],
    tone: "blue",
    badge: "step 1",
  }));

  body.push(card({
    ...runtimeBundle,
    title: ["thread_switch_probe"],
    body: ["named runtime bundle", "bundle + attachment lifetime owner"],
    tone: "blue",
    badge: "named handle",
  }));

  body.push(card({
    ...findMap,
    title: ["name counter_map"],
    body: ["stable map name", "used by loader lookup helpers"],
    tone: "blue",
    badge: "step 2",
  }));

  body.push(card({
    ...enable,
    title: ["ebpf_loader_enable"],
    body: ["verify current session", "publish enabled attachment"],
    tone: "blue",
    badge: "step 3",
  }));

  body.push(card({
    ...hook,
    title: ["kernel/thread_", "switched_in"],
    body: ["stable tracing hook", "scheduler switch callback"],
    tone: "green",
    badge: "event source",
  }));

  body.push(card({
    ...program,
    title: ["count_thread_", "switches()"],
    body: ["lookup key 0", "increment value by 1"],
    tone: "green",
    badge: "eBPF program",
  }));

  body.push(card({
    ...counterMap,
    title: ["counter_map"],
    body: ["array[0]", "shared counter"],
    tone: "green",
    badge: "shared map",
  }));

  body.push(card({
    ...worker,
    title: ["worker thread"],
    body: ["k_msleep(1) loop", "forces scheduler thread switches"],
    tone: "rose",
    badge: "stimulus",
  }));

  body.push(note({
    x: sampleNote.x,
    y: sampleNote.y,
    width: sampleNote.width,
    title: "Why this sample is useful",
    lines: [
      "It proves that a runtime-loaded tracing probe can update shared state without any shell or static registration path.",
      "Normal Zephyr code reads the same counter back through the public loader copy API.",
    ],
    tone: "slate",
  }));

  body.push(card({
    ...lookup,
    title: ["periodic map lookup"],
    body: ["ebpf_loader_map_lookup_copy_by_name", "read counter_map[0] once per second"],
    tone: "rose",
    badge: "normal code",
  }));

  body.push(card({
    ...consoleCard,
    title: ["console report"],
    body: ["count=%u (+delta)", "human-readable runtime signal"],
    tone: "rose",
    badge: "output",
  }));

  body.push(card({
    ...teardown,
    title: ["disable + unload"],
    body: ["ebpf_loader_disable_by_name", "ebpf_loader_unload_by_name"],
    tone: "rose",
    badge: "teardown",
  }));

  body.push(edge({
    points: [
      [centerX(source), bottom(source)],
      [centerX(source), bundle.y],
    ],
  }));

  body.push(edge({
    points: [
      [right(bundle), centerY(bundle)],
      [390, centerY(bundle)],
      [390, centerY(load)],
      [load.x, centerY(load)],
    ],
    dashed: true,
  }));

  body.push(edge({
    points: [
      [right(load), centerY(load)],
      [runtimeBundle.x, centerY(runtimeBundle)],
    ],
  }));

  body.push(edge({
    points: [
      [centerX(load), bottom(load)],
      [centerX(load), findMap.y],
    ],
  }));

  body.push(edge({
    points: [
      [centerX(runtimeBundle), bottom(runtimeBundle)],
      [centerX(runtimeBundle), enable.y],
    ],
  }));

  body.push(edge({
    points: [
      [right(findMap), centerY(findMap)],
      [enable.x, centerY(enable)],
    ],
  }));

  body.push(edge({
    points: [
      [centerX(enable), bottom(enable)],
      [centerX(enable), 548],
      [centerX(program), 548],
      [centerX(program), program.y],
    ],
    dashed: true,
  }));

  body.push(edge({
    points: [
      [worker.x, centerY(worker)],
      [960, centerY(worker)],
      [960, 490],
      [420, 490],
      [420, centerY(hook)],
      [hook.x, centerY(hook)],
    ],
    dashed: true,
  }));

  body.push(edge({
    points: [
      [right(hook), centerY(hook)],
      [program.x, centerY(program)],
    ],
  }));

  body.push(edge({
    points: [
      [right(program), centerY(program)],
      [counterMap.x, centerY(counterMap)],
    ],
  }));

  body.push(edge({
    points: [
      [right(counterMap), centerY(counterMap)],
      [960, centerY(counterMap)],
      [960, centerY(lookup)],
      [lookup.x, centerY(lookup)],
    ],
  }));

  body.push(edge({
    points: [
      [right(lookup), centerY(lookup)],
      [consoleCard.x, centerY(consoleCard)],
    ],
  }));

  body.push(edge({
    points: [
      [centerX(teardown), teardown.y],
      [centerX(teardown), teardown.y - 30],
      [1510, teardown.y - 30],
      [1510, 130],
      [centerX(runtimeBundle), 130],
      [centerX(runtimeBundle), runtimeBundle.y],
    ],
    dashed: true,
  }));

  body.push(labelBubble({ x: 392, y: 484, text: "embed bundle bytes", tone: "sand", minWidth: 148 }));
  body.push(labelBubble({ x: 676, y: 484, text: "runtime-owned map handle", tone: "blue", minWidth: 176 }));
  body.push(labelBubble({ x: 810, y: 534, text: "attachment becomes live", tone: "green", minWidth: 172 }));
  body.push(labelBubble({ x: 1110, y: 584, text: "read from normal code", tone: "rose", minWidth: 154 }));
  body.push(textBlock({
    x: 770,
    y: 836,
    lines: ["This is the story the sample demonstrates end to end: host-built bundle, runtime enable, native scheduler events, shared map update, and plain application-side readout."],
    className: "caption",
    anchor: "middle",
    lineHeight: 16,
  }));

  return svgDocument({
    width: 1540,
    height: 860,
    title: "Thread-switch counter flow",
    desc: "Scenario diagram for the thread-switch counter sample, showing build-time bundle creation, runtime load and enable, stable tracing hook delivery, map updates, and normal application-side map reads.",
    body: body.join("\n"),
  });
}

export async function generateThreadSwitchCounterFlowSvg() {
  return writeSvg("ebpf_thread_switch_counter_flow.svg", renderThreadSwitchCounterFlowSvg());
}

if (isDirectRun(import.meta.url)) {
  await generateThreadSwitchCounterFlowSvg();
}