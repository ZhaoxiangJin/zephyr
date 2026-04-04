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

export function renderLoaderPipelineSvg() {
  const body = [];

  const sourcePanel = { x: 48, y: 160, width: 240, height: 600 };
  const transactionPanel = { x: 320, y: 160, width: 860, height: 600 };
  const handlePanel = { x: 1212, y: 160, width: 240, height: 600 };

  const image = { x: 76, y: 294, width: 184, height: 120 };
  const validate = { x: 374, y: 244, width: 212, height: 108 };
  const resolve = { x: 646, y: 244, width: 212, height: 108 };
  const maps = { x: 404, y: 452, width: 214, height: 108 };
  const relocs = { x: 662, y: 452, width: 214, height: 108 };
  const attachments = { x: 924, y: 346, width: 214, height: 108 };
  const bundle = { x: 682, y: 596, width: 214, height: 92 };
  const namedHandle = { x: 1240, y: 282, width: 184, height: 108 };
  const laterOps = { x: 1240, y: 466, width: 184, height: 120 };

  body.push(headline({
    x: 52,
    y: 76,
    title: "Loader pipeline and transaction boundary",
    subtitle: "Loading is intentionally more than parsing bytes: the loader validates, resolves, instantiates, and only then exposes one named handle to the rest of the system.",
    width: 980,
  }));

  body.push(panel({
    ...sourcePanel,
    title: "Serialized input",
    subtitle: "A compact bundle image carries bytecode, maps, relocation metadata, names, and optional authentication.",
    tone: "sand",
  }));

  body.push(panel({
    ...transactionPanel,
    title: "Load transaction",
    subtitle: "The loader keeps intermediate runtime state private until the named bundle is coherent and safe to publish.",
    tone: "blue",
  }));

  body.push(panel({
    ...handlePanel,
    title: "Visible result",
    subtitle: "Only a successful load registers a handle that later control operations can target by name.",
    tone: "slate",
  }));

  body.push(zone({ x: 618, y: 224, width: 840, height: 430, label: "registry lock window", tone: "slate" }));

  body.push(card({
    ...image,
    title: ["Bundle image v2"],
    body: ["code, maps, relocs", "name, auth, TTL"],
    tone: "sand",
    badge: "input bytes",
  }));

  body.push(card({
    ...validate,
    title: ["Validate image"],
    body: ["header, ranges", "auth block before objects"],
    tone: "blue",
    badge: "gate 1",
  }));

  body.push(card({
    ...resolve,
    title: ["Resolve names"],
    body: ["bundle name uniqueness", "stable hooks to targets"],
    tone: "blue",
    badge: "gate 2",
  }));

  body.push(card({
    ...maps,
    title: ["Create maps"],
    body: ["runtime IDs", "bundle-owned state objects"],
    tone: "blue",
    badge: "objects",
  }));

  body.push(card({
    ...relocs,
    title: ["Apply relocations"],
    body: ["patch instruction streams", "map references become runtime IDs"],
    tone: "blue",
    badge: "fixups",
  }));

  body.push(card({
    ...attachments,
    title: ["Create attachments"],
    body: ["bundle-owned programs", "attach to resolved targets"],
    tone: "blue",
    badge: "objects",
  }));

  body.push(card({
    ...bundle,
    title: ["Runtime bundle"],
    body: ["coherent set of maps + attachments"],
    tone: "blue",
    badge: "assemble",
  }));

  body.push(card({
    ...namedHandle,
    title: ["Named handle"],
    body: ["registry entry", "flags, TTL, status"],
    tone: "slate",
    badge: "published",
  }));

  body.push(card({
    ...laterOps,
    title: ["Later control"],
    body: ["enable, disable, unload", "status by name"],
    tone: "slate",
    badge: "after load",
  }));

  body.push(note({
    x: 370,
    y: 598,
    width: 280,
    title: "Failure semantics",
    lines: [
      "Any error tears down partially created maps and attachments.",
      "The named handle stays invisible until the whole bundle is coherent.",
    ],
    tone: "rose",
  }));

  body.push(note({
    x: 930,
    y: 560,
    width: 224,
    title: "Why hold the lock so long?",
    lines: [
      "Duplicate-name rejection and final registration share one lock window.",
      "That closes the race between checking and publishing the handle.",
    ],
    tone: "green",
  }));

  body.push(edge({
    points: [
      [right(image), centerY(image)],
      [340, centerY(image)],
      [340, centerY(validate)],
      [validate.x, centerY(validate)],
    ],
  }));

  body.push(edge({
    points: [
      [right(validate), centerY(validate)],
      [resolve.x, centerY(resolve)],
    ],
  }));

  body.push(edge({
    points: [
      [centerX(resolve), bottom(resolve)],
      [centerX(resolve), 392],
      [centerX(maps), 392],
      [centerX(maps), maps.y],
    ],
  }));

  body.push(edge({
    points: [
      [right(maps), centerY(maps)],
      [relocs.x, centerY(relocs)],
    ],
  }));

  body.push(edge({
    points: [
      [right(resolve), centerY(resolve)],
      [894, centerY(resolve)],
      [894, centerY(attachments)],
      [attachments.x, centerY(attachments)],
    ],
  }));

  body.push(edge({
    points: [
      [centerX(relocs), bottom(relocs)],
      [centerX(relocs), bundle.y],
    ],
  }));

  body.push(edge({
    points: [
      [centerX(attachments), bottom(attachments)],
      [centerX(attachments), 566],
      [centerX(bundle) + 20, 566],
      [centerX(bundle) + 20, bundle.y],
    ],
  }));

  body.push(edge({
    points: [
      [right(bundle), centerY(bundle)],
      [920, centerY(bundle)],
      [920, 550],
      [1170, 550],
      [1170, centerY(namedHandle)],
      [namedHandle.x, centerY(namedHandle)],
    ],
  }));

  body.push(edge({
    points: [
      [centerX(namedHandle), bottom(namedHandle)],
      [centerX(namedHandle), laterOps.y],
    ],
  }));

  body.push(edge({
    points: [
      [centerX(bundle), bottom(bundle) + 4],
      [centerX(bundle), 704],
      [500, 704],
      [500, 650],
    ],
    dashed: true,
  }));

  body.push(labelBubble({ x: 480, y: 370, text: "auth + structural checks", tone: "sand", minWidth: 166 }));
  body.push(labelBubble({ x: 752, y: 370, text: "name reservation + hook lookup", tone: "slate", minWidth: 210 }));
  body.push(labelBubble({ x: 760, y: 576, text: "map references become runtime fixups", tone: "blue", minWidth: 232 }));
  body.push(labelBubble({ x: 1332, y: 652, text: "becomes visible here", tone: "slate", minWidth: 160 }));
  body.push(labelBubble({ x: 790, y: 730, text: "rollback on error", tone: "rose", minWidth: 138 }));
  body.push(textBlock({
    x: 790,
    y: 784,
    lines: ["The important architectural boundary is publication, not parsing: partial runtime objects never escape the transaction."],
    className: "caption",
    anchor: "middle",
    lineHeight: 16,
  }));

  return svgDocument({
    width: 1500,
    height: 820,
    title: "eBPF loader pipeline",
    desc: "Diagram showing the runtime loader transaction, the registry lock window, and when a named handle becomes visible.",
    body: body.join("\n"),
  });
}

export async function generateLoaderPipelineSvg() {
  return writeSvg("ebpf_loader_pipeline.svg", renderLoaderPipelineSvg());
}

if (isDirectRun(import.meta.url)) {
  await generateLoaderPipelineSvg();
}