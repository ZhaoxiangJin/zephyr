import fs from "node:fs/promises";
import path from "node:path";
import { fileURLToPath, pathToFileURL } from "node:url";

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

function round(value) {
  return Number(value.toFixed(1));
}

export function escapeXml(text) {
  return String(text)
    .replaceAll("&", "&amp;")
    .replaceAll("<", "&lt;")
    .replaceAll(">", "&gt;")
    .replaceAll('"', "&quot;");
}

export function estimateWidth(text, unit = 7.2) {
  return String(text).length * unit;
}

export function wrapLine(text, maxWidth, unit = 7.2) {
  if (estimateWidth(text, unit) <= maxWidth) {
    return [text];
  }

  const words = String(text).split(/\s+/);
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

export function wrapLines(lines, maxWidth, unit = 7.2) {
  return lines.flatMap((line) => wrapLine(line, maxWidth, unit));
}

export function textBlock({
  x,
  y,
  lines,
  className = "body",
  anchor = "middle",
  lineHeight = 18,
}) {
  const items = lines
    .map((line, index) => {
      const dy = index === 0 ? 0 : lineHeight;

      return `<tspan x="${x}" dy="${dy}">${escapeXml(line)}</tspan>`;
    })
    .join("");

  return `<text class="${className}" x="${x}" y="${y}" text-anchor="${anchor}">${items}</text>`;
}

export function headline({ x, y, title, subtitle, width = 540 }) {
  const subtitleLines = wrapLines([subtitle], width, 7.4);

  return [
    `<text class="headline" x="${x}" y="${y}">${escapeXml(title)}</text>`,
    textBlock({
      x,
      y: y + 32,
      lines: subtitleLines,
      className: "subheadline",
      anchor: "start",
      lineHeight: 18,
    }),
  ].join("\n");
}

export function centerX(box) {
  return box.x + box.width / 2;
}

export function centerY(box) {
  return box.y + box.height / 2;
}

export function right(box) {
  return box.x + box.width;
}

export function bottom(box) {
  return box.y + box.height;
}

export function pill({ x, y, text, tone = "blue", minWidth = 96, height = 28 }) {
  const width = Math.max(minWidth, estimateWidth(text, 6) + 24);

  return [
    `<rect class="pill pill-${tone}" x="${x}" y="${y}" width="${width}" height="${height}" rx="14" ry="14" />`,
    textBlock({
      x: x + width / 2,
      y: y + 19,
      lines: [text],
      className: `pill-text pill-text-${tone}`,
      lineHeight: 14,
    }),
  ].join("\n");
}

export function labelBubble({ x, y, text, tone = "slate", minWidth = 110 }) {
  const width = Math.max(minWidth, estimateWidth(text, 5.9) + 24);
  const left = x - width / 2;

  return [
    `<rect class="label-bubble label-bubble-${tone}" x="${left}" y="${y - 14}" width="${width}" height="28" rx="14" ry="14" />`,
    textBlock({
      x,
      y: y + 5,
      lines: [text],
      className: "label-bubble-text",
      lineHeight: 14,
    }),
  ].join("\n");
}

export function panel({ x, y, width, height, title, subtitle, tone = "blue" }) {
  const subtitleLines = wrapLines([subtitle], width - 40, 7.2);

  return [
    `<rect class="panel panel-${tone}" x="${x}" y="${y}" width="${width}" height="${height}" rx="28" ry="28" />`,
    `<line class="panel-divider" x1="${x}" y1="${y + 64}" x2="${x + width}" y2="${y + 64}" />`,
    textBlock({
      x: x + 22,
      y: y + 38,
      lines: [title],
      className: "panel-title",
      anchor: "start",
      lineHeight: 18,
    }),
    textBlock({
      x: x + 22,
      y: y + 88,
      lines: subtitleLines,
      className: "panel-subtitle",
      anchor: "start",
      lineHeight: 17,
    }),
  ].join("\n");
}

export function card({
  x,
  y,
  width,
  height,
  title,
  body = [],
  tone = "blue",
  badge,
  align = "center",
}) {
  const titleLines = wrapLines(Array.isArray(title) ? title : [title], width - 32, 8.6);
  const bodyLines = wrapLines(Array.isArray(body) ? body : [body], width - 36, 7.1);
  const badgeWidth = badge ? Math.max(86, estimateWidth(badge, 5.9) + 20) : 0;
  const anchor = align === "start" ? "start" : "middle";
  const textX = align === "start" ? x + 18 : x + width / 2;
  const titleY = y + (badge ? 58 : 40);
  const bodyY = titleY + (titleLines.length * 19) + 10;

  return [
    `<rect class="card card-${tone}" x="${x}" y="${y}" width="${width}" height="${height}" rx="20" ry="20" />`,
    badge
      ? `<rect class="badge badge-${tone}" x="${x + 16}" y="${y + 14}" width="${badgeWidth}" height="24" rx="12" ry="12" />`
      : "",
    badge
      ? textBlock({
          x: x + 16 + badgeWidth / 2,
          y: y + 30,
          lines: [badge],
          className: `badge-text badge-text-${tone}`,
          lineHeight: 14,
        })
      : "",
    textBlock({
      x: textX,
      y: titleY,
      lines: titleLines,
      className: "card-title",
      anchor,
      lineHeight: 19,
    }),
    textBlock({
      x: textX,
      y: bodyY,
      lines: bodyLines,
      className: "card-body",
      anchor,
      lineHeight: 16,
    }),
  ].join("\n");
}

export function note({ x, y, width, title, lines, tone = "slate" }) {
  const bodyLines = wrapLines(lines, width - 34, 7);
  const height = 80 + bodyLines.length * 16;

  return [
    `<rect class="note note-${tone}" x="${x}" y="${y}" width="${width}" height="${height}" rx="20" ry="20" />`,
    textBlock({
      x: x + 18,
      y: y + 30,
      lines: [title],
      className: "note-title",
      anchor: "start",
      lineHeight: 16,
    }),
    textBlock({
      x: x + 18,
      y: y + 58,
      lines: bodyLines,
      className: "note-body",
      anchor: "start",
      lineHeight: 16,
    }),
  ].join("\n");
}

export function zone({ x, y, width, height, label, tone = "blue" }) {
  return [
    `<rect class="zone zone-${tone}" x="${x}" y="${y}" width="${width}" height="${height}" rx="24" ry="24" />`,
    pill({ x: x + 18, y: y - 16, text: label, tone, minWidth: 138 }),
  ].join("\n");
}

function distance(a, b) {
  return Math.hypot(b.x - a.x, b.y - a.y);
}

function pointTowards(from, to, amount) {
  const total = distance(from, to);

  if (total === 0) {
    return { x: from.x, y: from.y };
  }

  const ratio = amount / total;

  return {
    x: round(from.x + (to.x - from.x) * ratio),
    y: round(from.y + (to.y - from.y) * ratio),
  };
}

export function roundedPath(points, radius = 18) {
  if (points.length === 0) {
    return "";
  }

  if (points.length === 1) {
    const [x, y] = points[0];

    return `M ${x} ${y}`;
  }

  let d = `M ${points[0][0]} ${points[0][1]}`;

  for (let index = 1; index < points.length - 1; index += 1) {
    const prev = { x: points[index - 1][0], y: points[index - 1][1] };
    const current = { x: points[index][0], y: points[index][1] };
    const next = { x: points[index + 1][0], y: points[index + 1][1] };
    const bend = Math.min(radius, distance(prev, current) / 2, distance(current, next) / 2);
    const start = pointTowards(current, prev, bend);
    const end = pointTowards(current, next, bend);

    d += ` L ${start.x} ${start.y} Q ${current.x} ${current.y} ${end.x} ${end.y}`;
  }

  const last = points[points.length - 1];
  d += ` L ${last[0]} ${last[1]}`;

  return d;
}

export function edge({ points, dashed = false, markerEnd = "url(#arrow)", radius = 18 }) {
  return `<path class="edge${dashed ? " edge-dashed" : ""}" d="${roundedPath(points, radius)}" fill="none" marker-end="${markerEnd}" />`;
}

function classifySvgLine(line) {
  if (line.includes('class="edge')) {
    return 20;
  }

  if (
    line.includes('class="card ') ||
    line.includes('class="badge ') ||
    line.includes('class="note ')
  ) {
    return 30;
  }

  if (line.includes('class="label-bubble ') && !line.includes('label-bubble-text')) {
    return 50;
  }

  if (line.includes('class="label-bubble-text')) {
    return 60;
  }

  if (
    line.includes('class="panel ') ||
    line.includes('class="panel-divider') ||
    line.includes('class="zone ') ||
    line.includes('class="pill ')
  ) {
    return 10;
  }

  return 40;
}

function orderSvgBody(body) {
  return body
    .split("\n")
    .filter((line) => line.trim().length > 0)
    .map((line, index) => ({ line, index, layer: classifySvgLine(line) }))
    .sort((left, right) => left.layer - right.layer || left.index - right.index)
    .map(({ line }) => line)
    .join("\n");
}

export function svgDocument({ width, height, title, desc, body, extraStyles = "", extraDefs = "" }) {
  const orderedBody = orderSvgBody(body);

  return `<?xml version="1.0" encoding="UTF-8"?>
<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 ${width} ${height}" role="img" aria-labelledby="title desc">
  <title id="title">${escapeXml(title)}</title>
  <desc id="desc">${escapeXml(desc)}</desc>
  <defs>
    <marker id="arrow" viewBox="0 0 10 10" refX="9" refY="5" markerWidth="10" markerHeight="10" orient="auto-start-reverse">
      <path d="M 0 0 L 10 5 L 0 10 z" fill="#29455f" />
    </marker>
    <filter id="shadow" x="-20%" y="-20%" width="140%" height="140%">
      <feDropShadow dx="0" dy="7" stdDeviation="10" flood-color="#3a4e64" flood-opacity="0.08" />
    </filter>
    <style>
      .bg { fill: #fcfdff; }
      .frame { fill: none; stroke: #d7dee8; stroke-width: 1.5; }
      .headline { fill: #17324a; font: 700 30px "Segoe UI", Arial, sans-serif; letter-spacing: 0.2px; }
      .subheadline { fill: #5b7287; font: 15px "Segoe UI", Arial, sans-serif; }
      .panel { stroke-width: 1.4; filter: url(#shadow); }
      .panel-blue { fill: #f4f8ff; stroke: #c7d5ea; }
      .panel-sand { fill: #fff9f0; stroke: #ddc79a; }
      .panel-green { fill: #f4fbf4; stroke: #c6dcc3; }
      .panel-rose { fill: #fff6f4; stroke: #e3c2bb; }
      .panel-slate { fill: #f6f8fb; stroke: #ccd5df; }
      .panel-divider { stroke: #dde5ee; stroke-width: 1; }
      .panel-title { fill: #21384f; font: 600 18px "Segoe UI", Arial, sans-serif; }
      .panel-subtitle { fill: #61788c; font: 14px "Segoe UI", Arial, sans-serif; }
      .card { stroke-width: 1.5; filter: url(#shadow); }
      .card-blue { fill: #ffffff; stroke: #7d9fc3; }
      .card-sand { fill: #fffefb; stroke: #cba76f; }
      .card-green { fill: #fdfffd; stroke: #92b08e; }
      .card-rose { fill: #fffdfc; stroke: #d5988a; }
      .card-slate { fill: #fbfcfe; stroke: #98a9bc; }
      .card-title { fill: #1e3349; font: 600 19px "Segoe UI", Arial, sans-serif; }
      .card-body { fill: #5a6f84; font: 13px "Segoe UI", Arial, sans-serif; }
      .badge { stroke-width: 0; }
      .badge-blue { fill: #e6f0ff; }
      .badge-sand { fill: #f3ead8; }
      .badge-green { fill: #e4f0e2; }
      .badge-rose { fill: #f6e4e0; }
      .badge-slate { fill: #e8edf3; }
      .badge-text { font: 600 11px "Segoe UI", Arial, sans-serif; letter-spacing: 0.7px; }
      .badge-text-blue { fill: #416488; }
      .badge-text-sand { fill: #7a6130; }
      .badge-text-green { fill: #4d6b4b; }
      .badge-text-rose { fill: #8a584c; }
      .badge-text-slate { fill: #4c6077; }
      .pill { stroke-width: 0; }
      .pill-blue { fill: #dfeefe; }
      .pill-sand { fill: #efe5d2; }
      .pill-green { fill: #dfeedd; }
      .pill-rose { fill: #f5e3de; }
      .pill-slate { fill: #e8edf4; }
      .pill-text { font: 600 11px "Segoe UI", Arial, sans-serif; letter-spacing: 0.7px; }
      .pill-text-blue { fill: #3c648a; }
      .pill-text-sand { fill: #725a2c; }
      .pill-text-green { fill: #4d6b4b; }
      .pill-text-rose { fill: #875447; }
      .pill-text-slate { fill: #4e637a; }
      .label-bubble { stroke-width: 1; }
      .label-bubble-blue { fill: #ffffff; stroke: #c9d9ed; }
      .label-bubble-sand { fill: #fffefa; stroke: #dbc8a7; }
      .label-bubble-green { fill: #ffffff; stroke: #c6dcc3; }
      .label-bubble-rose { fill: #ffffff; stroke: #e4c8c1; }
      .label-bubble-slate { fill: #ffffff; stroke: #d7dee8; }
      .label-bubble-text { fill: #4e647a; font: 12px "Segoe UI", Arial, sans-serif; }
      .note { stroke-width: 1.3; filter: url(#shadow); }
      .note-blue { fill: #f8fbff; stroke: #c9d9ed; }
      .note-sand { fill: #fffdf8; stroke: #decda8; }
      .note-green { fill: #f8fcf7; stroke: #c8ddc6; }
      .note-rose { fill: #fffaf8; stroke: #e6cbc4; }
      .note-slate { fill: #fafbfd; stroke: #d7dee8; }
      .note-title { fill: #22384d; font: 600 15px "Segoe UI", Arial, sans-serif; }
      .note-body { fill: #5d7286; font: 13px "Segoe UI", Arial, sans-serif; }
      .zone { fill: none; stroke-width: 1.8; stroke-dasharray: 10 8; }
      .zone-blue { stroke: #81a6cd; }
      .zone-sand { stroke: #c5a86a; }
      .zone-green { stroke: #92b08e; }
      .zone-rose { stroke: #d59b8e; }
      .zone-slate { stroke: #9eafc1; }
      .edge { stroke: #29455f; stroke-width: 2.4; stroke-linecap: round; stroke-linejoin: round; }
      .edge-dashed { stroke-dasharray: 8 7; }
      .caption { fill: #5c7387; font: 14px "Segoe UI", Arial, sans-serif; }
      ${extraStyles}
    </style>
    ${extraDefs}
  </defs>
  <rect class="bg" x="0" y="0" width="${width}" height="${height}" rx="24" ry="24" />
  <rect class="frame" x="12" y="12" width="${width - 24}" height="${height - 24}" rx="20" ry="20" />
  ${orderedBody}
</svg>`;
}

export async function writeSvg(fileName, content) {
  await fs.writeFile(path.join(__dirname, fileName), content, "utf8");
  return fileName;
}

export function isDirectRun(metaUrl) {
  return Boolean(process.argv[1]) && metaUrl === pathToFileURL(process.argv[1]).href;
}