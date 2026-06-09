import type { AssetGraph } from "../analysis/assetGraph.js";

// Self-contained SVG rendering of the asset ↔ IoC bipartite graph.
// Pure and dependency-free — no JavaScript in the output, safe to embed in
// the HTML report export.

const SVG_W = 700;
const NODE_W = 230;
const NODE_H = 28;
const ROW_H = 36;        // NODE_H + 8 gap
const TOP_PAD = 30;      // room for column headers
const BOT_PAD = 10;
const LEFT_X = 8;
const RIGHT_X = SVG_W - 8 - NODE_W;  // 462
const BADGE_W = 18;
const LABEL_X = BADGE_W + 6;          // 24 — label left offset within the node
const TRUNC = 26;
const MAX_ITEMS = 30;

function esc(s: string): string {
  return s.replace(/&/g, "&amp;").replace(/</g, "&lt;").replace(/>/g, "&gt;").replace(/"/g, "&quot;");
}

function trunc(s: string): string {
  return s.length > TRUNC ? s.slice(0, TRUNC - 1) + "…" : s;
}

const IOC_BADGE: Record<string, string> = {
  ip: "IP", domain: "DO", hash: "##", file: "FI", process: "PR", url: "UR", other: "OT",
};

// Returns an inline SVG string for the asset ↔ IoC graph, or "" when there are no assets.
// Assets on the left, IoCs on the right, cubic-Bezier curves for edges.
// Capped at MAX_ITEMS nodes per column with a truncation note when exceeded.
export function renderAssetGraphSvg(graph: AssetGraph): string {
  const { assets, iocs, edges } = graph;
  if (assets.length === 0) return "";

  const dispAssets = assets.slice(0, MAX_ITEMS);
  const dispAssetIds = new Set(dispAssets.map((a) => a.id));
  const connIocs = iocs.filter((i) => i.assetIds.some((aid) => dispAssetIds.has(aid)));
  const dispIocs = connIocs.slice(0, MAX_ITEMS);
  const dispIocIds = new Set(dispIocs.map((i) => i.id));
  const dispEdges = edges.filter((e) => dispAssetIds.has(e.asset) && dispIocIds.has(e.ioc));

  const rows = Math.max(dispAssets.length, dispIocs.length);
  const svgH = TOP_PAD + rows * ROW_H + BOT_PAD;

  const assetY = new Map(dispAssets.map((a, i) => [a.id, TOP_PAD + i * ROW_H] as const));
  const iocY = new Map(dispIocs.map((c, i) => [c.id, TOP_PAD + i * ROW_H] as const));

  const parts: string[] = [];

  // Column headers
  const hf = `font-size="12" font-weight="600" fill="#44506a" font-family="-apple-system,Segoe UI,Roboto,Arial,sans-serif"`;
  parts.push(
    `<text x="${LEFT_X + NODE_W / 2}" y="20" text-anchor="middle" ${hf}>Assets (${assets.length})</text>`,
    `<text x="${RIGHT_X + NODE_W / 2}" y="20" text-anchor="middle" ${hf}>IoCs (${iocs.length})</text>`,
  );

  // Edges — cubic Bezier, rendered before nodes so they don't occlude labels
  const ex1 = LEFT_X + NODE_W;
  const ex2 = RIGHT_X;
  const cpx = Math.round((ex1 + ex2) / 2);
  for (const e of dispEdges) {
    const ay = assetY.get(e.asset);
    const iy = iocY.get(e.ioc);
    if (ay === undefined || iy === undefined) continue;
    const y1 = ay + NODE_H / 2;
    const y2 = iy + NODE_H / 2;
    parts.push(
      `<path d="M${ex1},${y1} C${cpx},${y1} ${cpx},${y2} ${ex2},${y2}" fill="none" stroke="#b0b8c8" stroke-width="1" opacity="0.7"/>`,
    );
  }

  // Asset nodes
  const mf = `font-size="11" fill="#1b1f24" font-family="Consolas,'SFMono-Regular',monospace"`;
  for (const a of dispAssets) {
    const y = assetY.get(a.id)!;
    const ty = y + NODE_H / 2 + 4;

    const fill = a.compromised ? "#fde8e8" : a.type === "account" ? "#f3e8fe" : "#e8f0fe";
    const stroke = a.compromised ? "#c0392b" : a.type === "account" ? "#7b2fc8" : "#2d6cdf";
    const badge = a.type === "account" ? "A" : "H";

    parts.push(
      `<rect x="${LEFT_X}" y="${y}" width="${NODE_W}" height="${NODE_H}" rx="4" fill="${fill}" stroke="${stroke}" stroke-width="1.5"/>`,
      `<rect x="${LEFT_X + 2}" y="${y + 2}" width="${BADGE_W}" height="${NODE_H - 4}" rx="2" fill="${stroke}"/>`,
      `<text x="${LEFT_X + 2 + BADGE_W / 2}" y="${ty}" text-anchor="middle" font-size="9" font-weight="bold" fill="white" font-family="monospace">${badge}</text>`,
      `<text x="${LEFT_X + LABEL_X}" y="${ty}" ${mf}>${esc(trunc(a.name))}</text>`,
    );
  }

  // IoC nodes
  for (const ioc of dispIocs) {
    const y = iocY.get(ioc.id)!;
    const ty = y + NODE_H / 2 + 4;

    const fill = ioc.verdict === "malicious" ? "#fef0e8" : ioc.verdict === "suspicious" ? "#fefce8" : "#f0f2f5";
    const stroke = ioc.verdict === "malicious" ? "#d0511a" : ioc.verdict === "suspicious" ? "#b8860b" : "#8d9aac";
    const badge = IOC_BADGE[ioc.type] ?? ioc.type.slice(0, 2).toUpperCase();

    parts.push(
      `<rect x="${RIGHT_X}" y="${y}" width="${NODE_W}" height="${NODE_H}" rx="4" fill="${fill}" stroke="${stroke}" stroke-width="1.5"/>`,
      `<rect x="${RIGHT_X + 2}" y="${y + 2}" width="${BADGE_W}" height="${NODE_H - 4}" rx="2" fill="${stroke}"/>`,
      `<text x="${RIGHT_X + 2 + BADGE_W / 2}" y="${ty}" text-anchor="middle" font-size="8" font-weight="bold" fill="white" font-family="monospace">${badge}</text>`,
      `<text x="${RIGHT_X + LABEL_X}" y="${ty}" ${mf}>${esc(trunc(ioc.value))}</text>`,
    );
  }

  // Truncation note when the graph was capped
  if (assets.length > MAX_ITEMS || connIocs.length > MAX_ITEMS) {
    const note = esc(
      `Showing ${dispAssets.length}/${assets.length} assets · ${dispIocs.length}/${connIocs.length} IoCs — full detail in dashboard`,
    );
    parts.push(
      `<text x="${SVG_W / 2}" y="${svgH - 2}" text-anchor="middle" font-size="10" fill="#8d9aac" font-family="-apple-system,Segoe UI,Roboto,Arial,sans-serif">${note}</text>`,
    );
  }

  return `<svg xmlns="http://www.w3.org/2000/svg" width="${SVG_W}" height="${svgH}" viewBox="0 0 ${SVG_W} ${svgH}">\n${parts.join("\n")}\n</svg>`;
}
