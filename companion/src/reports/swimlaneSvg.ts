import type { SwimlaneData } from "../analysis/swimlane.js";

// Self-contained SVG rendering of the timeline swimlane for the HTML report export.
// Pure and dependency-free — no JavaScript in the output, safe to embed in the report
// (mirrors assetGraphSvg.ts). The interactive canvas version lives in the dashboard; this
// is the static, report-grade counterpart so a printed/exported report carries the timeline.

const SVG_W = 900;
const LABEL_W = 150;        // left lane-label column
const LANE_H = 22;          // px per lane row
const AXIS_H = 22;          // px for the time axis strip
const TOP_PAD = 26;         // room for the column header + legend
const RIGHT_PAD = 12;
const PLOT_X = LABEL_W;
const PLOT_W = SVG_W - LABEL_W - RIGHT_PAD;
const DOT_R = 4;
const MAX_LANES = 40;
const LABEL_TRUNC = 22;

// Darker than the dashboard's dark-bg palette so the dots read on the light report page.
const SEV_COLOR: Record<string, string> = {
  Critical: "#d64545", High: "#e0852b", Medium: "#c9a000", Low: "#3f9c54", Info: "#3d6cc0",
};

const LANE_LABEL_COLOR: Record<string, string> = {
  host: "#2d6cdf", account: "#7b2fc8", severity: "#44506a", tactic: "#44506a", unassigned: "#8d9aac",
};

function esc(s: string): string {
  return s.replace(/&/g, "&amp;").replace(/</g, "&lt;").replace(/>/g, "&gt;").replace(/"/g, "&quot;");
}

function trunc(s: string, n = LABEL_TRUNC): string {
  return s.length > n ? s.slice(0, n - 1) + "…" : s;
}

// Format a tick label: date when the window spans days, else HH:MM (UTC).
function tickLabel(ms: number, spanMs: number): string {
  const d = new Date(ms);
  if (spanMs >= 2 * 86400000) return d.toISOString().slice(0, 10);
  if (spanMs >= 3600000) return d.toISOString().slice(11, 16) + "Z";
  return d.toISOString().slice(11, 19) + "Z";
}

// Returns an inline SVG string for the swimlane, or "" when there are no dated events.
// Lanes (assets/severity/tactic) stack on the Y-axis; time runs along X; dots are
// severity-colored. Capped at MAX_LANES lanes with a truncation note when exceeded.
export function renderSwimlaneSvg(data: SwimlaneData): string {
  const allLanes = data.lanes.filter((l) => l.events.length > 0);
  if (allLanes.length === 0) return "";

  const lanes = allLanes.slice(0, MAX_LANES);

  const minMs = data.minTime ? Date.parse(data.minTime) : 0;
  let maxMs = data.maxTime ? Date.parse(data.maxTime) : minMs;
  if (!Number.isFinite(minMs) || !Number.isFinite(maxMs)) return "";
  if (maxMs <= minMs) maxMs = minMs + 60000; // avoid divide-by-zero for a single instant
  const span = maxMs - minMs;

  const plotH = lanes.length * LANE_H;
  const axisY = TOP_PAD + plotH;
  const truncated = allLanes.length > MAX_LANES;
  const svgH = axisY + AXIS_H + (truncated ? 14 : 0);

  const xFor = (ms: number): number => PLOT_X + ((ms - minMs) / span) * PLOT_W;

  const parts: string[] = [];
  const hf = `font-family="-apple-system,Segoe UI,Roboto,Arial,sans-serif"`;

  // Header
  parts.push(
    `<text x="0" y="14" font-size="12" font-weight="600" fill="#44506a" ${hf}>` +
      `Timeline — ${data.totalEvents} dated event${data.totalEvents === 1 ? "" : "s"}</text>`,
  );

  // Lane stripes + labels
  lanes.forEach((lane, i) => {
    const y = TOP_PAD + i * LANE_H;
    const stripe = i % 2 === 0 ? "#f7f8fa" : "#eef1f5";
    const labelColor = LANE_LABEL_COLOR[lane.type] ?? "#44506a";
    parts.push(
      `<rect x="0" y="${y}" width="${SVG_W}" height="${LANE_H}" fill="${stripe}"/>`,
      `<text x="6" y="${y + LANE_H / 2 + 4}" font-size="11" fill="${labelColor}" ${hf}>${esc(trunc(lane.label))}</text>`,
    );
  });

  // Plot border + label-column divider
  parts.push(
    `<line x1="${PLOT_X}" y1="${TOP_PAD}" x2="${PLOT_X}" y2="${axisY}" stroke="#d4d9e0" stroke-width="1"/>`,
    `<line x1="0" y1="${axisY}" x2="${SVG_W}" y2="${axisY}" stroke="#c4ccd6" stroke-width="1"/>`,
  );

  // Time-axis ticks (≈6 evenly spaced)
  const TICKS = 6;
  for (let t = 0; t <= TICKS; t++) {
    const ms = minMs + (span * t) / TICKS;
    const x = xFor(ms);
    parts.push(
      `<line x1="${x.toFixed(1)}" y1="${TOP_PAD}" x2="${x.toFixed(1)}" y2="${axisY}" stroke="#edf0f4" stroke-width="1"/>`,
      `<text x="${x.toFixed(1)}" y="${axisY + 14}" text-anchor="middle" font-size="9" fill="#8d9aac" ${hf}>${esc(tickLabel(ms, span))}</text>`,
    );
  }

  // Event dots
  lanes.forEach((lane, i) => {
    const cy = TOP_PAD + i * LANE_H + LANE_H / 2;
    for (const e of lane.events) {
      const ms = Date.parse(e.timestamp);
      if (Number.isNaN(ms)) continue;
      const cx = xFor(ms);
      const r = e.count && e.count > 5 ? DOT_R + 1.5 : DOT_R;
      const color = SEV_COLOR[e.severity] ?? "#3d6cc0";
      parts.push(
        `<circle cx="${cx.toFixed(1)}" cy="${cy}" r="${r}" fill="${color}" fill-opacity="0.85" stroke="#ffffff" stroke-width="0.75"/>`,
      );
    }
  });

  if (truncated) {
    parts.push(
      `<text x="${SVG_W / 2}" y="${svgH - 2}" text-anchor="middle" font-size="10" fill="#8d9aac" ${hf}>` +
        `Showing ${lanes.length}/${allLanes.length} lanes — full detail in dashboard</text>`,
    );
  }

  return `<svg xmlns="http://www.w3.org/2000/svg" width="${SVG_W}" height="${svgH}" viewBox="0 0 ${SVG_W} ${svgH}">\n${parts.join("\n")}\n</svg>`;
}
