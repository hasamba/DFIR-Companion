// Pure renderers: Companion investigation data → Notion block objects. No I/O — every
// function is deterministic and unit-tested. The orchestrator (notionPush.ts) wires these to
// the live NotionClient. This is the Notion analog of irisMap.ts / reports/markdown.ts: the
// SAME sections in report order, emitted as native Notion blocks rather than markdown.
//
// Everything here is written INSIDE the single managed container the Companion owns on the
// target page, so the investigators' own notes/screenshots (which live outside it) are never
// represented here and never touched on re-export.

import type {
  InvestigationState, IOC, IocEnrichment, ForensicEvent, Severity, Finding, Technique,
  InvestigationQuestion, NextStep, Thread,
} from "../../analysis/stateTypes.js";
import type { ReportMeta } from "../../reports/reportMeta.js";
import { executiveSummaryMarkdown } from "../iris/irisMap.js";
import { attackTechniqueUrl } from "../../analysis/attack.js";

// A Notion block object. Kept loose (index signature) like the IRIS request bodies — the
// builders below construct the exact shapes Notion expects; consumers read `type`/`table`.
export interface NotionBlock {
  object: "block";
  type: string;
  [key: string]: unknown;
}

export interface NotionRichText {
  type: "text";
  text: { content: string; link?: { url: string } | null };
}

// Notion named colors used for severity. The `_background` variants tint the whole callout.
export type NotionColor =
  | "default" | "gray" | "brown" | "orange" | "yellow" | "green" | "blue" | "purple" | "pink" | "red"
  | "gray_background" | "red_background" | "orange_background" | "yellow_background" | "blue_background";

const SEV_COLOR: Record<Severity, NotionColor> = {
  Critical: "red", High: "orange", Medium: "yellow", Low: "blue", Info: "gray",
};
const SEV_BG: Record<Severity, NotionColor> = {
  Critical: "red_background", High: "orange_background", Medium: "yellow_background", Low: "blue_background", Info: "gray_background",
};
const SEV_EMOJI: Record<Severity, string> = {
  Critical: "🔴", High: "🟠", Medium: "🟡", Low: "🔵", Info: "⚪",
};

// Default title of the managed container the Companion owns on the page.
export const DEFAULT_CONTAINER_TITLE = "🔍 DFIR Companion — Auto-generated";
const MAX_TIMELINE_ROWS = 500;
// Notion caps a single append at 100 top-level blocks and a table can't be unboundedly large,
// so we split big tables into chunks of this many data rows (+ a repeated header row).
const MAX_TABLE_ROWS = 90;

// ---- low-level block builders ----------------------------------------------

// Notion limits one rich-text object to 2000 chars, so split long text into runs.
export function richText(text: string): NotionRichText[] {
  const s = text ?? "";
  if (s.length === 0) return [{ type: "text", text: { content: "" } }];
  const runs: NotionRichText[] = [];
  for (let i = 0; i < s.length; i += 2000) runs.push({ type: "text", text: { content: s.slice(i, i + 2000) } });
  return runs;
}

function block(type: string, body: Record<string, unknown>): NotionBlock {
  return { object: "block", type, [type]: body };
}

export function heading2(text: string): NotionBlock { return block("heading_2", { rich_text: richText(text) }); }
export function heading3(text: string): NotionBlock { return block("heading_3", { rich_text: richText(text) }); }
export function paragraph(text: string): NotionBlock { return block("paragraph", { rich_text: richText(text) }); }
export function bulleted(text: string): NotionBlock { return block("bulleted_list_item", { rich_text: richText(text) }); }
export function bulletedRich(rich: NotionRichText[]): NotionBlock { return block("bulleted_list_item", { rich_text: rich }); }
export function divider(): NotionBlock { return block("divider", {}); }

export function callout(text: string, emoji: string, color: NotionColor = "default"): NotionBlock {
  return block("callout", { rich_text: richText(text), icon: { type: "emoji", emoji }, color });
}

export function toggle(title: string, color: NotionColor = "gray_background"): NotionBlock {
  return block("toggle", { rich_text: richText(title), color });
}

function tableRow(cells: string[]): NotionBlock {
  return { object: "block", type: "table_row", table_row: { cells: cells.map((c) => richText(c)) } };
}

// One or more table blocks (split when there are more rows than a single append allows). Each
// table repeats the header row and carries its data rows as nested children.
export function tables(headers: string[], rows: string[][]): NotionBlock[] {
  if (rows.length === 0) return [];
  const out: NotionBlock[] = [];
  for (let i = 0; i < rows.length; i += MAX_TABLE_ROWS) {
    const slice = rows.slice(i, i + MAX_TABLE_ROWS);
    out.push({
      object: "block",
      type: "table",
      table: {
        table_width: headers.length,
        has_column_header: true,
        has_row_header: false,
        children: [tableRow(headers), ...slice.map(tableRow)],
      },
    });
  }
  return out;
}

// Split prose into one paragraph block per blank-line-separated chunk (keeps long narratives
// readable). Each paragraph's rich_text still chunks at 2000 chars.
function paragraphs(text: string): NotionBlock[] {
  return (text || "")
    .split(/\n{2,}/)
    .map((p) => p.trim())
    .filter(Boolean)
    .map(paragraph);
}

function firstLine(s: string, max = 200): string {
  const line = (s.split(/\r?\n/)[0] ?? s).trim();
  return line.length <= max ? line : line.slice(0, max).trimEnd() + "…";
}

const VERDICT_ORDER = ["malicious", "suspicious", "harmless", "unknown"];
function worstVerdict(enrichments: readonly IocEnrichment[]): string | undefined {
  let best: string | undefined;
  for (const e of enrichments) {
    if (best === undefined || VERDICT_ORDER.indexOf(e.verdict) < VERDICT_ORDER.indexOf(best)) best = e.verdict;
  }
  return best;
}

// ---- sections --------------------------------------------------------------

export interface BuildBlocksOptions {
  caseId: string;
  exportedAt: string;            // ISO time stamped by the orchestrator (keeps this pure/testable)
  maxTimelineRows?: number;
}

export function managedBanner(opts: BuildBlocksOptions): NotionBlock[] {
  return [
    callout(
      "Auto-generated by DFIR Companion. Everything inside this block is overwritten on every export — write your own notes and paste screenshots OUTSIDE this block and they will never be touched.",
      "🔍",
      "gray_background",
    ),
    paragraph(`Case: ${opts.caseId}  ·  Exported: ${opts.exportedAt}`),
  ];
}

function summaryBlocks(state: InvestigationState, meta: ReportMeta): NotionBlock[] {
  const summary = executiveSummaryMarkdown(state, meta);
  if (!summary || !summary.trim()) return [];
  return [heading2("Executive Summary"), ...paragraphs(summary)];
}

function findingBlocks(f: Finding): NotionBlock[] {
  const out: NotionBlock[] = [
    callout(`[${f.severity}] ${f.title}`, SEV_EMOJI[f.severity], SEV_BG[f.severity]),
  ];
  out.push(...paragraphs(f.description));
  if (typeof f.confidence === "number") out.push(bulleted(`Confidence: ${f.confidence}%`));
  if (f.mitreTechniques.length) out.push(bulleted(`MITRE: ${f.mitreTechniques.join(", ")}`));
  if (f.relatedIocs.length) out.push(bulleted(`Related IOCs: ${f.relatedIocs.join(", ")}`));
  if (f.sourceScreenshots.length) out.push(bulleted(`Evidence: ${f.sourceScreenshots.join(", ")}`));
  out.push(bulleted(`Status: ${f.status}`));
  return out;
}

function findingsBlocks(findings: readonly Finding[]): NotionBlock[] {
  if (!findings.length) return [];
  return [heading2("Findings"), ...findings.flatMap(findingBlocks)];
}

function timelineBlocks(events: readonly ForensicEvent[], maxRows: number): NotionBlock[] {
  if (!events.length) return [];
  const shown = events.slice(0, maxRows);
  const rows = shown.map((e) => [
    e.timestamp || "",
    e.severity,
    firstLine(e.description),
    e.asset || "",
    (e.sources ?? []).join(", "),
  ]);
  const out: NotionBlock[] = [heading2("Incident Timeline"), ...tables(["Time", "Severity", "Event", "Asset", "Sources"], rows)];
  if (events.length > shown.length) out.push(paragraph(`+${events.length - shown.length} more events — see the full report.`));
  return out;
}

function iocSourceLabel(enr: readonly IocEnrichment[]): string {
  return [...new Set(enr.map((e) => e.source))].slice(0, 4).join(", ");
}

function iocsBlocks(iocs: readonly IOC[]): NotionBlock[] {
  if (!iocs.length) return [];
  const rows = iocs.map((i) => [
    i.type,
    i.value,
    i.firstSeen || "",
    worstVerdict(i.enrichments ?? []) ?? "",
    iocSourceLabel(i.enrichments ?? []),
  ]);
  return [heading2("Indicators of Compromise"), ...tables(["Type", "Value", "First seen", "Verdict", "Source"], rows)];
}

function mitreBlocks(techniques: readonly Technique[]): NotionBlock[] {
  if (!techniques.length) return [];
  const items = techniques.map((t) => {
    const url = attackTechniqueUrl(t.id);
    const suffix = `${t.name ? ` ${t.name}` : ""}${t.findingIds.length ? ` (${t.findingIds.length} finding(s))` : ""}`;
    const rich: NotionRichText[] = url
      ? [{ type: "text", text: { content: t.id, link: { url } } }, { type: "text", text: { content: suffix } }]
      : richText(`${t.id}${suffix}`);
    return bulletedRich(rich);
  });
  return [heading2("MITRE ATT&CK"), ...items];
}

function attackerPathBlocks(state: InvestigationState): NotionBlock[] {
  if (!state.attackerPath || !state.attackerPath.trim()) return [];
  return [heading2("Attack Path"), ...paragraphs(state.attackerPath)];
}

function questionsBlocks(qs: readonly InvestigationQuestion[]): NotionBlock[] {
  if (!qs.length) return [];
  const out: NotionBlock[] = [heading2("Key Investigative Questions")];
  for (const q of qs) {
    out.push(heading3(q.question));
    out.push(bulleted(`Status: ${q.status}`));
    out.push(bulleted(`Answer: ${q.answer || "—"}`));
    out.push(bulleted(`Pointer: ${q.pointer || "—"}`));
  }
  return out;
}

function nextStepsBlocks(steps: readonly NextStep[]): NotionBlock[] {
  if (!steps.length) return [];
  const items = steps.map((s) =>
    bulleted(`[${s.priority}] ${s.action}${s.rationale ? ` — ${s.rationale}` : ""}${s.pointer ? ` (Where: ${s.pointer})` : ""}`),
  );
  return [heading2("Recommended Next Steps"), ...items];
}

function threadsBlocks(threads: readonly Thread[]): NotionBlock[] {
  if (!threads.length) return [];
  const items = threads.map((t) =>
    bulleted(`[${t.status}] ${t.description} (opened ${t.openedAt}${t.closedAt ? `, closed ${t.closedAt}` : ""})`),
  );
  return [heading2("Open Threads"), ...items];
}

function metaTextSection(title: string, text: string): NotionBlock[] {
  if (!text || !text.trim()) return [];
  return [heading2(title), ...paragraphs(text)];
}

function recommendationsBlocks(meta: ReportMeta): NotionBlock[] {
  if (!meta.recommendations.length) return [];
  return [heading2("Recommendations"), ...meta.recommendations.map((r) => bulleted(r))];
}

function glossaryBlocks(meta: ReportMeta): NotionBlock[] {
  if (!meta.glossary.length) return [];
  return [heading2("Glossary"), ...meta.glossary.map((g) => bulleted(`${g.term} — ${g.explanation}`))];
}

// Assemble the full managed-container content: the banner, then every non-empty section in
// report order, separated by dividers. This is the single source of the Companion's content.
export function buildCompanionBlocks(state: InvestigationState, meta: ReportMeta, opts: BuildBlocksOptions): NotionBlock[] {
  const maxRows = opts.maxTimelineRows ?? MAX_TIMELINE_ROWS;
  const sections: NotionBlock[][] = [
    summaryBlocks(state, meta),
    findingsBlocks(state.findings),
    timelineBlocks(state.forensicTimeline, maxRows),
    iocsBlocks(state.iocs),
    mitreBlocks(state.mitreTechniques),
    attackerPathBlocks(state),
    questionsBlocks(state.keyQuestions),
    nextStepsBlocks(state.nextSteps),
    threadsBlocks(state.openThreads),
    metaTextSection("Business Impact Analysis", meta.businessImpact),
    metaTextSection("Investigation Limitations", meta.investigationLimitations),
    metaTextSection("Investigation Goals & Targets", meta.investigationGoals),
    metaTextSection("Conclusions", meta.conclusions),
    recommendationsBlocks(meta),
    glossaryBlocks(meta),
  ];
  const out: NotionBlock[] = [...managedBanner(opts)];
  for (const sec of sections) {
    if (sec.length) { out.push(divider()); out.push(...sec); }
  }
  return out;
}

// Pack blocks into append batches of ≤100 top-level "weight". A table block carries its rows
// as nested children, so it weighs 1 + rowCount; everything else weighs 1. No single block
// exceeds the budget because tables() already caps rows at MAX_TABLE_ROWS.
export function batchBlocks(blocks: readonly NotionBlock[], budget = 100): NotionBlock[][] {
  const batches: NotionBlock[][] = [];
  let cur: NotionBlock[] = [];
  let curWeight = 0;
  for (const b of blocks) {
    const weight = blockWeight(b);
    if (cur.length && curWeight + weight > budget) { batches.push(cur); cur = []; curWeight = 0; }
    cur.push(b);
    curWeight += weight;
  }
  if (cur.length) batches.push(cur);
  return batches;
}

function blockWeight(b: NotionBlock): number {
  if (b.type !== "table") return 1;
  const t = b.table as { children?: unknown[] } | undefined;
  return 1 + (t?.children?.length ?? 0);
}
