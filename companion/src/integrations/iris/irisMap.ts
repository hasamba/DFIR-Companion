// Pure mappers: Companion investigation data → DFIR-IRIS request bodies and note markdown.
// No I/O — every function is deterministic and unit-tested. The orchestrator (irisExport.ts)
// wires these to the live IrisClient. IRIS type IDs vary per install, so callers pass a
// resolved name→id map (built at runtime from the client's iocTypeMap/assetTypeMap).

import type {
  InvestigationState, IOC, IocEnrichment, ForensicEvent, Severity, Finding, Technique,
  InvestigationQuestion, NextStep, Thread,
} from "../../analysis/stateTypes.js";
import type { GraphAsset } from "../../analysis/assetGraph.js";
import type { ReportMeta } from "../../reports/reportMeta.js";
import type { IrisAssetBody, IrisIocBody, IrisEventBody, IrisTaskBody } from "./irisClient.js";
import { tacticForTechniques } from "./mitreTactics.js";

const TAG = "dfir-companion";

// ---- dates -----------------------------------------------------------------

// IRIS timeline wants `%Y-%m-%dT%H:%M:%S.%f` (microseconds, NO trailing Z / offset; the tz is
// carried separately in event_tz). We normalize to UTC and report event_tz "+00:00".
export function irisEventDate(iso: string): string | null {
  const d = new Date(iso);
  if (Number.isNaN(d.getTime())) return null;
  return d.toISOString().slice(0, -1) + "000"; // "...123Z" → "...123000"
}

// ---- IOCs ------------------------------------------------------------------

// Candidate IRIS type names (MISP taxonomy) for a Companion IOC, most-specific first.
function iocTypeCandidates(ioc: IOC): string[] {
  switch (ioc.type) {
    case "ip": return ["ip-dst", "ip-src", "ip"];
    case "domain": return ["domain", "hostname"];
    case "url": return ["url", "uri"];
    case "hash": {
      const hex = ioc.value.replace(/[^a-f0-9]/gi, "");
      if (hex.length === 32) return ["md5"];
      if (hex.length === 40) return ["sha1"];
      if (hex.length === 64) return ["sha256"];
      if (hex.length === 128) return ["sha512"];
      return ["sha256", "sha1", "md5"];
    }
    case "file": return ["filename"];
    case "process": return ["filename", "process-state"];
    case "other": return ["other", "text", "comment"];
    default: return ["other"];
  }
}

export function resolveIocTypeId(ioc: IOC, typeMap: ReadonlyMap<string, number>): number | undefined {
  for (const name of iocTypeCandidates(ioc)) {
    const id = typeMap.get(name);
    if (id !== undefined) return id;
  }
  return undefined;
}

const VERDICT_ORDER = ["malicious", "suspicious", "harmless", "unknown"];
function worstVerdict(enrichments: readonly IocEnrichment[]): string | undefined {
  let best: string | undefined;
  for (const e of enrichments) {
    if (best === undefined || VERDICT_ORDER.indexOf(e.verdict) < VERDICT_ORDER.indexOf(best)) best = e.verdict;
  }
  return best;
}

// Build an IRIS add-ioc body, or null when no IRIS type matches (caller records it as skipped).
export function mapIoc(ioc: IOC, typeMap: ReadonlyMap<string, number>): IrisIocBody | null {
  const typeId = resolveIocTypeId(ioc, typeMap);
  if (typeId === undefined) return null;

  const enr = ioc.enrichments ?? [];
  const verdict = worstVerdict(enr);
  const intelLines = enr.map((e) => `- ${e.source}: ${e.verdict}${e.score ? ` (${e.score})` : ""}${e.link ? ` ${e.link}` : ""}`);
  const description = intelLines.length
    ? `Threat intel:\n${intelLines.join("\n")}`
    : `Observed by DFIR Companion (first seen ${ioc.firstSeen}).`;
  const enrichTags = [...new Set(enr.flatMap((e) => e.tags ?? []))].slice(0, 5);
  const tags = [TAG, ioc.type, ...(verdict ? [verdict] : []), ...enrichTags];

  return {
    ioc_value: ioc.value,
    ioc_type_id: typeId,
    ioc_tlp_id: 2,                 // amber (default)
    ioc_description: description,
    ioc_tags: [...new Set(tags)].join(","),
  };
}

// ---- assets ----------------------------------------------------------------

function assetTypeCandidates(asset: GraphAsset): string[] {
  switch (asset.type) {
    case "host": return ["windows - computer", "windows - server", "linux - computer"];
    case "account":
      return /[\\@]/.test(asset.name) ? ["windows account - ad", "account"] : ["account"];
    default: return ["account"];
  }
}

export function resolveAssetTypeId(asset: GraphAsset, typeMap: ReadonlyMap<string, number>): number | undefined {
  for (const name of assetTypeCandidates(asset)) {
    const id = typeMap.get(name);
    if (id !== undefined) return id;
  }
  return undefined;
}

const IP_RE = /^\d{1,3}(\.\d{1,3}){3}$/;

export function mapAsset(asset: GraphAsset, typeMap: ReadonlyMap<string, number>): IrisAssetBody | null {
  const typeId = resolveAssetTypeId(asset, typeMap);
  if (typeId === undefined) return null;

  const body: IrisAssetBody = {
    asset_name: asset.name,
    asset_type_id: typeId,
    analysis_status_id: 1,
    asset_description: `DFIR Companion: ${asset.compromised ? "compromised" : "observed"}; max severity ${asset.maxSeverity}; ${asset.eventCount} event(s); ${asset.iocIds.length} linked IoC(s).`,
    asset_compromise_status_id: asset.compromised ? 1 : 3,   // 1 compromised, 3 unknown
    asset_tags: [TAG, asset.maxSeverity.toLowerCase(), asset.type].join(","),
  };
  if (IP_RE.test(asset.name)) body.asset_ip = asset.name;
  else if (asset.type === "host" && asset.name.includes(".")) body.asset_domain = asset.name;
  return body;
}

// ---- timeline --------------------------------------------------------------

const SEV_COLOR: Record<Severity, string> = {
  Critical: "#ef4444", High: "#f97316", Medium: "#eab308", Low: "#3b82f6", Info: "#6b7280",
};

function firstLine(s: string): string {
  return (s.split(/\r?\n/)[0] ?? s).trim();
}

// IRIS event_title is an unbounded Text column, so we keep the full first line; we only trim
// a runaway one-line description (on a word boundary, with an ellipsis) to keep the row sane.
function eventTitle(description: string, max = 300): string {
  const line = firstLine(description);
  if (line.length <= max) return line || "(event)";
  const cut = line.slice(0, max);
  const lastSpace = cut.lastIndexOf(" ");
  return (lastSpace > max * 0.6 ? cut.slice(0, lastSpace) : cut).trimEnd() + "…";
}

// Resolve which IRIS IOC ids an event references: by structured hash/path/process fields, by
// value appearing in the description, and (extraValues) by IOCs linked through the event's
// findings — all looked up in a lowercased value→id map of already-created IOCs.
function eventIocIds(event: ForensicEvent, iocByValue: ReadonlyMap<string, number>, extraValues: readonly string[] = []): number[] {
  const ids = new Set<number>();
  const tryAdd = (v?: string) => { if (v) { const id = iocByValue.get(v.toLowerCase()); if (id !== undefined) ids.add(id); } };
  tryAdd(event.sha256);
  tryAdd(event.md5);
  tryAdd(event.path);
  if (event.path) tryAdd(event.path.split(/[\\/]/).pop());
  tryAdd(event.processName);
  for (const v of extraValues) tryAdd(v);
  const desc = event.description.toLowerCase();
  for (const [value, id] of iocByValue) if (value.length >= 5 && desc.includes(value)) ids.add(id);
  return [...ids];
}

export interface MapEventContext {
  assetByName: ReadonlyMap<string, number>;          // lowercased asset name → iris asset id
  iocByValue: ReadonlyMap<string, number>;            // lowercased ioc value → iris ioc id
  categoryByName?: ReadonlyMap<string, number>;       // lowercased IRIS event-category name → id (MITRE tactics)
  findingIocValues?: (event: ForensicEvent) => string[]; // IOC values linked to the event via its findings
}

// Build an IRIS add-event body, or null when the event has no parseable timestamp. The event
// category (MITRE tactic) is auto-assigned from the event's techniques/description.
export function mapEvent(event: ForensicEvent, ctx: MapEventContext): IrisEventBody | null {
  const date = irisEventDate(event.timestamp);
  if (!date) return null;

  const tactic = tacticForTechniques(event.mitreTechniques, event.description);
  const categoryId = (tactic && ctx.categoryByName?.get(tactic.toLowerCase())) ?? 1; // 1 = Unspecified

  const parts: string[] = [event.description];
  if (event.count && event.count > 1) parts.push(`Occurrences: ${event.count}${event.endTimestamp ? ` (until ${event.endTimestamp})` : ""}`);
  if (event.asset) parts.push(`Asset: ${event.asset}`);
  if (event.sources?.length) parts.push(`Sources: ${event.sources.join(", ")}`);
  if (event.sha256) parts.push(`SHA256: ${event.sha256}`);
  if (event.md5) parts.push(`MD5: ${event.md5}`);
  if (event.path) parts.push(`Path: ${event.path}`);
  if (event.mitreTechniques?.length) parts.push(`MITRE: ${event.mitreTechniques.join(", ")}`);

  const assetIds = event.asset ? [ctx.assetByName.get(event.asset.trim().toLowerCase())].filter((x): x is number => x !== undefined) : [];

  return {
    event_title: eventTitle(event.description),
    event_date: date,
    event_tz: "+00:00",
    event_content: parts.join("\n"),
    event_in_graph: true,
    event_in_summary: event.severity === "Critical" || event.severity === "High",
    event_category_id: String(categoryId),
    event_color: SEV_COLOR[event.severity],
    event_tags: [TAG, event.severity.toLowerCase(), ...(event.mitreTechniques ?? [])].join(","),
    event_assets: assetIds,
    event_iocs: eventIocIds(event, ctx.iocByValue, ctx.findingIocValues?.(event)),
  };
}

// ---- tasks (Recommended Next Steps → IRIS tasks) ---------------------------

// Build the title/description/tags of an IRIS task from a recommended next step. The caller
// adds task_status_id (resolved "To do") and task_assignees_id ([] = unassigned).
export function mapNextStepTask(step: NextStep): IrisTaskBody {
  const title = `[${step.priority}] ${step.action}`.trim();
  const description = [step.rationale, step.pointer ? `Where: ${step.pointer}` : ""].filter(Boolean).join("\n\n");
  return {
    task_title: title.length >= 2 ? title : `${title} (next step)`,   // IRIS requires ≥2 chars
    task_description: description,
    task_tags: [TAG, step.priority].join(","),
  };
}

// ---- summary & notes -------------------------------------------------------

// The case summary (executive summary): a human-authored override wins over the AI summary.
export function executiveSummaryMarkdown(state: InvestigationState, meta: ReportMeta): string {
  return (meta.executiveSummary || "").trim() || state.lastSummary || "_No executive summary yet._";
}

export interface IrisNote { title: string; content: string }

function findingsNote(findings: readonly Finding[]): string {
  return findings.map((f) =>
    `### [${f.severity}] ${f.title}\n\n${f.description}\n` +
    (f.mitreTechniques.length ? `\n**MITRE:** ${f.mitreTechniques.join(", ")}` : "") +
    (f.relatedIocs.length ? `\n**Related IOCs:** ${f.relatedIocs.join(", ")}` : "") +
    `\n**Status:** ${f.status}`,
  ).join("\n\n---\n\n");
}

function mitreNote(techniques: readonly Technique[]): string {
  return techniques.map((t) => `- **${t.id}** ${t.name}${t.findingIds.length ? ` (${t.findingIds.length} finding(s))` : ""}`).join("\n");
}

function questionsNote(qs: readonly InvestigationQuestion[]): string {
  return qs.map((q) => `### ${q.question}\n\n- **Status:** ${q.status}\n- **Answer:** ${q.answer || "—"}\n- **Pointer:** ${q.pointer || "—"}`).join("\n\n");
}

function threadsNote(threads: readonly Thread[]): string {
  return threads.map((t) => `- [${t.status}] ${t.description} _(opened ${t.openedAt}${t.closedAt ? `, closed ${t.closedAt}` : ""})_`).join("\n");
}

// Assemble the "everything else" notes — one per non-empty section. Order is report-friendly.
export function buildNotes(state: InvestigationState, meta: ReportMeta): IrisNote[] {
  const notes: IrisNote[] = [];
  const push = (title: string, content: string) => { if (content && content.trim()) notes.push({ title, content }); };

  if (state.attackerPath) push("Attacker Path", state.attackerPath);
  if (state.findings.length) push("Findings", findingsNote(state.findings));
  if (state.mitreTechniques.length) push("MITRE ATT&CK", mitreNote(state.mitreTechniques));
  if (state.keyQuestions.length) push("Key Investigative Questions", questionsNote(state.keyQuestions));
  // Recommended Next Steps are exported as IRIS tasks (not notes) — see exportCaseToIris.
  if (state.openThreads.length) push("Open Threads", threadsNote(state.openThreads));

  // Human-authored report-meta sections.
  push("Business Impact Analysis", meta.businessImpact);
  push("Investigation Limitations", meta.investigationLimitations);
  push("Investigation Goals & Targets", meta.investigationGoals);
  push("Conclusions", meta.conclusions);
  if (meta.recommendations.length) push("Recommendations", meta.recommendations.map((r) => `- ${r}`).join("\n"));
  if (meta.glossary.length) push("Glossary", meta.glossary.map((g) => `- **${g.term}** — ${g.explanation}`).join("\n"));

  return notes;
}
