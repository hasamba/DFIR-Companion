// AI Agent Forensics (#2690): the dedicated mapper for rows the generated Velociraptor artifact emits
// (aiAgentRows.ts). Dispatched by velociraptorImport.ts BEFORE its classify(), so a hit row never
// reaches the shared YARA mapper and its path-based self-scan branch, and returns early so the shared
// tail never derives a message or fingerprint from the row.
//
// THE MATCHED TEXT NEVER BECOMES PART OF AN EVENT. A hit's snippet is, by design, an instruction an
// attacker planted for an AI to read. Event fields reach synthesis, Watson, explainEvent, Jev and the
// super-timeline, so the event carries rule + file + time only; the snippet stays in the raw evidence
// row and in the run report the panel and the exported reports read (aiAgentRunStore.ts).
//
// Grading (§5.1, §13.6) is provisional: the baseline grade the run recorded on the row (else the live
// rule set's, else Medium), then ONE lower-only demotion — Info when the file's SHA-256 is one of the
// detector's own rule copies or test fixtures. Never by path: a poisoned CLAUDE.md inside a detector
// checkout still hits. Inventory and credential rows are Info by construction, and every row is
// stamped with the AI Agent Forensics source so the tagger keeps its grade (vendorGrade.ts): those
// rows go to the super-timeline by explicit routing, never because a tagger rule happened to miss.

import type { MappedEvent, SiemIoc } from "./siemImport.js";
import { mitreFromText } from "./siemImport.js";
import { addIoc, mergeRowIocs } from "./iocSink.js";
import { withHostSuffix } from "./velociraptorTitle.js";
import { parseGrade } from "./aiAgentRuleParse.js";
import { activeAiAgentRuleSet } from "./aiAgentActiveRules.js";
import { aiAgentRuleGrade, aiAgentRuleLink, type AiAgentRuleSet } from "./aiAgentRuleSet.js";
import {
  aiAgentClientId,
  isAiAgentRow,
  parseAiAgentRow,
  type AiAgentHitRow,
  type AiAgentRow,
} from "./aiAgentRows.js";
import type { AiAgentHostLedger } from "./aiAgentHostLabels.js";
// Re-exported so the Velociraptor importer takes everything AI Agent Forensics from one import.
export {
  learnWholeFile,
  AiAgentHostLedger,
  type AiAgentHostsCtx,
  type AiAgentHostOptions,
} from "./aiAgentHostLabels.js";
import { AI_AGENT_FORENSICS_SOURCE } from "./vendorGrade.js";
import type { Severity } from "./stateTypes.js";

const LABEL = "AI Agent Forensics";
const SOURCES = ["Velociraptor", AI_AGENT_FORENSICS_SOURCE];
/** The time label every hit carries (§13.7): not the tampering time, its upper bound. */
export const AI_AGENT_TIME_LABEL = "latest time the content could have been planted";

type Row = Record<string, unknown>;

/**
 * Who a row is about (#2734): the aggKey part is the Velociraptor client id, so two clients sharing a
 * host name never merge; the label is the host name, with the client id added only when another
 * client in the file shares it. A row with no client id keys and labels by host name, as before.
 */
interface Endpoint {
  key: string;
  label: string;
  clientId: string;
}

function endpointOf(row: Row, host: string, ledger?: AiAgentHostLedger): Endpoint {
  const clientId = aiAgentClientId(row);
  const label = clientId && ledger ? ledger.label(host, clientId) : host;
  return { key: clientId || host, label, clientId };
}

function iso(v: unknown): string {
  if (v == null || v === "") return "";
  const n = typeof v === "number" ? v : /^\d+(\.\d+)?$/.test(String(v)) ? Number(v) : NaN;
  const d = Number.isFinite(n) ? new Date(n > 1e12 ? n : n * 1000) : new Date(String(v));
  return Number.isNaN(d.getTime()) ? "" : d.toISOString();
}

/** The later of mtime and birth time: a copy keeps its source mtime, so birth bounds it from above. */
export function hitTime(row: AiAgentHitRow): { time: string; basis: string } {
  const ev = iso(row.EventTime);
  if (row.Family === "sigma" && ev) return { time: ev, basis: "event time" };
  const m = iso(row.FileMtime);
  const b = iso(row.FileBtime);
  if (m && b && b > m) return { time: b, basis: "file created (copied: modified time is older)" };
  if (m) return { time: m, basis: "file last modified" };
  if (b) return { time: b, basis: "file created" };
  const scan = iso(row.ScanTime);
  return { time: scan || new Date(0).toISOString(), basis: scan ? "scan time (no file time)" : "unknown" };
}

function baseName(p: string): string {
  return p.split(/[\\/]/).pop() ?? p;
}

// A Sigma match keeps its native event columns (the wrapper adds the marker columns around them):
// the file or image it is about, from the columns the compiled templates and Sysmon events use.
function sigmaSubjectPath(row: AiAgentHitRow): string {
  const r = row as Record<string, unknown>;
  for (const k of ["TargetFilename", "OSPath", "Image", "Exe", "FullPath"]) {
    const v = r[k];
    if (typeof v === "string" && v.trim()) return v.trim().slice(0, 2048);
  }
  const ed = r.EventData as Record<string, unknown> | undefined;
  const fromEd = ed && (ed.TargetFilename ?? ed.Image);
  return typeof fromEd === "string" ? fromEd.slice(0, 2048) : "";
}

function lowInformationTime(set: AiAgentRuleSet, path: string): boolean {
  const name = baseName(path).toLowerCase();
  return set.lowInformationTimeFiles.some((f) => f.toLowerCase() === name);
}

/** The hit's grade: recorded baseline, then the content-hash self-scan demotion (lower only). */
export function gradeAiAgentHit(
  set: AiAgentRuleSet,
  row: AiAgentHitRow,
): { severity: Severity; selfScan: boolean } {
  const baseline = parseGrade(row.Grade) ?? aiAgentRuleGrade(set, row.Family, row.RuleName);
  const selfScan = !!row.FileSha256 && set.selfScanHashes.has(row.FileSha256);
  return { severity: selfScan ? "Info" : baseline, selfScan };
}

function mapHit(
  set: AiAgentRuleSet,
  row: AiAgentHitRow,
  ep: Endpoint,
  sink: Map<string, SiemIoc>,
): MappedEvent {
  const path = row.FilePath || (row.Family === "sigma" ? sigmaSubjectPath(row) : "");
  const { severity, selfScan } = gradeAiAgentHit(set, row);
  const { time, basis } = hitTime(row);
  const lowInfo = !!path && lowInformationTime(set, path);
  let description = `${LABEL}: ${row.RuleName}${path ? ` — ${path}` : ""} [${basis}: ${AI_AGENT_TIME_LABEL}]`;
  if (lowInfo) description += " [file rewritten every agent session — low-information time]";
  if (selfScan) description += " [detector's own rule copy or test fixture — self-scan]";
  description += " [provisional grade]";
  description = withHostSuffix(description, ep.label).slice(0, 600);
  const atlas = (row.RuleAtlas ?? "").trim();
  const detail = [
    `Rule ${row.RuleName} (${row.Family}${row.RuleFile ? `, ${row.RuleFile}` : ""})`,
    row.RuleAuthor ? `author ${row.RuleAuthor}` : "",
    row.RuleFile ? `rule link ${aiAgentRuleLink(set, row.RuleFile)}` : "",
    atlas ? `ATLAS ${atlas}` : "",
    row.Scope ? `scope ${row.Scope}` : "",
    `rule set ${row.RuleSet || set.version}`,
    ep.clientId ? `client ${ep.clientId}` : "",
    `file modified ${row.FileMtime || "unknown"}, created ${row.FileBtime || "unknown"}, scanned ${row.ScanTime || "unknown"}`,
    `event time basis: ${basis}`,
    row.Preserved ? `preserved: ${row.Preserved}` : "",
    // The file changed between hashing and the upload (#2722): said here, never a second hash IOC.
    // The hash is taken after the YARA scan, so it is not called the scan hash (Codex review).
    row.PreservedSha256 && row.FileSha256 && row.PreservedSha256 !== row.FileSha256
      ? `preserved copy hash differs from the file's hash taken after the scan (preserved SHA-256 ${row.PreservedSha256})`
      : "",
  ]
    .filter(Boolean)
    .join(" · ");
  const aggKey = `aiagent|${ep.key}|${row.Family}|${row.RuleName}|${path.toLowerCase()}`;
  const rowSink = new Map<string, SiemIoc>();
  if (!selfScan) {
    if (path) addIoc(rowSink, "file", path);
    if (row.FileSha256) addIoc(rowSink, "hash", row.FileSha256);
  }
  mergeRowIocs(sink, rowSink, aggKey);
  return {
    timestamp: time,
    description,
    severity,
    mitre: mitreFromText(row.RuleTags ?? ""),
    aggKey,
    sources: SOURCES,
    message: detail,
    ...(row.FileMtime && iso(row.FileMtime) ? { fileModified: iso(row.FileMtime) } : {}),
    ...(path ? { path } : {}),
    ...(row.FileSha256 ? { sha256: row.FileSha256 } : {}),
    ...(ep.label ? { asset: ep.label } : {}),
  };
}

function infoEvent(
  row: AiAgentRow,
  ep: Endpoint,
  description: string,
  aggKey: string,
  path = "",
): MappedEvent {
  return {
    timestamp: iso(row.ScanTime) || new Date(0).toISOString(),
    description: withHostSuffix(`${LABEL} ${description}`, ep.label).slice(0, 600),
    severity: "Info",
    mitre: [],
    aggKey: `aiagent|${ep.key}|${aggKey}`,
    sources: SOURCES,
    message: `rule set ${row.RuleSet || "unknown"}${ep.clientId ? ` · client ${ep.clientId}` : ""}`,
    ...(path ? { path } : {}),
    ...(ep.label ? { asset: ep.label } : {}),
  };
}

function mapOther(row: Exclude<AiAgentRow, AiAgentHitRow>, ep: Endpoint): MappedEvent {
  if (row.Kind === "inventory") {
    if (row.McpServer)
      return infoEvent(
        row,
        ep,
        `inventory: MCP server "${row.McpServer}" configured in ${row.Tool} (runs ${row.McpCommand || "unknown"}, ${row.McpArgCount ?? 0} argument(s) not shown)`,
        `mcp|${row.Tool}|${row.McpServer}|${row.ConfigPath ?? ""}`,
        row.ConfigPath ?? "",
      );
    return infoEvent(row, ep, `inventory: ${row.Tool} present`, `tool|${row.Tool}`);
  }
  if (row.Kind === "credential")
    return infoEvent(row, ep, `inventory: credential store present`, `cred|${row.FilePath}`, row.FilePath);
  return infoEvent(
    row,
    ep,
    `coverage: ${row.Source}${row.RuleName ? ` "${row.RuleName}"` : ""} — ${row.Status}${row.Detail ? ` (${row.Detail})` : ""}`,
    `cov|${row.Source}|${row.RuleName ? `${row.RuleName}|` : ""}${row.Status}`,
  );
}

/**
 * Map one row if it is an AI Agent Forensics row; null otherwise (the caller's classify() runs).
 * An unreadable marked row becomes one Info event that says so — never silently dropped, never
 * handed to the shared mappers.
 */
export function mapAiAgentRow(
  row: Row,
  artifact: string,
  host: string,
  sink: Map<string, SiemIoc>,
  ledger?: AiAgentHostLedger,
): { events: MappedEvent[]; detections: number } | null {
  if (!isAiAgentRow(row)) return null;
  const ep = endpointOf(row, host, ledger);
  const set = activeAiAgentRuleSet();
  const parsed = parseAiAgentRow(row);
  const stamp = (m: MappedEvent): MappedEvent => (artifact ? { ...m, artifactName: artifact } : m);
  if (!parsed.ok) {
    const bad: MappedEvent = {
      timestamp: iso(row.ScanTime) || new Date().toISOString(),
      description: withHostSuffix(`${LABEL}: unreadable result row (${parsed.error})`, ep.label).slice(
        0,
        600,
      ),
      severity: "Info",
      mitre: [],
      aggKey: `aiagent|${ep.key}|unreadable`,
      sources: SOURCES,
      ...(ep.label ? { asset: ep.label } : {}),
    };
    return { events: [stamp(bad)], detections: 0 };
  }
  const r = parsed.row;
  if (r.Kind === "hit") return { events: [stamp(mapHit(set, r, ep, sink))], detections: 1 };
  return { events: [stamp(mapOther(r, ep))], detections: 0 };
}
