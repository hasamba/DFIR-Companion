import { createHash } from "node:crypto";
import type { InvestigationState, IOC, IocEnrichment, Severity } from "../analysis/stateTypes.js";
import { iocToStixPattern } from "./stix.js";
import type { StixBundle, StixObject } from "./stix.js";

export type IocBlocklistFormat = "txt" | "csv" | "stix";
export type BlocklistIocType = "ip" | "domain" | "url" | "hash" | "email";

export interface IocBlocklistOptions {
  /** Minimum severity (derived from worst enrichment verdict). Default: "Medium". */
  minSeverity?: Severity;
  /** IOC types to include. Default: ip, domain, url, hash (not email). */
  types?: BlocklistIocType[];
  /** When true, only include IOCs with a malicious or suspicious verdict. Default: false. */
  verdictOnly?: boolean;
  /** Case name for TXT/CSV header comments. Falls back to caseId when absent. */
  caseName?: string;
  /** ISO timestamp for the "Generated:" header line. Defaults to current time when absent. */
  generatedAt?: string;
}

// ── Severity helpers ──────────────────────────────────────────────────────────

const SEVERITY_RANK: Record<Severity, number> = {
  Critical: 4, High: 3, Medium: 2, Low: 1, Info: 0,
};

const VERDICT_RANK: Record<IocEnrichment["verdict"], number> = {
  malicious: 3, suspicious: 2, harmless: 1, unknown: 0,
};

function worstVerdict(ioc: IOC): IocEnrichment["verdict"] | null {
  let best: IocEnrichment["verdict"] | null = null;
  for (const e of ioc.enrichments ?? []) {
    if (best === null || VERDICT_RANK[e.verdict] > VERDICT_RANK[best]) best = e.verdict;
  }
  return best;
}

// Derive a severity from the IOC's worst enrichment verdict (no enrichment → Info).
function iocSeverity(ioc: IOC): Severity {
  const v = worstVerdict(ioc);
  if (v === "malicious") return "High";
  if (v === "suspicious") return "Medium";
  if (v === "harmless") return "Low";
  return "Info";
}

// ── Type mapping ──────────────────────────────────────────────────────────────

const EMAIL_RE = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;

// Map an IOC to its block-list type. `other` IOCs are treated as `email` when the value
// matches an email pattern. Returns null for types that don't belong in a block-list
// (file paths, process names, opaque `other` values).
function effectiveType(ioc: IOC): BlocklistIocType | null {
  if (ioc.type === "ip") return "ip";
  if (ioc.type === "domain") return "domain";
  if (ioc.type === "url") return "url";
  if (ioc.type === "hash") return "hash";
  if (ioc.type === "other" && EMAIL_RE.test(ioc.value.trim())) return "email";
  return null;
}

// ── Filter ────────────────────────────────────────────────────────────────────

const DEFAULT_TYPES: BlocklistIocType[] = ["ip", "domain", "url", "hash"];
const DEFAULT_MIN_SEVERITY: Severity = "Medium";

/**
 * Apply block-list filters to an IOC list.
 * The state must already be scope/legitimate-filtered (ReportWriter.loadFilteredState does this).
 */
export function filterBlocklistIocs(
  iocs: IOC[],
  opts: IocBlocklistOptions,
): { ioc: IOC; effectiveType: BlocklistIocType }[] {
  const types = opts.types ?? DEFAULT_TYPES;
  const minSev = opts.minSeverity ?? DEFAULT_MIN_SEVERITY;
  const verdictOnly = opts.verdictOnly ?? false;

  const results: { ioc: IOC; effectiveType: BlocklistIocType }[] = [];
  for (const ioc of iocs) {
    const eff = effectiveType(ioc);
    if (!eff || !types.includes(eff)) continue;
    if (SEVERITY_RANK[iocSeverity(ioc)] < SEVERITY_RANK[minSev]) continue;
    if (verdictOnly) {
      const v = worstVerdict(ioc);
      if (v !== "malicious" && v !== "suspicious") continue;
    }
    results.push({ ioc, effectiveType: eff });
  }
  return results;
}

// ── Shared helpers ────────────────────────────────────────────────────────────

function verdictSummary(ioc: IOC): string {
  const v = worstVerdict(ioc);
  if (!v) return "";
  const hits = (ioc.enrichments ?? [])
    .filter((e) => e.verdict === v)
    .map((e) => `${e.source}${e.score ? ` (${e.score})` : ""}`)
    .join(", ");
  return hits ? `${v} — ${hits}` : v;
}

// ── Plain-text format ─────────────────────────────────────────────────────────

const TYPE_LABEL: Record<BlocklistIocType, string> = {
  ip: "IP Addresses",
  domain: "Domains",
  url: "URLs",
  hash: "Hashes",
  email: "Email Addresses",
};

/**
 * Build a plain-text IOC block-list: one value per line, grouped by type, with a header comment.
 * Pure — depends only on its arguments.
 */
export function buildIocBlocklistTxt(state: InvestigationState, opts: IocBlocklistOptions = {}): string {
  const filtered = filterBlocklistIocs(state.iocs, opts);
  const minSev = opts.minSeverity ?? DEFAULT_MIN_SEVERITY;
  const types = opts.types ?? DEFAULT_TYPES;
  const ts = opts.generatedAt ?? new Date().toISOString();

  const lines: string[] = [
    "# DFIR Companion — IOC Block List",
    `# Case: ${opts.caseName?.trim() || state.caseId}`,
    `# Generated: ${ts}`,
    `# Filters: scope applied, legitimate excluded, min severity: ${minSev}${opts.verdictOnly ? ", verdict-confirmed only" : ""}`,
    "",
  ];

  // Group by effective type, preserving the requested type order.
  const byType = new Map<BlocklistIocType, string[]>();
  for (const { ioc, effectiveType: eff } of filtered) {
    let arr = byType.get(eff);
    if (!arr) byType.set(eff, (arr = []));
    arr.push(ioc.value.trim());
  }

  for (const t of types) {
    const vals = byType.get(t);
    if (!vals || vals.length === 0) continue;
    lines.push(`# ${TYPE_LABEL[t]} (${vals.length})`);
    for (const v of vals) lines.push(v);
    lines.push("");
  }

  return lines.join("\n");
}

// ── CSV format ────────────────────────────────────────────────────────────────

function csvCell(s: string): string {
  if (/[",\r\n]/.test(s)) return `"${s.replace(/"/g, '""')}"`;
  return s;
}

/**
 * Build a minimal CSV IOC block-list: type, value, severity, verdict, description.
 * Pure — depends only on its arguments.
 */
export function buildIocBlocklistCsv(state: InvestigationState, opts: IocBlocklistOptions = {}): string {
  const filtered = filterBlocklistIocs(state.iocs, opts);
  const rows: string[] = [["type", "value", "severity", "verdict", "description"].map(csvCell).join(",")];
  for (const { ioc, effectiveType: eff } of filtered) {
    const sev = iocSeverity(ioc);
    const verdict = worstVerdict(ioc) ?? "";
    const desc = verdictSummary(ioc);
    rows.push([eff, ioc.value.trim(), sev, verdict, desc].map(csvCell).join(","));
  }
  return rows.join("\n") + "\n";
}

// ── STIX indicators-only format ───────────────────────────────────────────────
// Uses the same namespace and id scheme as the full STIX bundle (stix.ts) so indicator
// ids are stable and consistent whether exported here or via the full bundle.

const DFIR_STIX_NAMESPACE = "9b7c5e2a-1b9d-4f6c-8b2e-1a0f9c8d7e6b";

function uuidv5(name: string): string {
  const ns = Buffer.from(DFIR_STIX_NAMESPACE.replace(/-/g, ""), "hex");
  const b = createHash("sha1").update(ns).update(name, "utf8").digest().subarray(0, 16);
  b[6] = (b[6] & 0x0f) | 0x50;
  b[8] = (b[8] & 0x3f) | 0x80;
  const hex = b.toString("hex");
  return `${hex.slice(0, 8)}-${hex.slice(8, 12)}-${hex.slice(12, 16)}-${hex.slice(16, 20)}-${hex.slice(20)}`;
}

function stixTime(value: string | undefined, fallback: string): string {
  if (value) {
    const t = new Date(value);
    if (!Number.isNaN(t.getTime())) return t.toISOString();
  }
  return fallback;
}

const INDICATOR_TYPE: Record<IocEnrichment["verdict"], string> = {
  malicious: "malicious-activity",
  suspicious: "anomalous-activity",
  harmless: "benign",
  unknown: "unknown",
};

/**
 * Build a stripped-down STIX 2.1 bundle containing only `indicator` objects — no report,
 * identities, attack-patterns, or relationships. The minimal unit most blocking tools accept.
 * Indicator ids are identical to those produced by the full STIX bundle (same namespace + key).
 * Pure — depends only on its arguments.
 */
export function buildIocBlocklistStix(state: InvestigationState, opts: IocBlocklistOptions = {}): StixBundle {
  const filtered = filterBlocklistIocs(state.iocs, opts);
  const now = stixTime(state.updatedAt, new Date(0).toISOString());
  const idFor = (type: string, key: string): string => `${type}--${uuidv5(`${state.caseId}|${type}|${key}`)}`;

  const objects: StixObject[] = [];
  for (const { ioc } of [...filtered].sort((a, b) => a.ioc.value.localeCompare(b.ioc.value))) {
    const pattern = iocToStixPattern(ioc);
    if (!pattern) continue;
    const verdict = worstVerdict(ioc);
    const summary = verdictSummary(ioc);
    objects.push({
      type: "indicator",
      spec_version: "2.1",
      id: idFor("indicator", `${ioc.type}|${ioc.value}`),
      created: now,
      modified: now,
      name: ioc.value,
      pattern,
      pattern_type: "stix",
      valid_from: stixTime(ioc.firstSeen, now),
      indicator_types: [INDICATOR_TYPE[verdict ?? "unknown"]],
      description: summary
        ? `Threat-intel verdict: ${verdict} — ${summary}`
        : "Indicator observed during the investigation.",
    });
  }

  return {
    type: "bundle",
    id: `bundle--${uuidv5(`${state.caseId}|ioc-blocklist`)}`,
    objects,
  };
}
