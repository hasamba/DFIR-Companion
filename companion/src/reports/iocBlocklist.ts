import { createHash } from "node:crypto";
import { actionableAssertions } from "../analysis/intelViews.js";
import { retiredIocIds } from "../analysis/intelRetirement.js";
import {
  SEVERITY_RANK,
  type InvestigationState,
  type IOC,
  type IocEnrichment,
  type Severity,
} from "../analysis/stateTypes.js";
import { iocToStixPattern } from "./stix.js";
import type { StixBundle, StixObject } from "./stix.js";

/** The downloadable block-list file formats. */
export type IocBlocklistFormat = "txt" | "csv" | "stix";
/** What GET /cases/:id/export/ioc-blocklist accepts: a file format, or the match summary (#1807). */
export type IocBlocklistRequestFormat = IocBlocklistFormat | "summary";
export const IOC_BLOCKLIST_REQUEST_FORMATS: readonly IocBlocklistRequestFormat[] = [
  "txt",
  "csv",
  "stix",
  "summary",
];
/** Response content type and file extension per downloadable format. */
export const IOC_BLOCKLIST_FILE_FORMATS: Record<
  IocBlocklistFormat,
  { contentType: string; extension: string }
> = {
  txt: { contentType: "text/plain; charset=utf-8", extension: "txt" },
  csv: { contentType: "text/csv; charset=utf-8", extension: "csv" },
  stix: { contentType: "application/json; charset=utf-8", extension: "stix.json" },
};
export type BlocklistIocType = "ip" | "domain" | "url" | "hash" | "email";

export interface IocBlocklistOptions {
  /** Minimum severity (derived from worst enrichment verdict). Default: "Medium". */
  minSeverity?: Severity;
  /** IOC types to include. Default: ip, domain, url, hash (not email). */
  types?: BlocklistIocType[];
  /** When true, only include IOCs with a malicious or suspicious verdict. Default: false. */
  verdictOnly?: boolean;
  /** IOC ids a recorded retire decision leaves out (#1024) — the builders derive them from the state. */
  excludeIocIds?: ReadonlySet<string>;
  /** Case name for TXT/CSV header comments. Falls back to caseId when absent. */
  caseName?: string;
  /** ISO timestamp for the "Generated:" header line. Defaults to current time when absent. */
  generatedAt?: string;
}

// ── Severity helpers ──────────────────────────────────────────────────────────

const VERDICT_RANK: Record<IocEnrichment["verdict"], number> = {
  malicious: 3,
  suspicious: 2,
  harmless: 1,
  unknown: 0,
};

// A block-list ACTS: only actionable assertions decide its verdict (#1024) — an expired, revoked,
// not-returned, errored-last-known or legacy assertion never reaches a blocked address.
function worstVerdict(ioc: IOC): IocEnrichment["verdict"] | null {
  let best: IocEnrichment["verdict"] | null = null;
  for (const e of actionableAssertions(ioc)) {
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
 * Why a block-list leaves an IOC out (#1807), or null when it is kept. One reason per IOC: the
 * FIRST check it fails, in the order the filter applies them.
 *   - no-actionable-intel: fails the severity floor with no actionable verdict at all (never
 *     enriched, or every assertion expired / was revoked / is not actionable).
 *   - below-min-severity: has an actionable verdict, but it maps below the floor.
 */
export const BLOCKLIST_EXCLUSION_REASONS = [
  "retired",
  "client-reported",
  "ineligible-type",
  "no-actionable-intel",
  "below-min-severity",
  "not-verdict-confirmed",
] as const;
export type BlocklistExclusionReason = (typeof BLOCKLIST_EXCLUSION_REASONS)[number];

export function blocklistExclusionReason(
  ioc: IOC,
  opts: IocBlocklistOptions,
): BlocklistExclusionReason | null {
  if (opts.excludeIocIds?.has(ioc.id)) return "retired";
  // #1266: a block-list ACTS, and a client-reported value (a sender-controlled header, e.g.
  // X-Originating-IP) is a claim, not an observation — a forged header must never be able to
  // put an address on it, whatever intel says about that address. Same rule as MISP to_ids.
  if (ioc.provenance === "client-reported") return "client-reported";
  const eff = effectiveType(ioc);
  if (!eff || !(opts.types ?? DEFAULT_TYPES).includes(eff)) return "ineligible-type";
  // Canonical SEVERITY_RANK: lower = more severe, so "below the floor" is a GREATER rank.
  if (SEVERITY_RANK[iocSeverity(ioc)] > SEVERITY_RANK[opts.minSeverity ?? DEFAULT_MIN_SEVERITY]) {
    return worstVerdict(ioc) === null ? "no-actionable-intel" : "below-min-severity";
  }
  if (opts.verdictOnly) {
    const v = worstVerdict(ioc);
    if (v !== "malicious" && v !== "suspicious") return "not-verdict-confirmed";
  }
  return null;
}

/**
 * Apply block-list filters to an IOC list.
 * The state must already be scope/legitimate-filtered (ReportWriter.loadFilteredState does this).
 */
export function filterBlocklistIocs(
  iocs: IOC[],
  opts: IocBlocklistOptions,
): { ioc: IOC; effectiveType: BlocklistIocType }[] {
  const results: { ioc: IOC; effectiveType: BlocklistIocType }[] = [];
  for (const ioc of iocs) {
    const eff = effectiveType(ioc);
    if (eff && blocklistExclusionReason(ioc, opts) === null) results.push({ ioc, effectiveType: eff });
  }
  return results;
}

export interface BlocklistSummary {
  total: number;
  matched: number;
  excluded: Record<BlocklistExclusionReason, number>;
}

/** How many IOCs the block-list keeps, and how many each reason leaves out (#1807). */
export function summarizeBlocklist(iocs: IOC[], opts: IocBlocklistOptions): BlocklistSummary {
  const excluded = Object.fromEntries(BLOCKLIST_EXCLUSION_REASONS.map((r) => [r, 0])) as Record<
    BlocklistExclusionReason,
    number
  >;
  let matched = 0;
  for (const ioc of iocs) {
    const reason = blocklistExclusionReason(ioc, opts);
    if (reason === null) matched += 1;
    else excluded[reason] += 1;
  }
  return { total: iocs.length, matched, excluded };
}

function reasonText(reason: BlocklistExclusionReason, minSev: Severity): string {
  switch (reason) {
    case "retired":
      return "retired";
    case "client-reported":
      return "client-reported (sender-controlled header)";
    case "ineligible-type":
      return "IOC type not in the block-list or not selected";
    case "no-actionable-intel":
      return "no usable threat-intel verdict (never enriched, or the verdict expired or was revoked) — run enrichment and export again";
    case "below-min-severity":
      return `below minimum severity ${minSev}`;
    case "not-verdict-confirmed":
      return "not verdict-confirmed";
  }
}

// The TXT header lines that say how many IOCs matched and why the rest were left out.
function summaryHeaderLines(summary: BlocklistSummary, minSev: Severity): string[] {
  return [
    `# Matched ${summary.matched} of ${summary.total} IOCs`,
    ...BLOCKLIST_EXCLUSION_REASONS.filter((r) => summary.excluded[r] > 0).map(
      (r) => `#   ${summary.excluded[r]} ${reasonText(r, minSev)}`,
    ),
  ];
}

// ── Shared helpers ────────────────────────────────────────────────────────────

function verdictSummary(ioc: IOC): string {
  const v = worstVerdict(ioc);
  if (!v) return "";
  const hits = actionableAssertions(ioc)
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
// A retire decision leaves the retired finding's own IOCs out of every block-list format (#1024).
const withRetired = (state: InvestigationState, opts: IocBlocklistOptions): IocBlocklistOptions => ({
  ...opts,
  excludeIocIds: opts.excludeIocIds ?? retiredIocIds(state),
});

export function buildIocBlocklistTxt(state: InvestigationState, opts: IocBlocklistOptions = {}): string {
  const resolved = withRetired(state, opts);
  const filtered = filterBlocklistIocs(state.iocs, resolved);
  const minSev = opts.minSeverity ?? DEFAULT_MIN_SEVERITY;
  const types = opts.types ?? DEFAULT_TYPES;
  const ts = opts.generatedAt ?? new Date().toISOString();

  const lines: string[] = [
    "# DFIR Companion — IOC Block List",
    `# Case: ${opts.caseName?.trim() || state.caseId}`,
    `# Generated: ${ts}`,
    `# Filters: scope applied, legitimate excluded, client-reported excluded, min severity: ${minSev}${opts.verdictOnly ? ", verdict-confirmed only" : ""}`,
    ...summaryHeaderLines(summarizeBlocklist(state.iocs, resolved), minSev),
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
  // CSV injection guard: a cell starting with = + - @ (or a tab/CR) is interpreted as a formula by
  // Excel/LibreOffice. Prefix a single quote so spreadsheet apps treat it as text. Mirrors the
  // guard in csv.ts:cell — the two exporters were written independently and iocBlocklist missed it.
  // IOC ingest does not reject formula-prefixed values (a token starting with = can be real
  // evidence), so they reach the export and would execute as formulas on the analyst's machine.
  const guarded = /^[=+\-@\t\r]/.test(s) ? `'${s}` : s;
  if (/[",\r\n]/.test(guarded)) return `"${guarded.replace(/"/g, '""')}"`;
  return guarded;
}

/**
 * Build a minimal CSV IOC block-list: type, value, severity, verdict, description.
 * Pure — depends only on its arguments.
 */
export function buildIocBlocklistCsv(state: InvestigationState, opts: IocBlocklistOptions = {}): string {
  const filtered = filterBlocklistIocs(state.iocs, withRetired(state, opts));
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
  const filtered = filterBlocklistIocs(state.iocs, withRetired(state, opts));
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

// ── Format dispatch ───────────────────────────────────────────────────────────

/** Build the requested block-list output: a file format, or the match summary (#1807). */
export function buildIocBlocklist(
  format: IocBlocklistRequestFormat,
  state: InvestigationState,
  opts: IocBlocklistOptions = {},
): string | StixBundle | BlocklistSummary {
  if (format === "summary") return summarizeBlocklist(state.iocs, withRetired(state, opts));
  if (format === "csv") return buildIocBlocklistCsv(state, opts);
  if (format === "stix") return buildIocBlocklistStix(state, opts);
  return buildIocBlocklistTxt(state, opts);
}

const VALID_SEVERITIES: readonly Severity[] = ["Critical", "High", "Medium", "Low", "Info"];
const VALID_TYPES: readonly BlocklistIocType[] = ["ip", "domain", "url", "hash", "email"];

/** Read the block-list filter options from untrusted query parameters. Unknown values are dropped. */
export function parseBlocklistQuery(query: Record<string, unknown>): IocBlocklistOptions {
  const opts: IocBlocklistOptions = {};
  const { minSeverity, types, verdictOnly } = query;
  if (typeof minSeverity === "string" && VALID_SEVERITIES.includes(minSeverity as Severity)) {
    opts.minSeverity = minSeverity as Severity;
  }
  // A present but empty `types=` means the analyst unticked every type: no IOC matches. Only an
  // ABSENT parameter falls back to the defaults, or unticking everything would export them all.
  if (typeof types === "string") {
    opts.types = types
      .split(",")
      .filter((t): t is BlocklistIocType => VALID_TYPES.includes(t as BlocklistIocType));
  }
  if (verdictOnly === "true") opts.verdictOnly = true;
  return opts;
}
