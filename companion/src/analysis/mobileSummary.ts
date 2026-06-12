// Mobile companion summary (#59) — a compact, READ-ONLY projection of the case state for the
// mobile PWA (public/mobile.html). The phone view is for quick glances during IR when away from
// the workstation: case status, the worst findings, the most severe/recent timeline events, and
// the IOC list with their threat-intel verdicts. No editing, no AI operations — this module only
// SHAPES existing state into a lean payload (smaller over the wire, pre-sorted, pre-counted).
//
// Pure + unit-tested independently of I/O. The ReportWriter calls it on demand with the same
// scope/legitimate-filtered state the report and dashboard show, so the phone never disagrees
// with the desktop view.

import type { Finding, ForensicEvent, IOC, InvestigationState, Severity } from "./stateTypes.js";
import { SEVERITY_RANK } from "./severityFloor.js";

export type IocVerdict = "malicious" | "suspicious" | "harmless" | "unknown";

// Lower number = worse. Mirrors the dashboard's "flagged" notion (malicious/suspicious).
const VERDICT_RANK: Record<IocVerdict, number> = { malicious: 0, suspicious: 1, harmless: 2, unknown: 3 };

export interface MobileFinding {
  id: string;
  severity: Severity;
  title: string;
  confidence?: number;
  status: Finding["status"];
  mitreTechniques: string[];
}

export interface MobileEvent {
  id: string;
  timestamp: string;
  severity: Severity;
  description: string;
  asset?: string;
  mitreTechniques: string[];
  count?: number;          // occurrences when the event aggregates collapsed lines (absent ⇒ 1)
  sources?: string[];      // distinct tools that reported it (corroboration)
}

export interface MobileIoc {
  id: string;
  type: IOC["type"];
  value: string;
  firstSeen: string;
  verdict: IocVerdict | null;   // worst enrichment verdict across engines; null = not enriched yet
}

export interface MobileSummaryCounts {
  findings: number;
  events: number;
  iocs: number;
  openThreads: number;
  flaggedIocs: number;          // IOCs with a malicious or suspicious verdict from any engine
  techniques: number;
}

// A capped list plus the pre-cap total, so the UI can say "showing 50 of 312".
export interface MobileSection<T> {
  items: T[];
  total: number;
}

export interface MobileCaseSummary {
  caseId: string;
  caseName: string;
  updatedAt: string;
  summary: string;                            // lastSummary (trimmed)
  severityCounts: Record<Severity, number>;   // FINDINGS counted by severity
  counts: MobileSummaryCounts;
  findings: MobileSection<MobileFinding>;      // worst-first
  events: MobileSection<MobileEvent>;          // most severe, then most recent
  iocs: MobileSection<MobileIoc>;              // flagged-first, then newest
}

export interface MobileSummaryOptions {
  maxFindings?: number;   // default 50
  maxEvents?: number;     // default 50
  maxIocs?: number;       // default 100
  caseName?: string;      // display name (from case.json); falls back to caseId
}

const DEFAULTS = { maxFindings: 50, maxEvents: 50, maxIocs: 100 } as const;

// The single worst (most malicious) verdict across an IOC's enrichments, or null when it has not
// been enriched yet. "Flagged" in the dashboard = malicious|suspicious — we surface the same notion.
export function worstVerdict(ioc: Pick<IOC, "enrichments">): IocVerdict | null {
  const enrichments = ioc.enrichments ?? [];
  if (enrichments.length === 0) return null;
  let best: IocVerdict | null = null;
  for (const e of enrichments) {
    const v = e.verdict;
    if (best === null || VERDICT_RANK[v] < VERDICT_RANK[best]) best = v;
  }
  return best;
}

function isFlagged(v: IocVerdict | null): boolean {
  return v === "malicious" || v === "suspicious";
}

// Parse one event time to epoch-ms; NaN for empty/unparseable.
function eventTime(e: Pick<ForensicEvent, "timestamp">): number {
  return Date.parse(e.timestamp);
}

// Order findings worst-first: by severity, then most-recently-updated, then newest first-seen.
function compareFindings(a: Finding, b: Finding): number {
  const sev = SEVERITY_RANK[a.severity] - SEVERITY_RANK[b.severity];
  if (sev !== 0) return sev;
  const lu = (b.lastUpdated || "").localeCompare(a.lastUpdated || "");
  if (lu !== 0) return lu;
  return (b.firstSeen || "").localeCompare(a.firstSeen || "");
}

// Order events for the "what matters now" glance: most severe first, then most recent. Events with
// an unparseable/empty timestamp sort after dated ones so the known chronology stays readable.
function compareEvents(a: ForensicEvent, b: ForensicEvent): number {
  const sev = SEVERITY_RANK[a.severity] - SEVERITY_RANK[b.severity];
  if (sev !== 0) return sev;
  const ta = eventTime(a);
  const tb = eventTime(b);
  const va = Number.isNaN(ta);
  const vb = Number.isNaN(tb);
  if (va && vb) return 0;
  if (va) return 1;
  if (vb) return -1;
  return tb - ta;   // most recent first
}

// Order IOCs flagged-first (malicious before suspicious), then everything else newest-first.
function compareIocs(a: IOC, b: IOC): number {
  const va = worstVerdict(a);
  const vb = worstVerdict(b);
  const ra = va === null ? 4 : VERDICT_RANK[va];
  const rb = vb === null ? 4 : VERDICT_RANK[vb];
  if (ra !== rb) return ra - rb;
  return (b.firstSeen || "").localeCompare(a.firstSeen || "");
}

function emptySeverityCounts(): Record<Severity, number> {
  return { Critical: 0, High: 0, Medium: 0, Low: 0, Info: 0 };
}

function toMobileFinding(f: Finding): MobileFinding {
  return {
    id: f.id,
    severity: f.severity,
    title: f.title,
    confidence: f.confidence,
    status: f.status,
    mitreTechniques: f.mitreTechniques ?? [],
  };
}

function toMobileEvent(e: ForensicEvent): MobileEvent {
  return {
    id: e.id,
    timestamp: e.timestamp,
    severity: e.severity,
    description: e.description,
    asset: e.asset,
    mitreTechniques: e.mitreTechniques ?? [],
    count: e.count,
    sources: e.sources,
  };
}

function toMobileIoc(i: IOC): MobileIoc {
  return {
    id: i.id,
    type: i.type,
    value: i.value,
    firstSeen: i.firstSeen,
    verdict: worstVerdict(i),
  };
}

// Build the compact mobile payload from a (already scope/legitimate-filtered) investigation state.
// Pure: never mutates the input. Heavy lists (events, IOCs) are capped so the phone payload stays
// small; the pre-cap `total` lets the UI show "N of M".
export function buildMobileSummary(
  state: InvestigationState,
  opts: MobileSummaryOptions = {},
): MobileCaseSummary {
  const maxFindings = Math.max(0, opts.maxFindings ?? DEFAULTS.maxFindings);
  const maxEvents = Math.max(0, opts.maxEvents ?? DEFAULTS.maxEvents);
  const maxIocs = Math.max(0, opts.maxIocs ?? DEFAULTS.maxIocs);

  const findings = state.findings ?? [];
  const events = state.forensicTimeline ?? [];
  const iocs = state.iocs ?? [];
  const openThreads = state.openThreads ?? [];
  const techniques = state.mitreTechniques ?? [];

  const severityCounts = emptySeverityCounts();
  for (const f of findings) {
    if (f.severity in severityCounts) severityCounts[f.severity] += 1;
  }

  const flaggedIocs = iocs.reduce((n, i) => (isFlagged(worstVerdict(i)) ? n + 1 : n), 0);

  const sortedFindings = [...findings].sort(compareFindings);
  const sortedEvents = [...events].sort(compareEvents);
  const sortedIocs = [...iocs].sort(compareIocs);

  return {
    caseId: state.caseId,
    caseName: opts.caseName?.trim() || state.caseId,
    updatedAt: state.updatedAt,
    summary: (state.lastSummary ?? "").trim(),
    severityCounts,
    counts: {
      findings: findings.length,
      events: events.length,
      iocs: iocs.length,
      openThreads: openThreads.filter((t) => t.status === "open").length,
      flaggedIocs,
      techniques: techniques.length,
    },
    findings: { items: sortedFindings.slice(0, maxFindings).map(toMobileFinding), total: findings.length },
    events: { items: sortedEvents.slice(0, maxEvents).map(toMobileEvent), total: events.length },
    iocs: { items: sortedIocs.slice(0, maxIocs).map(toMobileIoc), total: iocs.length },
  };
}

// Resolve the per-list caps from the environment (DFIR_MOBILE_MAX_FINDINGS/EVENTS/IOCS), keeping
// the defaults when unset/invalid. Separated from the pure builder so buildMobileSummary stays
// side-effect-free; the ReportWriter calls this to assemble the options.
export function mobileSummaryEnvOptions(): MobileSummaryOptions {
  const num = (raw: string | undefined, fallback: number): number => {
    const n = Number(raw);
    return Number.isFinite(n) && n >= 0 ? Math.floor(n) : fallback;
  };
  return {
    maxFindings: num(process.env.DFIR_MOBILE_MAX_FINDINGS, DEFAULTS.maxFindings),
    maxEvents: num(process.env.DFIR_MOBILE_MAX_EVENTS, DEFAULTS.maxEvents),
    maxIocs: num(process.env.DFIR_MOBILE_MAX_IOCS, DEFAULTS.maxIocs),
  };
}
