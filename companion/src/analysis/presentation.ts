// Case Timeline Replay / Presentation Mode (#177) — a read-only, step-through deck for handoff
// briefings and executive walkthroughs. The dashboard is information-dense and great for analysts
// but hard to present to non-technical stakeholders; this module SHAPES the (already scope/legit-
// filtered) case state into an ordered list of large, readable slides the analyst can walk through
// one event at a time. No editing, no AI — like the mobile summary, it only projects existing state.
//
// Pure + unit-tested independently of I/O. The ReportWriter calls it on demand with the same
// scope/legitimate-filtered state the report and dashboard show (so the deck never disagrees), and
// resolves the branding from the case's report template; the slide viewer (public/present.html) and
// the standalone-HTML export both render the SAME deck.

import type { Finding, ForensicEvent, IOC, InvestigationState, Severity } from "./stateTypes.js";
import { SEVERITY_RANK } from "./severityFloor.js";

export type IocVerdict = "malicious" | "suspicious" | "harmless" | "unknown";

const VERDICT_RANK: Record<IocVerdict, number> = { malicious: 0, suspicious: 1, harmless: 2, unknown: 3 };

// Indicator-shaped token (IP/domain/URL/hash/path) — mirrors iocCorroboration's matcher so an
// event's "supporting IOCs" are tied to indicators that actually appear in the event, not guesses.
const TOKEN_RE = /[\w.@:/\\-]{3,}/g;

// Branding for the deck cover + accent, resolved by the ReportWriter from the case's report
// template (issue #60) so the presentation inherits the same look as the report.
export interface PresentationBranding {
  title: string;            // cover title (placeholders already rendered)
  subtitle: string;         // cover subtitle (placeholders already rendered)
  accentColor: string;      // #rrggbb
  companyName: string;      // firm/org name shown on the cover when showCompanyName is on
}

export interface PresentationIoc {
  value: string;
  type: IOC["type"];
  verdict: IocVerdict | null;   // worst enrichment verdict across engines; null = not enriched
}

export type PresentationSlideKind = "title" | "summary" | "section" | "finding" | "event";

export interface PresentationSlide {
  kind: PresentationSlideKind;
  title: string;
  // title slide
  branding?: PresentationBranding;
  counts?: PresentationCounts;
  severityCounts?: Record<Severity, number>;   // FINDINGS by severity (title slide)
  // summary / section slide
  body?: string;
  // finding / event slide
  severity?: Severity;
  timestamp?: string;
  endTimestamp?: string;
  description?: string;
  asset?: string;
  sources?: string[];
  mitreTechniques?: string[];
  iocs?: PresentationIoc[];
  screenshot?: string;          // screenshot filename, if any (rendered as evidence)
  confidence?: number;          // finding only
  count?: number;               // event aggregation count
}

export interface PresentationCounts {
  findings: number;             // post-filter
  events: number;               // post-filter
  iocs: number;
}

export interface PresentationDeck {
  caseId: string;
  caseName: string;
  generatedAt: string;          // stamped by the caller (the pure builder never reads the clock)
  minSeverity: Severity | null; // the severity floor the deck was built with (null = all)
  branding: PresentationBranding;
  slides: PresentationSlide[];
  slideCount: number;
}

export interface PresentationOptions {
  branding: PresentationBranding;
  caseName?: string;
  generatedAt?: string;         // ISO; stamped onto the deck (kept out of the pure logic)
  minSeverity?: Severity;       // severity floor for findings + events; absent/Info = include all
  maxFindings?: number;         // default 40
  maxEvents?: number;           // default 200
  maxIocsPerSlide?: number;     // default 8
}

const DEFAULTS = { maxFindings: 40, maxEvents: 200, maxIocsPerSlide: 8 } as const;

// The single worst (most malicious) verdict across an IOC's enrichments, or null when not yet
// enriched. Mirrors the mobile summary so the two read-only projections agree.
export function worstVerdict(ioc: Pick<IOC, "enrichments">): IocVerdict | null {
  const enrichments = ioc.enrichments ?? [];
  if (enrichments.length === 0) return null;
  let best: IocVerdict | null = null;
  for (const e of enrichments) {
    if (best === null || VERDICT_RANK[e.verdict] < VERDICT_RANK[best]) best = e.verdict;
  }
  return best;
}

function emptySeverityCounts(): Record<Severity, number> {
  return { Critical: 0, High: 0, Medium: 0, Low: 0, Info: 0 };
}

// Keep items at or above the floor (worse-or-equal rank). No floor / "Info" → keep everything.
function atOrAbove<T extends { severity: Severity }>(items: T[], minSeverity?: Severity): T[] {
  if (!minSeverity || minSeverity === "Info") return items;
  const floor = SEVERITY_RANK[minSeverity];
  return items.filter((i) => SEVERITY_RANK[i.severity] <= floor);
}

function eventTime(e: Pick<ForensicEvent, "timestamp">): number {
  return Date.parse(e.timestamp);
}

// Findings worst-first (by severity, then most-recently-updated, then newest first-seen).
function compareFindings(a: Finding, b: Finding): number {
  const sev = SEVERITY_RANK[a.severity] - SEVERITY_RANK[b.severity];
  if (sev !== 0) return sev;
  const lu = (b.lastUpdated || "").localeCompare(a.lastUpdated || "");
  if (lu !== 0) return lu;
  return (b.firstSeen || "").localeCompare(a.firstSeen || "");
}

// Events in CHRONOLOGICAL order — the deck walks the incident forward in time. Undated events
// (empty/unparseable timestamp) sort last so the known chronology stays readable.
function compareEventsChrono(a: ForensicEvent, b: ForensicEvent): number {
  const ta = eventTime(a);
  const tb = eventTime(b);
  const va = Number.isNaN(ta);
  const vb = Number.isNaN(tb);
  if (va && vb) return 0;
  if (va) return 1;
  if (vb) return -1;
  return ta - tb;   // earliest first
}

// Index IOCs by their lowercased value so an event's supporting indicators resolve in O(tokens).
function indexIocs(iocs: readonly IOC[]): Map<string, IOC> {
  const index = new Map<string, IOC>();
  for (const ioc of iocs) {
    const key = ioc.value.trim().toLowerCase();
    if (key.length >= 3 && !index.has(key)) index.set(key, ioc);
  }
  return index;
}

function toPresentationIoc(ioc: IOC): PresentationIoc {
  return { value: ioc.value, type: ioc.type, verdict: worstVerdict(ioc) };
}

// The IOCs an event references: structured fields (sha256/md5/srcIp/dstIp/path) plus
// indicator-shaped tokens in the description, looked up against the IOC index. Exact-token match
// (not substring) so "10.0.0.1" doesn't falsely match inside "10.0.0.10". Capped, malicious-first.
function eventIocs(event: ForensicEvent, index: Map<string, IOC>, cap: number): PresentationIoc[] {
  if (index.size === 0 || cap <= 0) return [];
  const seen = new Set<string>();
  const matched: IOC[] = [];
  const consider = (raw: string | undefined): void => {
    if (!raw) return;
    const key = raw.trim().toLowerCase();
    if (key.length < 3 || seen.has(key)) return;
    const ioc = index.get(key);
    if (ioc) { seen.add(key); matched.push(ioc); }
  };
  consider(event.sha256);
  consider(event.md5);
  consider(event.srcIp);
  consider(event.dstIp);
  consider(event.path);
  const tokens = (event.description || "").match(TOKEN_RE);
  if (tokens) for (const t of tokens) consider(t);
  return matched
    .map(toPresentationIoc)
    .sort((a, b) => {
      const ra = a.verdict === null ? 4 : VERDICT_RANK[a.verdict];
      const rb = b.verdict === null ? 4 : VERDICT_RANK[b.verdict];
      return ra - rb;
    })
    .slice(0, cap);
}

function findingSlide(f: Finding, iocById: Map<string, IOC>, cap: number): PresentationSlide {
  const iocs = (f.relatedIocs ?? [])
    .map((id) => iocById.get(id))
    .filter((i): i is IOC => Boolean(i))
    .map(toPresentationIoc)
    .slice(0, cap);
  return {
    kind: "finding",
    title: f.title,
    severity: f.severity,
    description: f.description,
    confidence: f.confidence,
    mitreTechniques: f.mitreTechniques ?? [],
    iocs,
    screenshot: (f.sourceScreenshots ?? [])[0],
  };
}

function eventSlide(e: ForensicEvent, valueIndex: Map<string, IOC>, cap: number): PresentationSlide {
  return {
    kind: "event",
    title: e.asset ? `${e.asset}` : "Timeline event",
    severity: e.severity,
    timestamp: e.timestamp,
    endTimestamp: e.endTimestamp,
    description: e.description,
    asset: e.asset,
    sources: e.sources,
    mitreTechniques: e.mitreTechniques ?? [],
    iocs: eventIocs(e, valueIndex, cap),
    screenshot: (e.sourceScreenshots ?? [])[0],
    count: e.count,
  };
}

// Build the presentation deck from an (already scope/legitimate-filtered) investigation state.
// Pure: never mutates the input. The slide order is: title → summary → narrative → key findings
// (worst-first) → timeline events (chronological). Findings and events are filtered by the
// severity floor and capped; IOCs per slide are capped. The caller stamps `generatedAt`.
export function buildPresentationDeck(
  state: InvestigationState,
  opts: PresentationOptions,
): PresentationDeck {
  const maxFindings = Math.max(0, opts.maxFindings ?? DEFAULTS.maxFindings);
  const maxEvents = Math.max(0, opts.maxEvents ?? DEFAULTS.maxEvents);
  const maxIocs = Math.max(0, opts.maxIocsPerSlide ?? DEFAULTS.maxIocsPerSlide);
  const minSeverity = opts.minSeverity && opts.minSeverity !== "Info" ? opts.minSeverity : undefined;

  const allFindings = state.findings ?? [];
  const allEvents = state.forensicTimeline ?? [];
  const iocs = state.iocs ?? [];

  const findings = atOrAbove([...allFindings], minSeverity).sort(compareFindings).slice(0, maxFindings);
  const events = atOrAbove([...allEvents], minSeverity).sort(compareEventsChrono).slice(0, maxEvents);

  const iocById = new Map<string, IOC>(iocs.map((i) => [i.id, i]));
  const valueIndex = indexIocs(iocs);

  const severityCounts = emptySeverityCounts();
  for (const f of findings) if (f.severity in severityCounts) severityCounts[f.severity] += 1;

  const counts: PresentationCounts = { findings: findings.length, events: events.length, iocs: iocs.length };
  const caseName = opts.caseName?.trim() || state.caseId;

  const slides: PresentationSlide[] = [];

  // 1) Cover.
  slides.push({
    kind: "title",
    title: opts.branding.title?.trim() || caseName,
    branding: opts.branding,
    counts,
    severityCounts,
  });

  // 2) Executive summary, then the prose incident narrative (presenter context), then attacker path.
  const summary = (state.lastSummary ?? "").trim();
  if (summary) slides.push({ kind: "summary", title: "Summary", body: summary });
  const narrative = (state.narrativeTimeline ?? "").trim();
  if (narrative) slides.push({ kind: "summary", title: "Incident narrative", body: narrative });
  const attackerPath = (state.attackerPath ?? "").trim();
  if (attackerPath) slides.push({ kind: "summary", title: "Attacker path", body: attackerPath });

  // 3) Key findings (worst-first).
  if (findings.length) {
    slides.push({ kind: "section", title: "Key findings", body: `${findings.length} finding(s)` });
    for (const f of findings) slides.push(findingSlide(f, iocById, maxIocs));
  }

  // 4) Timeline events (chronological — the step-through walk of the incident).
  if (events.length) {
    slides.push({ kind: "section", title: "Timeline", body: `${events.length} event(s)` });
    for (const e of events) slides.push(eventSlide(e, valueIndex, maxIocs));
  }

  return {
    caseId: state.caseId,
    caseName,
    generatedAt: opts.generatedAt ?? "",
    minSeverity: minSeverity ?? null,
    branding: opts.branding,
    slides,
    slideCount: slides.length,
  };
}

// Resolve the per-deck caps from the environment (DFIR_PRESENT_MAX_FINDINGS/EVENTS), keeping the
// defaults when unset/invalid. Separated from the pure builder so it stays side-effect-free.
export function presentationEnvOptions(): Pick<PresentationOptions, "maxFindings" | "maxEvents"> {
  const num = (raw: string | undefined, fallback: number): number => {
    const n = Number(raw);
    return Number.isFinite(n) && n >= 0 ? Math.floor(n) : fallback;
  };
  return {
    maxFindings: num(process.env.DFIR_PRESENT_MAX_FINDINGS, DEFAULTS.maxFindings),
    maxEvents: num(process.env.DFIR_PRESENT_MAX_EVENTS, DEFAULTS.maxEvents),
  };
}
