// Second-look loop (investigation-guidance #11). The complete raw record (the super-timeline + the
// scoped events the synthesis sampler omitted) is unreachable by the AI no matter what hypotheses it
// forms — northpeak's recon/clone/exfil story sat in raw rows synthesis never saw. This module is the
// PURE core of a post-synthesis executor that turns the case's OPEN questions into concrete search
// requests, resolves them against that raw record, and decides what to promote for one bounded
// re-synthesis. All I/O (querying the super-timeline, promoting, re-synthesizing) lives in pipeline.ts.
//
// Two request sources feed it: (a) DETERMINISTIC harvest — search terms mined from the open
// hypotheses (their IOC values + signal tokens in title/expectedOutcome), the unknown/partial key
// questions' structured collect targets, and the top connective IOCs; (b) MODEL-ISSUED — an optional
// evidenceRequests array the synthesis prompt lets the model fill with data it knows it wasn't shown.
//
// The bounds are strict and everything is deterministic + idempotent: a request that matches nothing is
// itself surfaced as a collection lead (a blind spot the tool can task around), matches are capped per
// term and per sweep, and only events NOT already in the analyzed timeline are promotable (re-promoting
// an event already present is a no-op that must never inflate the count).

import type { ForensicEvent, InvestigationQuestion } from "./stateTypes.js";
import type { Hypothesis } from "./hypothesis.js";
import type { IocAnchor } from "./iocAnchors.js";
import { shortHost } from "./iocAnchors.js";

// A single concrete search issued by the second-look sweep. `keywords` are matched case-insensitively
// (ANY keyword hits) across the event's searchable fields, optionally restricted to `host` and the
// [from,to] window. `tag` is the provenance stamp written onto every event this request promotes so the
// forensic timeline shows WHY the row was pulled up; `reason` becomes a collection lead when nothing
// matched anywhere.
export interface SecondLookRequest {
  source: "hypothesis" | "question" | "connective-ioc" | "model";
  tag: string;         // e.g. "[second-look: h2]"
  label: string;       // human summary of what this request looked for
  keywords: string[];  // lowercased, deduped, non-empty
  host?: string;       // optional host restriction (matched against shortHost of event.asset)
  from?: string;       // ISO lower bound (inclusive); undated events are kept
  to?: string;         // ISO upper bound (inclusive)
  reason: string;      // surfaced as a collection lead when matchedEventIds is empty
}

// One model-issued evidence request as parsed from the synthesis delta (all fields best-effort).
export interface ModelEvidenceRequest {
  host?: string;
  timeWindow?: { from?: string; to?: string };
  keywords?: string[];
  reason?: string;
}

export interface SecondLookResolution {
  request: SecondLookRequest;
  matchedEventIds: string[];    // every matched candidate id (incl. events already in the timeline)
  promotable: ForensicEvent[];  // matched events NOT already in the analyzed timeline (the real gain)
}

export interface SecondLookPlan {
  promotions: ForensicEvent[];         // deduped across requests + capped to the sweep budget
  tagById: Record<string, string[]>;   // event id → provenance tags to stamp on promotion
  resolutions: SecondLookResolution[];
  leads: SecondLookRequest[];          // requests that matched nothing anywhere — collection leads
  truncated: boolean;                  // true when the sweep cap dropped some promotable events
}

export interface SecondLookCaps {
  perTerm?: number;               // max events promoted from a single request (default 50)
  sweep?: number;                 // max events promoted across the whole sweep (default 200)
  maxHypotheses?: number;         // open hypotheses turned into requests (default 6)
  maxQuestions?: number;          // unknown/partial collect-bearing questions → requests (default 6)
  maxConnectiveIocs?: number;     // top connective IOCs → requests (default 5)
  maxModel?: number;              // model evidenceRequests honored (default 5)
  maxKeywordsPerRequest?: number; // keyword count cap per request (default 8)
}

export const SECOND_LOOK_PER_TERM_DEFAULT = 50;
export const SECOND_LOOK_SWEEP_DEFAULT = 200;
const MAX_HYPOTHESES_DEFAULT = 6;
const MAX_QUESTIONS_DEFAULT = 6;
const MAX_CONNECTIVE_IOCS_DEFAULT = 5;
const MAX_MODEL_DEFAULT = 5;
const MAX_KEYWORDS_DEFAULT = 8;

// Common prose words that appear in an expectedOutcome ("an archive written shortly before an outbound
// transfer") but carry no search signal. Kept deliberately small — only words that would otherwise
// match half the timeline. Case-folded before lookup.
const STOPWORDS = new Set([
  "the", "and", "for", "with", "that", "this", "from", "into", "onto", "was", "were", "would", "could",
  "should", "have", "has", "had", "been", "being", "will", "shall", "may", "might", "before", "after",
  "shortly", "then", "than", "also", "when", "where", "which", "what", "whom", "whose", "there", "here",
  "outbound", "inbound", "transfer", "activity", "evidence", "shows", "show", "showing", "confirm",
  "confirms", "confirmed", "prove", "proves", "disprove", "indicat", "indicate", "indicates", "logs",
  "log", "event", "events", "host", "hosts", "user", "users", "account", "accounts", "file", "files",
  "malicious", "attacker", "collect", "collected", "check", "checks", "look", "looking", "written",
  "write", "writes", "access", "click", "clicked", "session", "process", "processes", "command",
  "commands", "network", "connection", "connections", "around", "first", "last", "same", "other",
  "still", "unknown", "gateway", "proxy", "server", "servers", "client", "clients", "system", "systems",
]);

// Extract SPECIFIC identifier-like tokens from prose: hostnames, filenames, paths, IPs, domains,
// process/command names — the things worth searching the raw record for. A token qualifies when it
// carries structure (a dot/slash/backslash/colon or a digit — i.e. it looks like a name/path/address)
// OR it is a reasonably long word that is not a generic stopword. Lowercased + deduped, bounded.
export function extractSignalTokens(text: string | undefined, max = MAX_KEYWORDS_DEFAULT): string[] {
  const raw = String(text ?? "");
  const out: string[] = [];
  const seen = new Set<string>();
  // Optional leading dot so a bare file extension (".zip", ".7z") survives as a searchable token.
  const matches = raw.match(/\.?[A-Za-z0-9][A-Za-z0-9._\-\\/:]{2,}/g) ?? [];
  for (const m of matches) {
    const tok = m.toLowerCase().replace(/[.,:;]+$/, ""); // strip trailing sentence punctuation
    if (tok.length < 3) continue;
    const structured = /[./\\:]/.test(tok) || /\d/.test(tok);
    if (!structured) {
      if (tok.length < 5) continue;          // short bare words are too noisy
      if (STOPWORDS.has(tok)) continue;
    }
    if (seen.has(tok)) continue;
    seen.add(tok);
    out.push(tok);
    if (out.length >= max) break;
  }
  return out;
}

function cleanKeywords(values: readonly (string | undefined)[], max: number): string[] {
  const out: string[] = [];
  const seen = new Set<string>();
  for (const v of values) {
    const tok = String(v ?? "").trim().toLowerCase();
    if (!tok || seen.has(tok)) continue;
    seen.add(tok);
    out.push(tok);
    if (out.length >= max) break;
  }
  return out;
}

// Signature that makes two requests with the same effective search identical, so we don't sweep the
// same terms twice from different sources (a hypothesis and a question can both point at "nfs-01").
function requestSignature(r: SecondLookRequest): string {
  return `${(r.host ?? "").toLowerCase()}|${r.from ?? ""}|${r.to ?? ""}|${[...r.keywords].sort().join(",")}`;
}

export interface BuildRequestsInput {
  hypotheses?: readonly Hypothesis[];
  iocValueById?: ReadonlyMap<string, string>;   // ioc id → value, to resolve a hypothesis's relatedIocIds
  keyQuestions?: readonly InvestigationQuestion[];
  connectiveIocs?: readonly IocAnchor[];
  modelRequests?: readonly ModelEvidenceRequest[];
  window?: { from?: string; to?: string };      // the case's active window (scope or derived)
  caps?: SecondLookCaps;
}

// Assemble the deterministic + model-issued search requests. Deterministic sources are mined from the
// OPEN questions of the investigation; each request is scoped to the active window unless a model
// request overrides it. Deduped by effective signature; requests with no keywords are dropped.
export function buildSecondLookRequests(input: BuildRequestsInput): SecondLookRequest[] {
  const caps = input.caps ?? {};
  const maxKw = caps.maxKeywordsPerRequest ?? MAX_KEYWORDS_DEFAULT;
  const win = input.window ?? {};
  const out: SecondLookRequest[] = [];
  const seen = new Set<string>();

  const push = (r: SecondLookRequest): void => {
    if (!r.keywords.length) return;
    const sig = requestSignature(r);
    if (seen.has(sig)) return;
    seen.add(sig);
    out.push(r);
  };

  // (a) Open hypotheses → their IOC values + signal tokens from title/expectedOutcome.
  const open = (input.hypotheses ?? []).filter((h) => h.status === "open");
  open.slice(0, caps.maxHypotheses ?? MAX_HYPOTHESES_DEFAULT).forEach((h, i) => {
    const iocValues = (h.relatedIocIds ?? [])
      .map((id) => input.iocValueById?.get(id))
      .filter((v): v is string => !!v);
    const tokens = [...extractSignalTokens(h.title, maxKw), ...extractSignalTokens(h.expectedOutcome, maxKw)];
    const keywords = cleanKeywords([...iocValues, ...tokens], maxKw);
    push({
      source: "hypothesis",
      tag: `[second-look: h${i + 1}]`,
      label: `hypothesis: ${h.title}`.slice(0, 160),
      keywords,
      from: win.from,
      to: win.to,
      reason: h.expectedOutcome?.trim() || h.title,
    });
  });

  // (b) Unknown/partial key questions that carry a structured collect target.
  const openQ = (input.keyQuestions ?? []).filter(
    (q) => (q.status === "unknown" || q.status === "partial") && q.collect,
  );
  openQ.slice(0, caps.maxQuestions ?? MAX_QUESTIONS_DEFAULT).forEach((q, i) => {
    const c = q.collect!;
    const keywords = cleanKeywords(
      [
        ...extractSignalTokens(c.artifact, maxKw),
        ...extractSignalTokens(c.logSource, maxKw),
        ...extractSignalTokens(c.expectedOutcome, maxKw),
        ...extractSignalTokens(q.question, maxKw),
      ],
      maxKw,
    );
    push({
      source: "question",
      tag: `[second-look: q${i + 1}]`,
      label: `question: ${q.question}`.slice(0, 160),
      keywords,
      host: c.host ? shortHost(c.host) : undefined,
      from: win.from,
      to: win.to,
      reason: c.expectedOutcome?.trim() || q.question,
    });
  });

  // (c) Top connective IOCs — the backbone indicators; search the raw record for every mention.
  (input.connectiveIocs ?? []).slice(0, caps.maxConnectiveIocs ?? MAX_CONNECTIVE_IOCS_DEFAULT).forEach((a) => {
    const keywords = cleanKeywords([a.value], maxKw);
    push({
      source: "connective-ioc",
      tag: `[second-look: ${a.value.slice(0, 40)}]`,
      label: `connective indicator: ${a.value}`.slice(0, 160),
      keywords,
      from: win.from,
      to: win.to,
      reason: `every raw mention of the connective indicator ${a.value}`,
    });
  });

  // (d) Model-issued evidence requests — data the model knows it was not shown. Its own timeWindow
  // (when given) overrides the active window; otherwise it inherits it.
  (input.modelRequests ?? []).slice(0, caps.maxModel ?? MAX_MODEL_DEFAULT).forEach((m, i) => {
    const keywords = cleanKeywords(m.keywords ?? [], maxKw);
    push({
      source: "model",
      tag: `[second-look: model${i + 1}]`,
      label: `model request: ${(m.reason || keywords.join(", ")).slice(0, 140)}`,
      keywords,
      host: m.host ? shortHost(m.host) : undefined,
      from: m.timeWindow?.from ?? win.from,
      to: m.timeWindow?.to ?? win.to,
      reason: m.reason?.trim() || `evidence the model requested (${keywords.join(", ")})`,
    });
  });

  return out;
}

// Combine an event's searchable fields into one lowercased haystack (broader than searchFilter's
// eventMatchesSearch — includes message/path/process names/artifact, which carry recon/exfil signal).
function eventHaystack(e: ForensicEvent): string {
  return [
    e.description, e.message, e.asset, e.path, e.processName, e.parentName, e.artifactName,
    ...(e.sources ?? []), ...(e.mitreTechniques ?? []),
  ]
    .filter(Boolean)
    .join("  ")
    .toLowerCase();
}

function inWindow(e: ForensicEvent, from: string | undefined, to: string | undefined): boolean {
  const t = Date.parse(e.timestamp);
  if (Number.isNaN(t)) return true;                 // undated kept — can't be proven out of range
  if (from) { const f = Date.parse(from); if (!Number.isNaN(f) && t < f) return false; }
  if (to) { const u = Date.parse(to); if (!Number.isNaN(u) && t > u) return false; }
  return true;
}

function hostMatches(e: ForensicEvent, host: string | undefined): boolean {
  if (!host) return true;
  if (!e.asset) return false;
  return shortHost(e.asset).toLowerCase() === host.toLowerCase();
}

// Resolve each request against the candidate pool (the omitted scoped events + the super-timeline
// within the window). matchedEventIds records EVERY hit (so a request that only re-finds events already
// in the timeline is counted as satisfied, not a lead); promotable is the subset whose ids are NOT yet
// in the analyzed timeline — the genuine recall gain. Per-request matches are capped and time-ordered.
export function resolveSecondLookRequests(
  requests: readonly SecondLookRequest[],
  candidates: readonly ForensicEvent[],
  forensicEventIds: ReadonlySet<string>,
  caps: SecondLookCaps = {},
): SecondLookResolution[] {
  const perTerm = caps.perTerm ?? SECOND_LOOK_PER_TERM_DEFAULT;
  // Precompute haystacks once — a sweep can scan tens of thousands of raw rows per request.
  const hay = new Map<string, string>();
  const ms = (e: ForensicEvent): number => { const t = Date.parse(e.timestamp); return Number.isNaN(t) ? Infinity : t; };
  return requests.map((request) => {
    const matched: ForensicEvent[] = [];
    for (const e of candidates) {
      if (!inWindow(e, request.from, request.to)) continue;
      if (!hostMatches(e, request.host)) continue;
      let h = hay.get(e.id);
      if (h === undefined) { h = eventHaystack(e); hay.set(e.id, h); }
      if (!request.keywords.some((k) => h!.includes(k))) continue;
      matched.push(e);
    }
    // Undated rows sort last (Infinity) so a capped request keeps the dated, placeable evidence first.
    matched.sort((a, b) => ms(a) - ms(b));
    const capped = matched.slice(0, perTerm);
    return {
      request,
      matchedEventIds: capped.map((e) => e.id),
      promotable: capped.filter((e) => !forensicEventIds.has(e.id)),
    };
  });
}

// Turn resolutions into the final promotion plan: dedupe promotable events across requests (an event
// pulled by two requests carries both provenance tags), enforce the sweep cap, and collect the
// zero-match requests as collection leads. Deterministic — request order drives which events win the
// budget, and the first request to claim an event owns its position.
export function buildSecondLookPlan(
  resolutions: readonly SecondLookResolution[],
  caps: SecondLookCaps = {},
): SecondLookPlan {
  const sweep = caps.sweep ?? SECOND_LOOK_SWEEP_DEFAULT;
  const promotions: ForensicEvent[] = [];
  const tagById: Record<string, string[]> = {};
  const index = new Map<string, number>(); // event id → position in promotions
  let truncated = false;

  for (const res of resolutions) {
    for (const e of res.promotable) {
      if (!(e.id in tagById)) {
        if (promotions.length >= sweep) { truncated = true; continue; }
        index.set(e.id, promotions.length);
        promotions.push(e);
        tagById[e.id] = [res.request.tag];
      } else if (!tagById[e.id].includes(res.request.tag)) {
        tagById[e.id].push(res.request.tag);
      }
    }
  }

  const leads = resolutions.filter((r) => r.matchedEventIds.length === 0).map((r) => r.request);
  return { promotions, tagById, resolutions: [...resolutions], leads, truncated };
}

// Compact per-request promotion counts, for the human summary. e.g. "h2 (rsync, nfs-01) +42".
function requestTally(res: SecondLookResolution): string {
  const idTag = res.request.tag.replace(/^\[second-look:\s*/, "").replace(/\]$/, "");
  const kw = res.request.keywords.slice(0, 3).join(", ");
  return `${idTag}${kw ? ` (${kw})` : ""} +${res.promotable.length}`;
}

// One-line summary for the synth-meta card. Mirrors the roadmap's example phrasing:
// "second look: 42 raw events matching hypothesis h2 (rsync, nfs-01) promoted — conclusions updated."
export function summarizeSecondLook(plan: SecondLookPlan): string {
  const promoted = plan.promotions.length;
  if (!promoted) {
    if (plan.leads.length) {
      return `second look: 0 new events; ${plan.leads.length} request(s) matched nothing — collection lead(s) surfaced`;
    }
    return "second look: nothing new to promote";
  }
  const tallies = plan.resolutions
    .filter((r) => r.promotable.length > 0)
    .map(requestTally)
    .slice(0, 5)
    .join("; ");
  const more = plan.truncated ? " (sweep cap reached)" : "";
  return `second look: ${promoted} raw event(s) promoted — ${tallies}${more} — conclusions updated`;
}

// Derive the active window from a set of events when the case has no explicit scope: the earliest and
// latest DATED event. Returns {} when nothing is dated (no bound is better than a wrong bound).
export function deriveWindow(events: readonly ForensicEvent[]): { from?: string; to?: string } {
  let min = Infinity;
  let max = -Infinity;
  for (const e of events) {
    const t = Date.parse(e.timestamp);
    if (Number.isNaN(t)) continue;
    if (t < min) min = t;
    if (t > max) max = t;
  }
  if (!Number.isFinite(min) || !Number.isFinite(max)) return {};
  return { from: new Date(min).toISOString(), to: new Date(max).toISOString() };
}
