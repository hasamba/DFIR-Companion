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
// request, per normalized shape and per sweep, and only events NOT already in the analyzed timeline are
// promotable (re-promoting an event already present is a no-op that must never inflate the count).
//
// Every cap here exists to bound WHAT ENTERS THE FORENSIC RECORD — the record the super-timeline
// boundary protects — not to ration a budget that ought to be spent in full. Two measurements on a real
// case set their shape (#1554): the sweep promoted 265 rows and only 15 of the case's 42 findings cited
// any of them, so promoting MORE is not the goal; and those 265 rows carried only 160 distinct shapes,
// so 105 of them were near-duplicates of a row already promoted. The budget is therefore spent
// round-robin, a little to every open request, rather than first-come — coverage, not volume. No
// scoring and no model ranks anything here: relevance ranking was tried and rejected (#1553).

import type { ForensicEvent, InvestigationQuestion } from "./stateTypes.js";
import type { Hypothesis } from "./hypothesis.js";
import type { IocAnchor } from "./iocAnchors.js";
import { shortHost } from "./iocAnchors.js";
import { patternKey } from "./prevalence.js";

// A single concrete search issued by the second-look sweep. `keywords` are matched case-insensitively
// (ANY keyword hits) across the event's searchable fields, optionally restricted to `host` and the
// [from,to] window. `tag` is the provenance stamp written onto every event this request promotes so the
// forensic timeline shows WHY the row was pulled up; `reason` becomes a collection lead when nothing
// matched anywhere.
export interface SecondLookRequest {
  source: "hypothesis" | "question" | "connective-ioc" | "model";
  tag: string; // e.g. "[second-look: h2]"
  label: string; // human summary of what this request looked for
  keywords: string[]; // lowercased, deduped, non-empty
  host?: string; // optional host restriction (matched against shortHost of event.asset)
  from?: string; // ISO lower bound (inclusive); undated events are kept
  to?: string; // ISO upper bound (inclusive)
  reason: string; // surfaced as a collection lead when matchedEventIds is empty
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
  // Answers ONE question: did this request find anything at all in the raw record? It therefore still
  // counts hits that are ALREADY in the forensic timeline — a request whose every hit is already
  // analyzed found its evidence; it is satisfied, not a blind spot. Never read as a promotion count.
  matchedEventIds: string[];
  promotable: ForensicEvent[]; // matched events NOT already in the analyzed timeline (the real gain)
}

export interface SecondLookPlan {
  promotions: ForensicEvent[]; // deduped across requests + capped to the sweep budget
  tagById: Record<string, string[]>; // event id → provenance tags to stamp on promotion
  resolutions: SecondLookResolution[];
  leads: SecondLookRequest[]; // requests that matched nothing anywhere — collection leads
  truncated: boolean; // true when the sweep cap dropped some promotable events
  shapeCapped: number; // rows withheld because their normalized shape had already had its turn
}

export interface SecondLookCaps {
  perTerm?: number; // max events one request may offer the sweep (default 12)
  sweep?: number; // max events promoted across the whole sweep (default 200)
  perShape?: number; // max rows of one normalized shape one sweep promotes (default 3)
  maxHypotheses?: number; // open hypotheses turned into requests (default 6)
  maxQuestions?: number; // unknown/partial collect-bearing questions → requests (default 6)
  maxConnectiveIocs?: number; // top connective IOCs → requests (default 5)
  maxModel?: number; // model evidenceRequests honored (default 5)
  maxKeywordsPerRequest?: number; // keyword count cap per request (default 8)
}

// The per-request allowance. It bounds what ENTERS THE FORENSIC RECORD from one search; it is not a
// ration of a budget to be spent in full. Measured on a real case: the six open questions matched 266,
// 51, 1308, 244, 148 and 259 archive rows, so an allowance of 50 would have let four questions write
// 200 rows — a 7x rise in second-look inflow — while "privilege escalation" alone matched the ENTIRE
// 1308-row archive, where taking 50 is sampling noise, not evidence selection. 12 sits just above the
// equal share of the sweep budget (200 / the module's 22 possible requests ≈ 9), so a sweep with few
// live questions still gets depth, and no single request can claim more than 6% of the sweep.
export const SECOND_LOOK_PER_TERM_DEFAULT = 12;
export const SECOND_LOOK_SWEEP_DEFAULT = 200;
// Rows of one normalized shape (same fingerprint, same severity, same host) one sweep may promote.
// Measured: 265 promoted rows carried only 160 distinct shapes — one Sigma rule accounted for 38 of
// them — so 105 near-duplicates spent the sweep budget. 3 is deliberately one below synthGroup's
// DEFAULT_GROUP_MIN_REPEATS (4), the count this repo already judges too small to be worth collapsing.
export const SECOND_LOOK_PER_SHAPE_DEFAULT = 3;
const MAX_HYPOTHESES_DEFAULT = 6;
const MAX_QUESTIONS_DEFAULT = 6;
const MAX_CONNECTIVE_IOCS_DEFAULT = 5;
const MAX_MODEL_DEFAULT = 5;
const MAX_KEYWORDS_DEFAULT = 8;

// Common prose words that appear in an expectedOutcome ("an archive written shortly before an outbound
// transfer") but carry no search signal. Kept deliberately small — only words that would otherwise
// match half the timeline. Case-folded before lookup.
const STOPWORDS = new Set([
  "the",
  "and",
  "for",
  "with",
  "that",
  "this",
  "from",
  "into",
  "onto",
  "was",
  "were",
  "would",
  "could",
  "should",
  "have",
  "has",
  "had",
  "been",
  "being",
  "will",
  "shall",
  "may",
  "might",
  "before",
  "after",
  "shortly",
  "then",
  "than",
  "also",
  "when",
  "where",
  "which",
  "what",
  "whom",
  "whose",
  "there",
  "here",
  "outbound",
  "inbound",
  "transfer",
  "activity",
  "evidence",
  "shows",
  "show",
  "showing",
  "confirm",
  "confirms",
  "confirmed",
  "prove",
  "proves",
  "disprove",
  "indicat",
  "indicate",
  "indicates",
  "logs",
  "log",
  "event",
  "events",
  "host",
  "hosts",
  "user",
  "users",
  "account",
  "accounts",
  "file",
  "files",
  "malicious",
  "attacker",
  "collect",
  "collected",
  "check",
  "checks",
  "look",
  "looking",
  "written",
  "write",
  "writes",
  "access",
  "click",
  "clicked",
  "session",
  "process",
  "processes",
  "command",
  "commands",
  "network",
  "connection",
  "connections",
  "around",
  "first",
  "last",
  "same",
  "other",
  "still",
  "unknown",
  "gateway",
  "proxy",
  "server",
  "servers",
  "client",
  "clients",
  "system",
  "systems",
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
      if (tok.length < 5) continue; // short bare words are too noisy
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
    const tok = String(v ?? "")
      .trim()
      .toLowerCase();
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
  iocValueById?: ReadonlyMap<string, string>; // ioc id → value, to resolve a hypothesis's relatedIocIds
  keyQuestions?: readonly InvestigationQuestion[];
  connectiveIocs?: readonly IocAnchor[];
  modelRequests?: readonly ModelEvidenceRequest[];
  window?: { from?: string; to?: string }; // the case's active window (scope or derived)
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
  (input.connectiveIocs ?? [])
    .slice(0, caps.maxConnectiveIocs ?? MAX_CONNECTIVE_IOCS_DEFAULT)
    .forEach((a) => {
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
    e.description,
    e.message,
    e.asset,
    e.path,
    e.processName,
    e.parentName,
    e.artifactName,
    ...(e.sources ?? []),
    ...(e.mitreTechniques ?? []),
  ]
    .filter(Boolean)
    .join("  ")
    .toLowerCase();
}

function inWindow(e: ForensicEvent, from: string | undefined, to: string | undefined): boolean {
  const t = Date.parse(e.timestamp);
  if (Number.isNaN(t)) return true; // undated kept — can't be proven out of range
  if (from) {
    const f = Date.parse(from);
    if (!Number.isNaN(f) && t < f) return false;
  }
  if (to) {
    const u = Date.parse(to);
    if (!Number.isNaN(u) && t > u) return false;
  }
  return true;
}

function hostMatches(e: ForensicEvent, host: string | undefined): boolean {
  if (!host) return true;
  if (!e.asset) return false;
  return shortHost(e.asset).toLowerCase() === host.toLowerCase();
}

function eventMs(e: ForensicEvent): number {
  const t = Date.parse(e.timestamp);
  return Number.isNaN(t) ? Infinity : t;
}

// The bounded record of what this request hit. It holds the rows the allowance actually selected PLUS
// the hits that were already analyzed, because emptiness here is the SOLE trigger for a collection
// lead: a request that matched 200 rows the AI can already see must not be reported as "nothing was
// found", when something was found and is simply already in hand. Both halves are capped, so a request
// whose keywords match the whole archive cannot grow this list without limit.
function matchedIds(
  matched: readonly ForensicEvent[],
  selected: readonly ForensicEvent[],
  forensicEventIds: ReadonlySet<string>,
  perTerm: number,
): string[] {
  const chosen = new Set(selected.map((e) => e.id));
  const out: string[] = [];
  let analyzed = 0;
  for (const e of matched) {
    if (chosen.has(e.id)) {
      out.push(e.id);
      continue;
    }
    if (!forensicEventIds.has(e.id) || analyzed >= perTerm) continue;
    analyzed += 1;
    out.push(e.id);
  }
  return out;
}

function resolveOne(
  request: SecondLookRequest,
  candidates: readonly ForensicEvent[],
  forensicEventIds: ReadonlySet<string>,
  hay: Map<string, string>,
  perTerm: number,
): SecondLookResolution {
  const matched: ForensicEvent[] = [];
  for (const e of candidates) {
    if (!inWindow(e, request.from, request.to)) continue;
    if (!hostMatches(e, request.host)) continue;
    let h = hay.get(e.id);
    if (h === undefined) {
      h = eventHaystack(e);
      hay.set(e.id, h);
    }
    if (!request.keywords.some((k) => h.includes(k))) continue;
    matched.push(e);
  }
  // Undated rows sort last (Infinity), so a source with no usable timestamps is the first casualty of
  // the allowance. That is deliberate and it stays: the sweep exists to put evidence ON the forensic
  // timeline for a re-synthesis that reasons about sequence, and a row with no time cannot be placed
  // there or corroborate an ordering claim. Two things blunt the edge — the allowance is no longer
  // burned by already-analyzed rows, which is what used to exhaust it before any undated row was
  // reached, and an unpromoted row stays in the super-timeline for the analyst to search.
  matched.sort((a, b) => eventMs(a) - eventMs(b));
  // THE FIX (#1554): fill the allowance from rows that can actually be promoted. Capping first and
  // filtering second spent the allowance on rows already in the forensic timeline — re-promoting one
  // is a no-op — so on a real case three of six open questions promoted ZERO rows while unseen
  // evidence sat behind the cap.
  const promotable = matched.filter((e) => !forensicEventIds.has(e.id)).slice(0, perTerm);
  return { request, matchedEventIds: matchedIds(matched, promotable, forensicEventIds, perTerm), promotable };
}

// Resolve each request against the candidate pool (the omitted scoped events + the super-timeline
// within the window). `promotable` is the allowance: up to perTerm matched events, earliest first, that
// are NOT yet in the analyzed timeline — the genuine recall gain. `matchedEventIds` answers the
// separate, narrower question of whether the request found anything at all (see matchedIds).
export function resolveSecondLookRequests(
  requests: readonly SecondLookRequest[],
  candidates: readonly ForensicEvent[],
  forensicEventIds: ReadonlySet<string>,
  caps: SecondLookCaps = {},
): SecondLookResolution[] {
  const perTerm = caps.perTerm ?? SECOND_LOOK_PER_TERM_DEFAULT;
  // Precompute haystacks once — a sweep can scan tens of thousands of raw rows per request.
  const hay = new Map<string, string>();
  return requests.map((request) => resolveOne(request, candidates, forensicEventIds, hay, perTerm));
}

// The normalized SHAPE of a row, for the per-shape cap. Reuses prevalence.patternKey — the case-wide
// fingerprint that already folds digits, paths, GUIDs and quoted strings to placeholders, and that the
// prevalence baseline and the synthesis burst grouping both key on — rather than inventing a second
// normalizer. A content hash wins inside it, so two distinct binaries matched by one rule never merge.
//
// Severity and host join the key. synthGroup groups ACROSS hosts on purpose, but it keeps the row and
// spells the host spread out on the rendered line; here a capped row is simply absent, so folding hosts
// together would let one noisy endpoint's repetition erase another endpoint's first occurrence — the
// lateral-movement signal. A row with no stable fingerprint returns "" and is never capped: no shape,
// no claim of redundancy.
function promotionShapeKey(e: ForensicEvent): string {
  const pattern = patternKey(e);
  if (!pattern) return "";
  return `${e.severity}|${pattern}|${(e.asset ?? "").trim().toLowerCase()}`;
}

interface SweepState {
  promotions: ForensicEvent[];
  tagById: Record<string, string[]>;
  shapeCount: Map<string, number>; // shape key → rows of that shape already promoted this sweep
  withheld: Set<string>; // distinct rows the shape cap held back (reported to the analyst)
  truncated: boolean;
}

// One request's turn in the round-robin. It advances the request's cursor until the request has
// contributed exactly one row, and returns the new cursor.
//
//   * A row an earlier request already claimed SPENDS the turn — the row is in the plan and now carries
//     this request's tag too, so the request was served.
//   * A row the shape cap withholds does NOT spend the turn — it contributed nothing, and letting one
//     repeated Sigma hit eat a question's whole share is exactly what fix B exists to stop.
//   * A row that needs a slot when the sweep budget is gone ends the sweep and marks it truncated.
function spendTurn(
  res: SecondLookResolution,
  from: number,
  state: SweepState,
  caps: Required<Pick<SecondLookCaps, "sweep" | "perShape">>,
): number {
  for (let i = from; i < res.promotable.length; i += 1) {
    const e = res.promotable[i];
    const tags = state.tagById[e.id];
    if (tags) {
      if (!tags.includes(res.request.tag)) tags.push(res.request.tag);
      return i + 1;
    }
    const shape = promotionShapeKey(e);
    const used = shape ? (state.shapeCount.get(shape) ?? 0) : 0;
    if (shape && used >= caps.perShape) {
      state.withheld.add(e.id);
      continue;
    }
    if (state.promotions.length >= caps.sweep) {
      state.truncated = true;
      return i;
    }
    state.promotions.push(e);
    state.tagById[e.id] = [res.request.tag];
    if (shape) state.shapeCount.set(shape, used + 1);
    return i + 1;
  }
  return res.promotable.length;
}

// Turn resolutions into the final promotion plan: spend the sweep budget ROUND-ROBIN across requests,
// dedupe promoted events (an event pulled by two requests carries both provenance tags), cap repeats of
// one normalized shape, and collect the zero-match requests as collection leads.
//
// Round-robin, not first-come: the goal is COVERAGE, not volume. Taking each request's rows in order
// let the first requests take the whole budget, and the model's own "I was not shown this" requests are
// built LAST, so they starved first. Every request now gets a turn before any request gets a second row.
//
// Deterministic: request order decides who moves first in each round, and the first request to claim an
// event owns its position.
export function buildSecondLookPlan(
  resolutions: readonly SecondLookResolution[],
  caps: SecondLookCaps = {},
): SecondLookPlan {
  const limits = {
    sweep: caps.sweep ?? SECOND_LOOK_SWEEP_DEFAULT,
    perShape: caps.perShape ?? SECOND_LOOK_PER_SHAPE_DEFAULT,
  };
  const state: SweepState = {
    promotions: [],
    tagById: {},
    shapeCount: new Map(),
    withheld: new Set(),
    truncated: false,
  };
  const cursor = resolutions.map(() => 0);

  let spending = true;
  while (spending && !state.truncated) {
    spending = false;
    for (let i = 0; i < resolutions.length; i += 1) {
      if (cursor[i] >= resolutions[i].promotable.length) continue;
      cursor[i] = spendTurn(resolutions[i], cursor[i], state, limits);
      if (state.truncated) break;
      if (cursor[i] < resolutions[i].promotable.length) spending = true;
    }
  }

  const leads = resolutions.filter((r) => r.matchedEventIds.length === 0).map((r) => r.request);
  return {
    promotions: state.promotions,
    tagById: state.tagById,
    resolutions: [...resolutions],
    leads,
    truncated: state.truncated,
    shapeCapped: state.withheld.size,
  };
}

// How many rows each request actually put on the forensic timeline, from the plan's own tags — NOT from
// promotable.length, which is what the request OFFERED before the sweep cap and the shape cap had their
// say. The summary sentence says "promoted", so the tally has to mean promoted.
function promotedByTag(plan: SecondLookPlan): Map<string, number> {
  const counts = new Map<string, number>();
  for (const e of plan.promotions) {
    for (const tag of plan.tagById[e.id] ?? []) counts.set(tag, (counts.get(tag) ?? 0) + 1);
  }
  return counts;
}

// Compact per-request promotion counts, for the human summary. e.g. "h2 (rsync, nfs-01) +42".
function requestTally(res: SecondLookResolution, promoted: number): string {
  const idTag = res.request.tag.replace(/^\[second-look:\s*/, "").replace(/\]$/, "");
  const kw = res.request.keywords.slice(0, 3).join(", ");
  return `${idTag}${kw ? ` (${kw})` : ""} +${promoted}`;
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
  const counts = promotedByTag(plan);
  const tallies = plan.resolutions
    .filter((r) => (counts.get(r.request.tag) ?? 0) > 0)
    .map((r) => requestTally(r, counts.get(r.request.tag) ?? 0))
    .slice(0, 5)
    .join("; ");
  const more = plan.truncated ? " (sweep cap reached)" : "";
  // The analyst is entitled to know a row was held back, not just the model (#452's disclosure rule in
  // spirit). "Held back" is the exact word: the row was never deleted — it stays in the super-timeline,
  // searchable and promotable by hand, which is what makes capping the forensic record safe at all.
  const held = plan.shapeCapped
    ? ` — ${plan.shapeCapped} repeat row(s) of an already-promoted detection held back (still in the super-timeline)`
    : "";
  return `second look: ${promoted} raw event(s) promoted — ${tallies}${more}${held} — conclusions updated`;
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
