import { z } from "zod";
import {
  SEVERITY_RANK,
  type Finding,
  type ForensicEvent,
  type InvestigationState,
  type Severity,
  type Technique,
} from "./stateTypes.js";
import {
  matchKey,
  norm,
  overlappingFinding,
  pairByOverlap,
  resolveDecisionTargets,
} from "./secondOpinionTargets.js";
import { heldForAnalyst } from "./secondOpinionGuard.js";
import { byEventTime } from "./forensicSort.js";
import { renderEventLine } from "./ai/eventLine.js";
import { stateEventResolver } from "./eventAliasLookup.js";
import { rejectedTechniqueIds, withRejectedTechniqueIds } from "./rejectedTechniques.js";
import { projectScope } from "./scopeProject.js";
import type { ScopeWindow } from "./scope.js";

// Second LLM opinion (issue #116). A QA control: a DIFFERENT model independently re-synthesizes
// the same case, and we surface where it disagrees with the primary synthesis so the analyst can
// adjudicate before finalizing a report. This module is PURE (no I/O, no AI) — it computes the
// deterministic delta set between the two analyses, shapes the reconcile prompt, merges the
// reconcile AI's per-delta verdicts, and applies the analyst's accepted deltas back onto the case.
//
// Findings are DERIVED in this architecture (synthesis rewrites them), so an accepted delta is made
// durable by re-applying it via `applyAcceptedSecondOpinion` — used by BOTH the apply route and
// synthesize()'s post-processing, so an accepted model-B call never silently regresses.

export type SecondOpinionDeltaKind = "b_only" | "a_only" | "severity" | "mitre_added" | "mitre_removed";
export type DeltaStatus = "pending" | "accepted" | "rejected";
export type DeltaRecommendation = "accept_b" | "keep_a" | "review";

export interface SecondOpinionDelta {
  id: string; // stable across runs: `${kind}:${slug(semanticKey|title|techniqueId)}` (#69)
  kind: SecondOpinionDeltaKind;
  title: string; // finding title, or the ATT&CK technique id for mitre_* deltas
  aSeverity?: Severity; // severity/ a_only: model A's severity
  bSeverity?: Severity; // severity / b_only: model B's severity
  finding?: Finding; // b_only: B's finding (merged on accept); a_only/severity: A's finding (edited in place)
  bFinding?: Finding; // severity: B's copy, so the referee sees BOTH sides' cited events (#1466)
  techniqueName?: string; // mitre_added: the technique name, so accept can add a labelled Technique
  rationale: string; // one-line reconcile-AI judgement (default "")
  recommendation: DeltaRecommendation; // reconcile-AI suggestion (default "review")
  status: DeltaStatus; // pending | accepted | rejected
  // #1590 — set on an accepted decision carried into a newer run: the run it was first accepted in.
  carriedFrom?: string;
  // #1590 — response-only, never stored: this accepted decision matches no finding right now.
  unapplied?: UnappliedReason;
  // #1596 — set only on a fresh, pending A-only delta the referee proposed to dismiss: why the
  // dismissal is left for the analyst. No bulk action accepts a delta that carries one.
  refereeFlags?: RefereeFlag[];
}

// "answers_open_item": the finding is the last one that bears on an open thread or an unresolved /
// negative answer. "unquoted_reason": the reason quotes nothing from the cited events.
// "unreadable": a stored flag that failed to parse — kept as a hold, never dropped (fail safe).
export type RefereeFlag =
  | {
      kind: "answers_open_item";
      itemId: string;
      itemKind: "thread" | "question" | "negative";
      text: string;
    }
  | { kind: "unquoted_reason" }
  | { kind: "unreadable" };

// "missing": no finding has its id or key any more. "changed": its id now holds a different claim.
export type UnappliedReason = "missing" | "changed";

export interface SecondOpinion {
  generatedAt: string;
  modelA: string; // primary synthesis model label
  modelB: string; // second-opinion model label
  referee: string; // label of the model that wrote the verdicts (#1466); "" when no reconcile pass ran
  summary: string; // reconcile-AI overall assessment (default "")
  agreementCount: number; // findings BOTH models share (by matchKey — semanticKey or title)
  deltas: SecondOpinionDelta[];
  // #1587 — the LAST referee attempt failed. Without it a failed pass saved a record identical to a
  // referee that chose to say nothing, and the reason reached only the server log.
  refereeError?: RefereeError;
  // The exact user prompt the failed attempt was given, kept only while `refereeError` is set, so a
  // referee-only re-run judges the same summaries and cited events instead of today's timeline.
  refereePrompt?: string;
}

export interface RefereeError {
  referee: string; // label of the referee that was tried
  message: string; // flattened, capped provider error
  at: string; // ISO time of the failed attempt
}

// The cross-run finding key (semanticKey, else derived — issue #69) and the title normalizer live in
// secondOpinionTargets.ts, which also resolves an accepted decision to its finding by id (#1590).

// URL/id-safe slug for a stable delta id. Collapses runs of non-alphanumerics to single dashes.
function slug(text: string): string {
  return (
    String(text)
      .trim()
      .toLowerCase()
      .replace(/[^a-z0-9]+/g, "-")
      .replace(/^-+|-+$/g, "") || "x"
  );
}

// A cross-run finding index. A counterpart is matched by semanticKey FIRST (so a reworded title with
// the same technique+phrase collapses to one finding — the #69 fix) and by normalized title as a
// fallback (so a same-title finding stays matched even when the two runs mapped it to different
// dominant techniques — that divergence surfaces separately as mitre deltas, not as finding noise).
// The side's own list is de-duped by matchKey (first wins), mirroring the previous byTitle behavior.
interface FindingIndex {
  all: readonly Finding[]; // de-duped findings (first per matchKey)
  match: (f: Finding) => Finding | undefined; // this side's counterpart to `f`, by semanticKey then title
}

function indexFindings(findings: readonly Finding[]): FindingIndex {
  const all: Finding[] = [];
  const seen = new Set<string>();
  const bySem = new Map<string, Finding>();
  const byTitle = new Map<string, Finding>();
  for (const f of findings) {
    // Key on the DERIVED matchKey, not the stored `semanticKey` field: model B's second-opinion
    // findings are a dry-run synthesis that never persisted through grounding, so they carry no
    // stored key. Deriving it here is what lets B's differently-worded findings match A's by
    // semanticKey at all (#69) — indexing on the stored field silently disabled that.
    const key = matchKey(f);
    if (!key || seen.has(key)) continue;
    seen.add(key);
    all.push(f);
    if (!bySem.has(key)) bySem.set(key, f);
    const t = norm(f.title);
    if (t && !byTitle.has(t)) byTitle.set(t, f);
  }
  const match = (f: Finding): Finding | undefined => {
    const hit = bySem.get(matchKey(f));
    if (hit) return hit;
    const t = norm(f.title);
    return t ? byTitle.get(t) : undefined;
  };
  return { all, match };
}

// Compute the deterministic delta set between model A (primary, saved) and model B (second opinion).
// b_only: B raised a finding A missed; a_only: A has a finding B dropped; severity: matched finding,
// different severity; mitre_added/removed: ATT&CK techniques present on one side only (by id).
// `scope` is the case's time window: only in-scope findings count toward a technique mapping.
export function buildSecondOpinionDeltas(
  a: InvestigationState,
  b: InvestigationState,
  scope?: ScopeWindow,
): SecondOpinionDelta[] {
  const { aAll, bAll, counterpart } = pairFindings(a, b);
  const deltas: SecondOpinionDelta[] = [];
  const matchedA = new Set<Finding>();

  for (const bf of bAll) {
    const af = counterpart.get(bf);
    if (!af) {
      deltas.push(delta("b_only", matchKey(bf), bf.title, { finding: bf, bSeverity: bf.severity }));
    } else if (!matchedA.has(af)) {
      matchedA.add(af); // one delta per A finding — a second B finding mapping to it agrees, no delta
      if (af.severity !== bf.severity) {
        deltas.push(
          delta("severity", matchKey(af), af.title, {
            finding: af,
            bFinding: bf,
            aSeverity: af.severity,
            bSeverity: bf.severity,
          }),
        );
      }
    }
  }
  for (const af of aAll) {
    if (!matchedA.has(af))
      deltas.push(delta("a_only", matchKey(af), af.title, { finding: af, aSeverity: af.severity }));
  }

  // The side that maps a technique is read from its TABLE, which is what accepting the delta acts
  // on. The side that "does not" is read from its table AND its live findings' tags (#1757): a model
  // can tag a finding and leave the id out of its top-level list, and then "Model B does not map
  // this technique" was false and the referee was asked to settle a disagreement nobody had.
  const aMapped = mappedTechniques(a, scope);
  const bMapped = mappedTechniques(b, scope);
  const aTech = new Map(a.mitreTechniques.map((t) => [t.id, t]));
  const bTech = new Map(b.mitreTechniques.map((t) => [t.id, t]));
  for (const [id, t] of bTech) {
    if (!aMapped.has(id)) deltas.push(delta("mitre_added", id, id, { techniqueName: t.name }));
  }
  for (const [id, t] of aTech) {
    if (!bMapped.has(id)) deltas.push(delta("mitre_removed", id, id, { techniqueName: t.name }));
  }
  return deltas;
}

// The findings that are a model's current claims: not dismissed (by the analyst or an accepted
// second-opinion decision), and inside the scope window. Model A's saved case re-attaches
// deterministic findings backed only by out-of-window events (carryOutOfWindowFindings); model B's
// dry run never gets them, so without the projection one could hide B's in-scope technique.
function liveFindings(s: InvestigationState, scope?: ScopeWindow): Finding[] {
  const visible = scope ? projectScope(s, scope).findings : s.findings;
  return visible.filter((f) => f.status !== "dismissed");
}

// Every technique id a model maps: its table plus its live findings' tags. Exact ids — a
// sub-technique does not map its parent, nor the reverse.
function mappedTechniques(s: InvestigationState, scope?: ScopeWindow): Set<string> {
  return new Set([
    ...s.mitreTechniques.map((t) => t.id),
    ...liveFindings(s, scope).flatMap((f) => f.mitreTechniques),
  ]);
}

// `keyBasis` is the STABLE identity the delta id is slugged from — a finding's matchKey (semanticKey
// or normalized title) or, for mitre deltas, the technique id. Keying the id off semanticKey rather
// than the raw title is what keeps the delta stable across a reworded re-run (issue #69). `title`
// remains the human-readable label rendered to the analyst.
function delta(
  kind: SecondOpinionDeltaKind,
  keyBasis: string,
  title: string,
  extra: Partial<SecondOpinionDelta>,
): SecondOpinionDelta {
  return {
    id: `${kind}:${slug(keyBasis)}`,
    kind,
    title,
    rationale: "",
    recommendation: "review",
    status: "pending",
    ...extra,
  };
}

// Findings BOTH models produced — a simple agreement signal. Matched by the same union rule as the
// deltas (semanticKey then title), counting each A finding at most once.
function agreementCount(a: InvestigationState, b: InvestigationState): number {
  return new Set(pairFindings(a, b).counterpart.values()).size;
}

// Each B finding's A counterpart. First by semanticKey then title (#69). The findings still unpaired
// after that are paired by cited-event overlap or a near-identical title, globally greedy and 1:1
// (#1682), so one finding under two titles is an agreement or a severity delta, never an A-only
// plus a B-only delta.
function pairFindings(
  a: InvestigationState,
  b: InvestigationState,
): { aAll: readonly Finding[]; bAll: readonly Finding[]; counterpart: Map<Finding, Finding> } {
  const aIdx = indexFindings(a.findings);
  const bIdx = indexFindings(b.findings);
  const counterpart = new Map<Finding, Finding>();
  for (const bf of bIdx.all) {
    const af = aIdx.match(bf);
    if (af) counterpart.set(bf, af);
  }
  const claimed = new Set(counterpart.values());
  const aLeft = aIdx.all.filter((f) => !claimed.has(f));
  const bLeft = bIdx.all.filter((f) => !counterpart.has(f));
  for (const [i, j] of pairByOverlap(aLeft, bLeft)) counterpart.set(bLeft[j], aLeft[i]);
  return { aAll: aIdx.all, bAll: bIdx.all, counterpart };
}

export interface BuildSecondOpinionInput {
  a: InvestigationState;
  b: InvestigationState;
  modelA: string;
  modelB: string;
  referee?: string; // set by the run once it knows who will (or did) referee; "" until then
  now: () => string;
  scope?: ScopeWindow; // the case's time window, for the technique deltas (#1757)
}

// Assemble a fresh SecondOpinion record (deltas pending, no reconcile verdicts yet).
export function buildSecondOpinion(input: BuildSecondOpinionInput): SecondOpinion {
  return {
    generatedAt: input.now(),
    modelA: input.modelA,
    modelB: input.modelB,
    referee: input.referee ?? "",
    summary: "",
    agreementCount: agreementCount(input.a, input.b),
    deltas: buildSecondOpinionDeltas(input.a, input.b, input.scope),
  };
}

// --- Reconcile AI pass (annotate the deltas with rationale + recommendation) -------------------

export const reconcileResponseSchema = z.object({
  summary: z.string().catch(""),
  verdicts: z
    .array(
      z.object({
        id: z.string(),
        rationale: z.string().catch(""),
        // Lenient enum: an unexpected value falls back to "review" instead of rejecting the response.
        recommendation: z.enum(["accept_b", "keep_a", "review"]).catch("review"),
      }),
    )
    .catch([]),
});

export type ReconcileResponse = z.infer<typeof reconcileResponseSchema>;

// System prompt for the reconcile call (overridable via DFIR_AI_RECONCILE_PROMPT[_FILE]).
export const RECONCILE_PROMPT = [
  "You are a senior DFIR analyst RECONCILING two INDEPENDENT analyses of the SAME investigation:",
  "Model A and Model B — two different models that each read the same forensic timeline. Neither is",
  "the authority. You may yourself be one of the two models; judge every delta on its merits, never",
  "on authorship. You are given the points where they DISAGREE. Under each delta you are shown the",
  "forensic events the disputed finding cites. An event list is evidence; a description is a claim.",
  "Prefer the evidence. A finding that cites no events is a hypothesis, not a fact — weigh that.",
  "For EACH numbered delta, judge which call is better supported and give a one-line rationale plus",
  "a recommendation:",
  "- accept_b: Model B is right — adopt B's call (add B's finding, take B's severity, add/remove the technique).",
  "- keep_a:   Model A is right — keep A as-is and reject B's change.",
  "- review:   genuinely ambiguous — the analyst must decide.",
  "Be decisive but honest: prefer 'review' only when the evidence truly doesn't settle it. Do NOT invent",
  "evidence; reason only from the finding titles, severities, descriptions, the cited forensic events",
  "shown under each delta, and the case summaries shown.",
  "Also write a 1-2 sentence 'summary' of how the two analyses compare overall.",
  "",
  "Return ONLY raw JSON (no markdown fences) with EXACTLY this shape — echo each delta's id verbatim:",
  JSON.stringify(
    {
      summary: "one to two sentences comparing the two analyses",
      verdicts: [
        {
          id: "b_only:example-finding",
          rationale: "why one model's call is better supported",
          recommendation: "accept_b|keep_a|review",
        },
      ],
    },
    null,
    2,
  ),
].join("\n");

const sevLabel = (s?: Severity): string => s ?? "?";

// Render one delta as a numbered line the reconcile model can judge.
function renderDelta(d: SecondOpinionDelta, hint?: string): string {
  const line = renderDeltaLine(d);
  return hint ? `${line}\n  ${hint}` : line;
}

function renderDeltaLine(d: SecondOpinionDelta): string {
  const desc = d.finding?.description ? ` — ${d.finding.description.slice(0, 240)}` : "";
  switch (d.kind) {
    case "b_only":
      return `[${d.id}] (B-only finding) "${d.title}" [severity ${sevLabel(d.bSeverity)}]: Model B raised this; Model A did NOT.${desc}`;
    case "a_only":
      return `[${d.id}] (A-only finding) "${d.title}" [severity ${sevLabel(d.aSeverity)}]: Model A has this; Model B DROPPED it (B may judge it unsupported/benign).${desc}`;
    case "severity":
      return `[${d.id}] (severity disagreement) "${d.title}": Model A says ${sevLabel(d.aSeverity)}, Model B says ${sevLabel(d.bSeverity)}.${desc}`;
    case "mitre_added":
      return `[${d.id}] (ATT&CK technique) ${d.title}${d.techniqueName ? ` (${d.techniqueName})` : ""}: Model B maps this technique; Model A does not.`;
    case "mitre_removed":
      return `[${d.id}] (ATT&CK technique) ${d.title}${d.techniqueName ? ` (${d.techniqueName})` : ""}: Model A maps this technique; Model B does not.`;
  }
}

// --- Cited events for the referee (#1466) -----------------------------------------------------
//
// The referee used to judge from a one-line delta and routinely rejected findings it had no way to
// weigh. Now each delta carries the FORENSIC-timeline events the disputed finding cites (both sides'
// citations on a severity delta; on a mitre delta, the technique-tagged events plus the events the
// findings carrying the technique cite — #1757). Two caps keep a
// 50-delta run inside one prompt: per delta, and a run-wide budget. Both truncations are stated so
// the referee knows it saw a sample. Reads `forensicTimeline` only — never the super-timeline.
export const RECONCILE_EVENTS_PER_DELTA = 8;
export const RECONCILE_EVENTS_TOTAL = 120;

const EVENT_INDENT = "  · ";

const bySeverityThenTime = (x: ForensicEvent, y: ForensicEvent): number =>
  SEVERITY_RANK[x.severity] - SEVERITY_RANK[y.severity] || byEventTime(x, y);

const isTechniqueDelta = (d: SecondOpinionDelta): boolean =>
  d.kind === "mitre_added" || d.kind === "mitre_removed";

// Resolve event ids through the scoped map, first occurrence wins; unknown ids are skipped.
function uniqueEvents(
  events: readonly ForensicEvent[],
  ids: readonly string[],
  byId: Map<string, ForensicEvent>,
) {
  const seen = new Set<string>();
  const out: ForensicEvent[] = [];
  for (const e of [...events, ...ids.map((id) => byId.get(id))]) {
    if (e && !seen.has(e.id)) {
      seen.add(e.id);
      out.push(e);
    }
  }
  return out;
}

// The events one delta puts in front of the referee, ranked highest severity first, then by time.
// `carriers` are the findings shown under a technique delta; their citations join the tagged events.
function citedEvents(
  d: SecondOpinionDelta,
  byId: Map<string, ForensicEvent>,
  timeline: readonly ForensicEvent[],
  carriers: readonly Finding[] = [],
): ForensicEvent[] {
  if (isTechniqueDelta(d)) {
    const tagged = timeline.filter((e) => e.mitreTechniques.includes(d.title));
    const cited = carriers.flatMap((f) => f.relatedEventIds ?? []);
    return uniqueEvents(tagged, cited, byId).sort(bySeverityThenTime);
  }
  const ids = [...(d.finding?.relatedEventIds ?? []), ...(d.bFinding?.relatedEventIds ?? [])];
  return uniqueEvents([], ids, byId).sort(bySeverityThenTime);
}

// --- The findings behind a technique delta (#1757) --------------------------------------------
//
// A technique delta used to reach the referee as a bare id plus the events TAGGED with it. A staged
// kit's finding cites events that carry no tag, so the referee read "(no cited events — this finding
// is ungrounded)" and dropped T1490 from a shadow-copy script because it "was only staged". Now the
// delta lists the live findings of the side that maps the technique, with their full text. A finding
// shown under an earlier technique delta is referred back to, keyed by side — both models use f1, f2…
export const RECONCILE_TECHNIQUE_FINDINGS = 3;
export const RECONCILE_TECHNIQUE_DESC_CHARS = 1000;

const FINDING_INDENT = "  › ";

interface TechniqueCarriers {
  side: "A" | "B";
  shown: Finding[];
  more: number;
}

function techniqueCarriers(
  d: SecondOpinionDelta,
  a: InvestigationState,
  b: InvestigationState,
  scope?: ScopeWindow,
): TechniqueCarriers | undefined {
  if (!isTechniqueDelta(d)) return undefined;
  const side = d.kind === "mitre_added" ? "B" : "A";
  const all = liveFindings(side === "A" ? a : b, scope)
    .filter((f) => f.mitreTechniques.includes(d.title))
    .sort((x, y) => SEVERITY_RANK[x.severity] - SEVERITY_RANK[y.severity]);
  const shown = all.slice(0, RECONCILE_TECHNIQUE_FINDINGS);
  return { side, shown, more: all.length - shown.length };
}

function clipText(text: string): string {
  const flat = text.replace(/\s+/g, " ").trim();
  return flat.length > RECONCILE_TECHNIQUE_DESC_CHARS
    ? `${flat.slice(0, RECONCILE_TECHNIQUE_DESC_CHARS)}…`
    : flat;
}

// `textShown` is the prompt builder's run-wide record of findings already printed in full.
function renderCarriers(c: TechniqueCarriers, textShown: Set<string>): string[] {
  const lines = c.shown.map((f) => {
    const head = `${FINDING_INDENT}Model ${c.side} finding [${f.id}] "${f.title}" [severity ${f.severity}]`;
    const key = `${c.side}:${f.id}`;
    if (textShown.has(key)) return `${head} — text shown above`;
    textShown.add(key);
    return `${head}: ${clipText(f.description ?? "")}`;
  });
  if (c.more > 0)
    lines.push(`${FINDING_INDENT}… +${c.more} more Model ${c.side} findings carry this technique`);
  return lines;
}

// How to judge a technique delta (#1757). User-prompt text, like the #1596 guard block, so an
// ejected DFIR_AI_RECONCILE_PROMPT still carries it. Sent only when the run has a technique delta.
export const RECONCILE_TECHNIQUE_RULE = [
  "ATT&CK TECHNIQUE DELTAS — how to judge them:",
  "- A technique names the behaviour an artefact implements. A script or tool that was staged, dropped or found but never run still maps to the technique its contents or purpose implement — for example a batch script that deletes shadow copies, or a tunnelling tool.",
  '- Not being run is not a reason to remove a technique, or to reject its addition. Say "staged, not executed" in the rationale instead. Execution status belongs in the finding text, not in the technique mapping.',
  "- A general-purpose program that merely could do it (cmd.exe, PowerShell, a copy tool) is not enough to support a technique by itself.",
  "- Recommend removing a technique only when it is wrong for the artefact: the artefact is build-time or collector activity, or the behaviour is a different technique.",
  "- Under each technique delta you see the findings that carry it. Read their text as well as the events before you call a technique ungrounded.",
].join("\n");

// A delta line plus its cited events, honouring both caps. `budget` is the run-wide remainder and
// is decremented in place by the caller's loop through the returned `used` count. `carrierLines`
// are the findings behind a technique delta, printed between the delta line and its events.
function renderDeltaWithEvents(
  d: SecondOpinionDelta,
  events: readonly ForensicEvent[],
  budget: number,
  hint?: string,
  carrierLines: readonly string[] = [],
): { text: string; used: number } {
  const lines = [renderDelta(d, hint), ...carrierLines];
  if (events.length === 0) {
    const why = carrierLines.length ? "judge from the finding text above" : "this finding is ungrounded";
    lines.push(`${EVENT_INDENT}(no cited events — ${why})`);
    return { text: lines.join("\n"), used: 0 };
  }
  const shown = events.slice(0, Math.max(0, Math.min(RECONCILE_EVENTS_PER_DELTA, budget)));
  for (const e of shown) lines.push(`${EVENT_INDENT}${renderEventLine(e)}`);
  const left = events.length - shown.length;
  if (left > 0) {
    const why = shown.length < RECONCILE_EVENTS_PER_DELTA ? " (run-wide event budget reached)" : "";
    lines.push(`${EVENT_INDENT}… +${left} more cited events${why}`);
  }
  return { text: lines.join("\n"), used: shown.length };
}

// Build the reconcile USER prompt: the two case summaries + every disagreement, each tagged with its id
// and followed by the forensic events it cites. `events` is the SAME scoped set both syntheses read
// (scope window applied, analyst-marked false positives removed — aiContext.loadScopedEvents), so the
// referee cannot be handed an event neither model saw. Defaults to A's forensic timeline for callers
// with no scope (tests, CLI). `guard` (#1596) is the runtime context from secondOpinionGuard.ts: the
// open threads / negative answers block and a hint line under each A-only delta that may be the
// last evidence for one. Carried as user-prompt text so an ejected reconcile prompt still gets it.
// `scope` is the case's time window: a technique delta lists only in-scope carrying findings (#1757).
export interface ReconcileGuardText {
  block: string;
  hints: ReadonlyMap<string, string>;
}

export function buildReconcilePrompt(
  a: InvestigationState,
  b: InvestigationState,
  deltas: readonly SecondOpinionDelta[],
  events?: readonly ForensicEvent[],
  guard?: ReconcileGuardText,
  scope?: ScopeWindow,
): string {
  const aSummary = a.lastSummary?.trim() || a.attackerPath?.trim() || "(no summary)";
  const bSummary = b.lastSummary?.trim() || b.attackerPath?.trim() || "(no summary)";
  const timeline = events ?? (a.forensicTimeline.length ? a.forensicTimeline : b.forensicTimeline);
  const byId = new Map(timeline.map((e) => [e.id, e]));
  let budget = RECONCILE_EVENTS_TOTAL;
  const textShown = new Set<string>();
  const rendered = deltas.map((d) => {
    const carriers = techniqueCarriers(d, a, b, scope);
    const carrierLines = carriers ? renderCarriers(carriers, textShown) : [];
    const cited = citedEvents(d, byId, timeline, carriers?.shown);
    const out = renderDeltaWithEvents(d, cited, budget, guard?.hints.get(d.id), carrierLines);
    budget -= out.used;
    return out.text;
  });
  return [
    `MODEL A summary: ${aSummary}`,
    "",
    `MODEL B summary: ${bSummary}`,
    "",
    `DISAGREEMENTS (${deltas.length}) — each followed by the forensic events the finding cites:`,
    ...rendered,
    "",
    ...(deltas.some(isTechniqueDelta) ? [RECONCILE_TECHNIQUE_RULE, ""] : []),
    ...(guard?.block ? [guard.block, ""] : []),
    "Return your reconciliation as raw JSON in the required shape — one verdict object per delta id above.",
  ].join("\n");
}

// Merge the reconcile AI's per-delta verdicts (rationale + recommendation) onto the matching deltas
// by id, and set the overall summary. Unknown ids are ignored. Immutable.
export function mergeReconcileVerdicts(so: SecondOpinion, parsed: ReconcileResponse): SecondOpinion {
  const byId = new Map(parsed.verdicts.map((v) => [v.id, v]));
  return {
    ...so,
    summary: parsed.summary,
    deltas: so.deltas.map((d) => {
      const v = byId.get(d.id);
      return v ? { ...d, rationale: v.rationale, recommendation: v.recommendation } : d;
    }),
  };
}

// --- Analyst actions --------------------------------------------------------------------------

// Immutably set one delta's status (pending | accepted | rejected). Other deltas are untouched.
// The analyst's own decision settles the referee's flags (#1596), so they are dropped with it.
export function setDeltaStatus(so: SecondOpinion, id: string, status: DeltaStatus): SecondOpinion {
  return { ...so, deltas: so.deltas.map((d) => (d.id === id ? { ...withoutFlags(d), status } : d)) };
}

function withoutFlags(d: SecondOpinionDelta): SecondOpinionDelta {
  const { refereeFlags: _f, ...rest } = d;
  return rest;
}

// Bulk variant for accept-all / reject-all: set EVERY still-pending delta to `status`. Deltas the
// analyst already decided (accepted/rejected) are left as-is, so a bulk action never silently
// reverses an individual decision. Accept-all skips a delta held for the analyst (#1596); reject-all
// does not, because rejecting keeps Model A's finding. Immutable.
export function setAllPendingStatus(so: SecondOpinion, status: DeltaStatus): SecondOpinion {
  const skip = (d: SecondOpinionDelta): boolean => status === "accepted" && heldForAnalyst(d);
  return {
    ...so,
    deltas: so.deltas.map((d) => (d.status === "pending" && !skip(d) ? { ...withoutFlags(d), status } : d)),
  };
}

// Follow the referee on every still-pending delta: accept_b → accepted, keep_a → rejected. A
// "review" delta (the referee made no call) stays pending for the analyst, and so does a delta held
// for the analyst by the dismissal guard (#1596). Pure, immutable.
const REFEREE_STATUS: Partial<Record<DeltaRecommendation, DeltaStatus>> = {
  accept_b: "accepted",
  keep_a: "rejected",
};
export function followRefereeStatus(so: SecondOpinion): SecondOpinion {
  return {
    ...so,
    deltas: so.deltas.map((d) => {
      const status =
        d.status === "pending" && !heldForAnalyst(d) ? REFEREE_STATUS[d.recommendation] : undefined;
      return status ? { ...d, status } : d;
    }),
  };
}

// Apply EVERY accepted delta onto a case state. Pure, immutable, IDEMPOTENT (safe to run on every
// read/synthesis): b_only adds B's finding if absent by matchKey; a_only dismisses A's finding in
// place; severity rewrites A's finding severity; mitre_added adds the technique; mitre_removed is
// RECORDED in rejectedTechniques and hidden at read time, never deleted from stored data (#1742).
// a_only / severity find their finding by id first, while it still holds the same claim, and by
// matchKey only when it does not (#1590) — so a retitled or retagged finding keeps the decision.
// Used by both the apply route (on the live state) and synthesize() post-processing (durability).
export function applyAcceptedSecondOpinion(
  state: InvestigationState,
  so: SecondOpinion | null,
): InvestigationState {
  if (!so) return state;
  const accepted = so.deltas.filter((d) => d.status === "accepted");
  // Recomputed from the whole record every time, so switching a removal back to rejected clears it.
  const base = withRejectedTechniqueIds(state, rejectedTechniqueIds(accepted));
  if (accepted.length === 0) return base;

  let findings = state.findings;
  let techniques = state.mitreTechniques;
  // A saved finding cites events as they were when the second opinion ran; an event correlation has
  // folded since is cited as the one it lives on now (#1715), before matching and before adoption.
  const resolve = stateEventResolver(state);

  for (const d of accepted) {
    if (d.kind === "b_only" && d.finding) {
      const bFinding = d.finding.relatedEventIds
        ? { ...d.finding, relatedEventIds: [...new Set(d.finding.relatedEventIds.map(resolve))] }
        : d.finding;
      // Present already by the id it was adopted under (the model may have retitled it), or by key.
      const key = matchKey(bFinding);
      const adoptedId = `so:${slug(d.title)}`;
      if (findings.some((f) => f.id === adoptedId || matchKey(f) === key)) continue;
      // #1682 — B's finding cites mostly the same events as a live finding: it is that finding
      // under another title. Accepting B takes B's severity on it; the finding count never grows.
      const dup = overlappingFinding(findings, bFinding);
      const sev = d.bSeverity ?? bFinding.severity;
      findings = dup
        ? findings.map((f) => (f.id === dup.id ? { ...f, severity: sev } : f))
        : [...findings, { ...bFinding, id: adoptedId, status: "open" }];
    } else if (d.kind === "a_only") {
      findings = mapTargets(findings, d, (f) => ({ ...f, status: "dismissed" as const }));
    } else if (d.kind === "severity" && d.bSeverity) {
      const sev = d.bSeverity;
      findings = mapTargets(findings, d, (f) => ({ ...f, severity: sev }));
    } else if (d.kind === "mitre_added") {
      // `analystAccepted` is what keeps it visible: the projection drops a technique nothing
      // surviving supports, and an accepted addition has no finding and no event behind it by
      // construction — it is the analyst overruling both models (#893).
      const existing = techniques.find((t) => t.id === d.title);
      if (!existing) {
        techniques = [
          ...techniques,
          {
            id: d.title,
            name: d.techniqueName || d.title,
            findingIds: [],
            analystAccepted: true,
          } satisfies Technique,
        ];
      } else if (!existing.analystAccepted) {
        // Already present, but now also affirmed by hand — it outlives whatever first put it there.
        techniques = techniques.map((t) => (t.id === d.title ? { ...t, analystAccepted: true } : t));
      }
    }
  }

  if (findings === state.findings && techniques === state.mitreTechniques) return base;
  return { ...base, findings, mitreTechniques: techniques };
}

function mapTargets(
  findings: readonly Finding[],
  d: SecondOpinionDelta,
  fn: (f: Finding) => Finding,
): Finding[] {
  const { ids } = resolveDecisionTargets(findings, d);
  return findings.map((f) => (ids.has(f.id) ? fn(f) : f));
}
