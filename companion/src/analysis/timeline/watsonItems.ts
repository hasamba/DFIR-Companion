import { sortByEventTime } from "../forensicSort.js";
import { deriveSemanticKey } from "../semanticKey.js";
import type { Finding, ForensicEvent, InvestigationState, NextStep } from "../stateTypes.js";
import type { WatsonFindingDisagreement } from "../watsonItemTypes.js";

/**
 * Every path that replaces findings or next steps keeps the ones the analyst applied from Watson.
 *
 * Synthesis rebuilds findings from an empty base and replaces next steps wholesale; import and MCP
 * deltas, the incident-type apply and the false-positive cascade replace next steps too. A Watson
 * item (`author: "watson"`) is an analyst decision, not a model conclusion, so none of those may
 * drop, re-grade or rewrite it. Each of them calls `keepWatsonItems` with the store's copy.
 *
 * Watson items are identified by `author`, never by the `f-watson-` id prefix: the prefix is only
 * reserved so a model cannot mint one (responseSchema.ts).
 */

/** The provenance marker on a forensic event Watson created (a pasted line, a promoted row). */
export const WATSON_MARKER = "[watson]";

type Watsonish = { author?: "watson" } | undefined;
export const isWatsonItem = (x: Watsonish): boolean => x?.author === "watson";
export const isWatsonEvent = (e: ForensicEvent): boolean => (e.provenance ?? []).includes(WATSON_MARKER);

/** The fields a run may set on a kept Watson finding; everything else is the store's. */
const FINDING_ANNOTATIONS = ["synthesisDisagrees", "similarSynthesisId", "citationsChanged"] as const;
/** The FP cascade's stale badge is the one field a run may set on a kept Watson next step. */
const STEP_ANNOTATIONS = ["staleReSynth"] as const;

const keepFinding = (stored: Finding, run: Finding | undefined): Finding =>
  overlay(stored, run, FINDING_ANNOTATIONS);

/**
 * A kept Watson step also keeps the import high-water stamp the run put on its collection request
 * (stampCollectDirectives), as a kept Watson question does: the request is Watson's, the stamp is
 * what stops the request's own evidence being handed back as its result.
 */
function keepStep(stored: NextStep, run: NextStep | undefined): NextStep {
  const out = overlay(stored, run, STEP_ANNOTATIONS);
  const seq = run?.collect?.issuedAfterImportSeq;
  if (!out.collect || out.collect.issuedAfterImportSeq !== undefined || seq === undefined) return out;
  return { ...out, collect: { ...out.collect, issuedAfterImportSeq: seq } };
}

/** What `keepWatsonItems` reads from the store. `forensicTimeline` present → events reconcile too. */
export type WatsonItemsSource = Pick<InvestigationState, "findings" | "nextSteps"> & {
  forensicTimeline?: readonly ForensicEvent[];
};

/** The store's Watson findings and next steps only — for callers that must not reconcile events. */
export function watsonItemsOf(state: Pick<InvestigationState, "findings" | "nextSteps">): WatsonItemsSource {
  return { findings: state.findings, nextSteps: state.nextSteps };
}

/** `latest`'s copy with the run's annotations laid over it (absent on the run's copy = cleared). */
function overlay<T extends object>(stored: T, run: T | undefined, keys: readonly (keyof T)[]): T {
  if (!run) return stored;
  const out = { ...stored };
  for (const k of keys) {
    if (run[k] === undefined) delete out[k];
    else out[k] = run[k];
  }
  return out;
}

/**
 * Reconcile one list: every Watson item in `latest` is in the result as in `latest` (with the run's
 * annotations), in the run's position when the run has it, else appended; a Watson item absent from
 * `latest` (undone while the run worked) is dropped. Non-Watson items are the run's.
 */
function reconcile<T extends { id: string; author?: "watson" }>(
  run: readonly T[],
  latest: readonly T[],
  keep: (stored: T, run: T | undefined) => T,
): T[] {
  const stored = new Map(latest.filter(isWatsonItem).map((x) => [x.id, x] as const));
  const out: T[] = [];
  const placed = new Set<string>();
  for (const x of run) {
    const kept = stored.get(x.id);
    if (kept) {
      if (!placed.has(x.id)) out.push(keep(kept, isWatsonItem(x) ? x : undefined));
      placed.add(x.id);
    } else if (!isWatsonItem(x)) out.push(x);
  }
  for (const [id, kept] of stored) if (!placed.has(id)) out.push(kept);
  return out;
}

/**
 * Watson-marked events: present iff present in `latest`, with `latest`'s fields — except the run's
 * `relatedFindingIds`, which the fold rebuilt. An event the run's correlation folded into another
 * (listed in the run's `eventAliases`) is not re-added: its citations already follow the survivor.
 */
function reconcileEvents(next: InvestigationState, latest: readonly ForensicEvent[]): ForensicEvent[] {
  const stored = new Map(latest.filter(isWatsonEvent).map((e) => [e.id, e] as const));
  const runIds = new Set(next.forensicTimeline.map((e) => e.id));
  const folded = next.eventAliases ?? {};
  const kept = next.forensicTimeline.flatMap((e) => {
    const s = stored.get(e.id);
    if (s) return [{ ...s, relatedFindingIds: e.relatedFindingIds }];
    return isWatsonEvent(e) ? [] : [e];
  });
  const added = [...stored.values()].filter((e) => !runIds.has(e.id) && !(e.id in folded));
  return added.length ? sortByEventTime([...kept, ...added]) : kept;
}

/**
 * Restore every Watson finding and next step from `latest` into `next` (see `reconcile`), and the
 * Watson-marked forensic events when `latest` carries a timeline. Pure and idempotent. A run may
 * only set the annotations: `synthesisDisagrees`, `similarSynthesisId`, `citationsChanged` on a
 * finding, and `staleReSynth` plus the collection request's import stamp on a next step. `relatedFindingIds` on events are never touched.
 */
export function keepWatsonItems(next: InvestigationState, latest: WatsonItemsSource): InvestigationState {
  const anyWatson =
    next.findings.some(isWatsonItem) ||
    next.nextSteps.some(isWatsonItem) ||
    latest.findings.some(isWatsonItem) ||
    latest.nextSteps.some(isWatsonItem);
  const events = latest.forensicTimeline;
  const anyEvent = !!events && (events.some(isWatsonEvent) || next.forensicTimeline.some(isWatsonEvent));
  if (!anyWatson && !anyEvent) return next;
  return {
    ...next,
    findings: reconcile(next.findings, latest.findings, keepFinding),
    nextSteps: reconcile(next.nextSteps, latest.nextSteps, keepStep),
    ...(events && anyEvent ? { forensicTimeline: reconcileEvents(next, events) } : {}),
  };
}

/** Synthesis's version of a Watson finding, when it differs on severity, title or description. */
export function watsonFindingDisagreement(
  delta: Pick<Finding, "severity" | "title" | "description">,
  kept: Pick<Finding, "severity" | "title" | "description">,
): WatsonFindingDisagreement | undefined {
  const same =
    delta.severity === kept.severity && delta.title === kept.title && delta.description === kept.description;
  return same ? undefined : { severity: delta.severity, title: delta.title, description: delta.description };
}

/** A synthesis run is the re-synthesis the FP cascade's stale badge asks for: it clears the badge. */
export function clearWatsonStepBadges(next: InvestigationState): InvestigationState {
  if (!next.nextSteps.some((s) => isWatsonItem(s) && s.staleReSynth)) return next;
  return {
    ...next,
    nextSteps: next.nextSteps.map((s) => {
      if (!isWatsonItem(s) || !s.staleReSynth) return s;
      const { staleReSynth: _stale, ...rest } = s;
      return rest;
    }),
  };
}

/** A next-step list with the Watson steps of `stored` kept (for callers that replace a list). */
export function keepWatsonSteps(steps: readonly NextStep[], stored: readonly NextStep[]): NextStep[] {
  return reconcile(steps, stored, keepStep);
}

// ── The synthesis fold ────────────────────────────────────────────────────────────────────────────

export type WatsonDisagreements = ReadonlyMap<string, WatsonFindingDisagreement | undefined>;

/**
 * Before the fold renames forged ids: a delta finding re-issuing an existing Watson finding's id is
 * dropped (Watson's version stands), and what synthesis said is kept as the disagreement — undefined
 * when it agreed, which clears an old one. A `f-watson-` id that is not a Watson finding stays in the
 * delta, so the rename turns it into `f-model-f-watson-…` as for any other reserved id.
 */
export function splitWatsonReissues<F extends Pick<Finding, "id" | "severity" | "title" | "description">>(
  findings: readonly F[],
  prior: readonly Finding[],
): { findings: F[]; disagreements: WatsonDisagreements } {
  const watson = new Map(prior.filter(isWatsonItem).map((f) => [f.id, f] as const));
  const disagreements = new Map<string, WatsonFindingDisagreement | undefined>();
  const kept: F[] = [];
  for (const f of findings) {
    const w = watson.get(f.id);
    if (w) disagreements.set(f.id, watsonFindingDisagreement(f, w));
    else kept.push(f);
  }
  return { findings: kept, disagreements };
}

/**
 * The snapshot's Watson findings put back into a finding list the fold rebuilt from scratch — except
 * the ones the analyst marked false positive (`rejected`). Those stay persisted (the fold's last
 * step restores them; undo is their removal path) but are not live: not surviving, not citing.
 */
export function withWatsonFindings(
  next: InvestigationState,
  prior: readonly Finding[],
  rejected: ReadonlySet<string> = new Set(),
): InvestigationState {
  const present = new Set(next.findings.map((f) => f.id));
  const add = prior.filter((f) => isWatsonItem(f) && !present.has(f.id) && !rejected.has(f.id));
  return add.length ? { ...next, findings: [...next.findings, ...add] } : next;
}

/**
 * Watson findings as back-link sources: their cited events, each followed through correlation folds
 * to the row that holds it now, without any the analyst rejected.
 */
export function watsonCitationSources(
  state: Pick<InvestigationState, "findings" | "eventAliases">,
  benign: ReadonlySet<string>,
): Pick<Finding, "id" | "status" | "relatedEventIds">[] {
  const aliases = state.eventAliases ?? {};
  const rejected = (id: string): boolean => benign.has(id.trim().toLowerCase());
  return state.findings.filter(isWatsonItem).map((f) => ({
    id: f.id,
    status: f.status,
    relatedEventIds: [
      ...new Set(
        (f.relatedEventIds ?? []).filter((id) => !rejected(id)).map((id) => resolveAlias(id, aliases)),
      ),
    ].filter((id) => !rejected(id)),
  }));
}

/**
 * Back-links to a Watson finding of the snapshot that is gone from `next` (undone while the run
 * worked) are removed, so no event points at a finding the case no longer holds.
 */
export function dropUndoneWatsonLinks(
  next: InvestigationState,
  prior: readonly Finding[],
): InvestigationState {
  const present = new Set(next.findings.map((f) => f.id));
  const gone = new Set(prior.filter((f) => isWatsonItem(f) && !present.has(f.id)).map((f) => f.id));
  if (gone.size === 0) return next;
  return {
    ...next,
    forensicTimeline: next.forensicTimeline.map((e) =>
      e.relatedFindingIds.some((id) => gone.has(id))
        ? { ...e, relatedFindingIds: e.relatedFindingIds.filter((id) => !gone.has(id)) }
        : e,
    ),
  };
}

const keyOf = (f: Finding): string => deriveSemanticKey(f);

/** An event id followed through correlation folds to the row that holds it now (bounded). */
function resolveAlias(id: string, aliases: Readonly<Record<string, string>>): string {
  let cur = id;
  for (let i = 0; i < 8 && aliases[cur] && aliases[cur] !== cur; i++) cur = aliases[cur];
  return cur;
}

/** Every cited event is a false positive or no longer in the timeline. Paste-only: never. */
function citationsGone(f: Finding, state: InvestigationState, benign: ReadonlySet<string>): boolean {
  const cited = f.relatedEventIds ?? [];
  if (cited.length === 0) return false;
  const live = new Set(state.forensicTimeline.map((e) => e.id));
  const aliases = state.eventAliases ?? {};
  return cited.every((id) => {
    const now = resolveAlias(id, aliases);
    return !live.has(now) || benign.has(now.trim().toLowerCase()) || benign.has(id.trim().toLowerCase());
  });
}

/**
 * The fold's annotations on every Watson finding, recomputed each run: the disagreement from this
 * run's re-issue (kept from earlier runs when this one did not re-issue the id), the synthesis
 * finding sharing its semantic key, and whether its cited evidence changed.
 */
export function annotateWatsonFindings(
  next: InvestigationState,
  disagreements: WatsonDisagreements,
  benign: ReadonlySet<string>,
): InvestigationState {
  if (!next.findings.some(isWatsonItem)) return next;
  const byKey = new Map<string, string>();
  for (const f of next.findings) {
    const k = isWatsonItem(f) ? "" : keyOf(f);
    if (k && !byKey.has(k)) byKey.set(k, f.id);
  }
  const findings = next.findings.map((f) => {
    if (!isWatsonItem(f)) return f;
    const { synthesisDisagrees: oldDis, similarSynthesisId: _s, citationsChanged: _c, ...own } = f;
    const dis = disagreements.has(f.id) ? disagreements.get(f.id) : oldDis;
    const similar = byKey.get(keyOf(f));
    return {
      ...own,
      ...(dis ? { synthesisDisagrees: dis } : {}),
      ...(similar ? { similarSynthesisId: similar } : {}),
      ...(citationsGone(f, next, benign) ? { citationsChanged: true } : {}),
    };
  });
  return { ...next, findings };
}
