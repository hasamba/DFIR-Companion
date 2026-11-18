import { stateEventResolver, type EventResolver } from "../eventAliasLookup.js";
import { isDeterministicFindingId } from "../responseSchema.js";
import { deriveSemanticKey } from "../semanticKey.js";
import { SEVERITY_RANK, type Finding, type InvestigationState } from "../stateTypes.js";
import type { WatsonFindingReview, WatsonFindingVerdict } from "../watsonItemTypes.js";
import { isWatsonItem } from "./watsonItems.js";

/**
 * Watson's verdicts on synthesis findings (#2682): a demotion or a dismissal the analyst approved
 * (or Auto applied, Low/Medium only). The verdict is the case's own record (`watsonFindingVerdicts`),
 * never the analyst's false-positive marker. Synthesis mints new model-finding ids each run, so a
 * verdict is matched by a stable key: the id for a deterministic finding (the #2092 key), else the
 * finding's semantic key (#69), else its normalised title. Exact match only.
 *
 * Reopen rule: a run whose finding cites an event the verdict did not consider (alias-resolved, so
 * a correlation fold is not new evidence) leaves the finding open and unchanged, with a note.
 * A verdict never raises a severity, and a Watson-authored finding is never a target.
 */

/** How many new event ids a reopened finding's note lists. */
const MAX_NEW_IDS = 20;

/** The key a verdict is matched by across re-synthesis. */
export function findingVerdictKey(f: Pick<Finding, "id" | "title" | "mitreTechniques">): string {
  if (isDeterministicFindingId(f.id)) return `id:${f.id}`;
  const key = deriveSemanticKey(f);
  return key ? `key:${key}` : `title:${f.title.trim().toLowerCase()}`;
}

/** The finding as synthesis left it: the mark removed and, if applied, its severity and status back. */
export function withoutReview(f: Finding): Finding {
  const r = f.watsonReview;
  if (!r) return f;
  const { watsonReview: _mark, ...rest } = f;
  return isApplied(r) ? { ...rest, severity: r.fromSeverity, status: r.fromStatus } : rest;
}

/** True when the mark changed the finding (not reopened by new evidence, not held from Auto). */
export const isApplied = (r: WatsonFindingReview): boolean => !r.newEventIds && !r.autoHeld;

/** Auto never changes a High or Critical finding by itself (user decision, #2682). */
const AUTO_HELD: ReadonlySet<string> = new Set(["Critical", "High"]);

/** A demotion that would not lower the finding changes nothing. */
const lowers = (v: WatsonFindingVerdict, f: Finding): boolean =>
  v.action === "dismiss" || (!!v.severity && SEVERITY_RANK[v.severity] > SEVERITY_RANK[f.severity]);

/** `f` (with no mark) under verdict `v`: applied, or marked reopened when it cites new evidence. */
export function reviewFinding(f: Finding, v: WatsonFindingVerdict, resolve: EventResolver): Finding {
  if (!lowers(v, f) || f.status === "dismissed") return f;
  const considered = new Set(v.consideredEventIds.map(resolve));
  const newEventIds = (f.relatedEventIds ?? []).filter((id) => !considered.has(resolve(id)));
  const mark: WatsonFindingReview = {
    action: v.action,
    ...(v.severity ? { severity: v.severity } : {}),
    reason: v.reason,
    eventIds: v.eventIds,
    proposalId: v.proposalId,
    approvedBy: v.approvedBy,
    at: v.at,
    fromSeverity: f.severity,
    fromStatus: f.status,
  };
  if (newEventIds.length) {
    return { ...f, watsonReview: { ...mark, newEventIds: newEventIds.slice(0, MAX_NEW_IDS) } };
  }
  if (v.auto && AUTO_HELD.has(f.severity)) return { ...f, watsonReview: { ...mark, autoHeld: true } };
  if (v.action === "dismiss") return { ...f, status: "dismissed", watsonReview: mark };
  return { ...f, severity: v.severity!, watsonReview: mark };
}

/**
 * Every synthesis finding with the case's verdicts applied. Pure and idempotent: each mark is first
 * taken off (putting back what it changed), then the verdict for the finding's key is applied again.
 * Needs the forensic timeline for alias resolution; without it ids compare as written.
 */
export function applyWatsonVerdicts(state: InvestigationState, only?: readonly string[]): InvestigationState {
  const verdicts = new Map((state.watsonFindingVerdicts ?? []).map((v) => [v.key, v] as const));
  if (only?.length === 0 || (!verdicts.size && !state.findings.some((f) => f.watsonReview))) return state;
  const resolve = stateEventResolver(state);
  const findings = state.findings.map((f) => {
    if (isWatsonItem(f) || (only && !only.includes(f.id))) return f;
    const base = withoutReview(f);
    const v = verdicts.get(findingVerdictKey(base));
    return v ? reviewFinding(base, v, resolve) : base;
  });
  return { ...state, findings };
}

/** `state` with exactly `verdicts` as its record (absent when there are none). */
export function withVerdicts(
  state: InvestigationState,
  verdicts: readonly WatsonFindingVerdict[] | undefined,
): InvestigationState {
  const { watsonFindingVerdicts: _old, ...rest } = state;
  return verdicts?.length ? { ...rest, watsonFindingVerdicts: [...verdicts] } : rest;
}

/** The verdict keys the synthesis findings in `state` answer to (Watson's own findings excluded). */
function findingKeys(state: InvestigationState): Set<string> {
  return new Set(
    state.findings.filter((f) => !isWatsonItem(f)).map((f) => findingVerdictKey(withoutReview(f))),
  );
}

/**
 * The stored verdicts a full synthesis run left without a finding (#2693): matched a finding in
 * `before`, match none in `after`. Only the change is reported, so a verdict that was already dormant
 * before the run is not reported again. Never call it for a partial re-grade (`only`): there a missing
 * finding means "not in this slice".
 */
export function orphanedVerdicts(
  before: InvestigationState,
  after: InvestigationState,
): WatsonFindingVerdict[] {
  const verdicts = after.watsonFindingVerdicts ?? [];
  if (!verdicts.length) return [];
  const was = findingKeys(before);
  const now = findingKeys(after);
  return verdicts.filter((v) => was.has(v.key) && !now.has(v.key));
}

/** How much of a verdict's title or approver the log line keeps. */
const MAX_LOG_TEXT = 160;

/** Adversary-influenced text made safe for one log line: one line, no double quotes, clipped. */
function logText(s: string): string {
  const flat = s
    .replace(/[\u0000-\u001f\u007f]+/g, " ")
    .replace(/\s+/g, " ")
    .replace(/"/g, "'")
    .trim();
  return flat.length > MAX_LOG_TEXT ? `${flat.slice(0, MAX_LOG_TEXT - 1)}…` : flat;
}

/** The Investigation-Log line for a verdict that no longer matches a finding. */
export function orphanedVerdictNotice(v: WatsonFindingVerdict): string {
  const change = v.action === "dismiss" ? "dismissed" : `demoted to ${v.severity ?? "a lower severity"}`;
  return (
    `Watson's change to "${logText(v.title)}" (${change}, approved by ${logText(v.approvedBy)}) no longer ` +
    `matches a finding: synthesis reworded the finding, or it is no longer raised. The change is kept and ` +
    `applies again if the finding comes back in the same words. Undo on its proposal card in the Watson ` +
    `chat still works.`
  );
}
