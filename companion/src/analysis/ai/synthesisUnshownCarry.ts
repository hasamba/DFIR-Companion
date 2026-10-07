import { applyFalsePositive, type FalsePositiveMarker } from "../falsePositive.js";
import { deriveSemanticKey } from "../semanticKey.js";
import type { Finding, InvestigationState } from "../stateTypes.js";
import { supportingEventIds } from "./synthesisMerge.js";

/**
 * #2006: a synthesis run rebuilds its findings from an empty base, and the model is shown only the
 * first FINDINGS_ECHO_CAP of the prior ones. A finding past that cut was never re-emitted, so the
 * run deleted it, along with the analyst notes keyed to its id.
 *
 * Re-attach each prior finding the model was NOT shown, exactly as stored (same id), with its event
 * back-links restored and the false-positive filter applied. Two cases leave it out:
 *   - The run already has a finding with the same id. The run's version wins.
 *   - The run has a NEW finding with the same semantic key or the same title. The model wrote that
 *     one this run, so the old unshown copy would only be a duplicate.
 *
 * A finding the model WAS shown and dropped stays dropped: synthesis replacing its own conclusions
 * is the invariant. With no more than FINDINGS_ECHO_CAP findings, nothing is unshown and this is a
 * no-op. Runs after grading, so a carried finding keeps the grade it was stored with.
 */
export interface UnshownCarryInput {
  /** The correlated pre-call snapshot the echo was built from. */
  prior: InvestigationState;
  /** Ids of the findings the echo showed the model. */
  echoedIds: ReadonlySet<string>;
  markers: FalsePositiveMarker[];
}

function titleKey(f: Pick<Finding, "title">): string {
  return (f.title ?? "").trim().toLowerCase().replace(/\s+/g, " ");
}

function semanticOf(f: Finding): string {
  return f.semanticKey || deriveSemanticKey(f);
}

export function carryUnshownFindings(
  next: InvestigationState,
  input: UnshownCarryInput,
): { state: InvestigationState; carriedCount: number } {
  const { prior, echoedIds, markers } = input;
  const ids = new Set(next.findings.map((f) => f.id));
  const titles = new Set(next.findings.map(titleKey));
  const keys = new Set(next.findings.map(semanticOf).filter(Boolean));

  const candidates = prior.findings.filter((f) => {
    if (echoedIds.has(f.id) || ids.has(f.id)) return false;
    if (titles.has(titleKey(f))) return false;
    const key = semanticOf(f);
    return !(key && keys.has(key));
  });
  if (candidates.length === 0) return { state: next, carriedCount: 0 };

  const carried = applyFalsePositive({ ...prior, findings: candidates }, markers).findings;
  if (carried.length === 0) return { state: next, carriedCount: 0 };

  const backing = supportingEventIds(prior, markers);
  const relink = new Map<string, string[]>();
  for (const f of carried)
    for (const eid of backing.get(f.id) ?? []) relink.set(eid, [...(relink.get(eid) ?? []), f.id]);

  return {
    carriedCount: carried.length,
    state: {
      ...next,
      findings: [...next.findings, ...carried],
      forensicTimeline: next.forensicTimeline.map((e) => {
        const add = relink.get(e.id)?.filter((fid) => !e.relatedFindingIds.includes(fid));
        return add?.length ? { ...e, relatedFindingIds: [...e.relatedFindingIds, ...add] } : e;
      }),
    },
  };
}
