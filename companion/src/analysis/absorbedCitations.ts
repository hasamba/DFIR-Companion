// Correlation folds a group of events into one and drops every other member's id (#1714). A finding,
// an IOC's provenance, a session-command note or a contradiction pointer that cited a folded-away id
// then pointed at nothing: grading dropped it as hallucinated, the finding was capped as ungrounded,
// and the High backfill could raise the same events again as a duplicate auto finding. This rewrites
// every such citation in the case state to the event that survived, in the same step that folded it.
//
// Only core state is rewritten here. Stores keyed by event id outside the state (tags, comments,
// hypotheses …) are never rewritten; the same step records the fold in the case lineage, and their
// readers resolve through it (#1715, eventAliases.ts).

import type { InvestigationState } from "./stateTypes.js";
import { recordEventAliases } from "./eventAliases.js";

type Absorbed = ReadonlyMap<string, string>;

/** The ids with every absorbed one replaced by its survivor, de-duplicated in first-seen order. */
function remapIds(ids: readonly string[], absorbed: Absorbed): string[] | undefined {
  if (!ids.some((id) => absorbed.has(id))) return undefined;
  return [...new Set(ids.map((id) => absorbed.get(id) ?? id))];
}

function remapFinding(f: InvestigationState["findings"][number], absorbed: Absorbed) {
  const related = f.relatedEventIds && remapIds(f.relatedEventIds, absorbed);
  const commands = f.sessionCommands?.some((c) => absorbed.has(c.eventId))
    ? f.sessionCommands.map((c) =>
        absorbed.has(c.eventId) ? { ...c, eventId: absorbed.get(c.eventId)! } : c,
      )
    : undefined;
  if (!related && !commands) return f;
  return {
    ...f,
    ...(related ? { relatedEventIds: related } : {}),
    ...(commands ? { sessionCommands: commands } : {}),
  };
}

function remapIoc(i: InvestigationState["iocs"][number], absorbed: Absorbed) {
  const from = i.extractedFrom && remapIds(i.extractedFrom, absorbed);
  return from ? { ...i, extractedFrom: from } : i;
}

function remapQuestion(q: InvestigationState["keyQuestions"][number], absorbed: Absorbed) {
  const ids = q.contradicted && remapIds(q.contradicted.eventIds, absorbed);
  return ids && q.contradicted ? { ...q, contradicted: { ...q.contradicted, eventIds: ids } } : q;
}

/** The state with every citation of an absorbed event id pointed at the event that kept it. */
export function remapAbsorbedEventIds(state: InvestigationState, absorbed: Absorbed): InvestigationState {
  if (absorbed.size === 0) return state;
  return {
    ...state,
    findings: state.findings.map((f) => remapFinding(f, absorbed)),
    iocs: state.iocs.map((i) => remapIoc(i, absorbed)),
    keyQuestions: state.keyQuestions.map((q) => remapQuestion(q, absorbed)),
    eventAliases: recordEventAliases(state.eventAliases, absorbed),
  };
}
