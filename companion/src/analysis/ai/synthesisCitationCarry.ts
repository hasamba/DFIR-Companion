import type { deltaSchema } from "../responseSchema.js";

type Delta = ReturnType<typeof deltaSchema.parse>;

export interface CitationCarryInput {
  /** Per prior finding id: the events that still back it (`supportingEventIds`). */
  backing: ReadonlyMap<string, ReadonlySet<string>>;
  /** Ids of the findings the model was shown. Only a shown finding can be a re-issue (#2047). */
  echoedIds: ReadonlySet<string>;
  /** The events this run considered; a carried id must resolve in grading. */
  scopedIds: ReadonlySet<string>;
}

export interface CitationCarry {
  delta: Delta;
  /** Findings that kept prior citations, for the caller's log. */
  inherited: { findingId: string; eventIds: string[] }[];
}

/**
 * A re-issued finding keeps the citations it had (#2047).
 *
 * Synthesis rebuilds findings from an empty base. When the selection changes between runs, the
 * model may re-issue a finding by id ("Earlier analysis found...") without the row it cited, and
 * the finding then reads as ungrounded. A delta finding that is shown to the model, has the id of
 * a prior finding and cites nothing takes back the prior citations that are still in scope.
 */
export function inheritPriorCitations(delta: Delta, input: CitationCarryInput): CitationCarry {
  const inherited: CitationCarry["inherited"] = [];
  const findings = delta.findings.map((f) => {
    if ((f.relatedEventIds ?? []).length > 0 || !input.echoedIds.has(f.id)) return f;
    const eventIds = [...(input.backing.get(f.id) ?? [])].filter((id) => input.scopedIds.has(id));
    if (eventIds.length === 0) return f;
    inherited.push({ findingId: f.id, eventIds });
    return { ...f, relatedEventIds: eventIds };
  });
  return inherited.length ? { delta: { ...delta, findings }, inherited } : { delta, inherited };
}
