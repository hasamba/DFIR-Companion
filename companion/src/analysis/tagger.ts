// Content-based event tagger — the PURE runner. Given a set of events and a compiled ruleset, it
// reports what each rule matched and, per event, the aggregated tags / MITRE techniques / proposed
// severity. It NEVER performs I/O and NEVER mutates its inputs: applying the result to case state
// (writing tags through TagsStore, raising forensic-event severity) is the caller's job (the route
// / pipeline), so this stays trivially unit-testable and side-effect free.
//
// Invariants enforced here: MITRE is UNION-only and severity is RAISE-only (applyToForensicEvent) —
// a tagger rule can never remove a technique or downgrade a severity the AI assigned.

import type { ForensicEvent, Severity } from "./stateTypes.js";
import { matchEvent, SEVERITIES, type CompiledRule, type CompiledRuleset } from "./taggerRules.js";

/** Per-rule outcome for a run — its match count, the events it hit, and the actions it carries. */
export interface RuleMatch {
  id: string;
  description?: string;
  view?: string;
  tags: string[];
  mitre: string[];
  severity?: Severity;
  eventIds: string[];
  matched: number;
}

/** Aggregated proposal for one event across every rule that matched it. */
export interface EventTagResult {
  eventId: string;
  tags: string[];       // union of matching rules' tags (order-stable, deduped)
  mitre: string[];      // union of matching rules' MITRE ids
  severity?: Severity;  // the HIGHEST severity any matching rule requested (undefined if none set one)
  ruleIds: string[];    // ids of the rules that matched (drives per-tag authorship: `tagger:<id>`)
}

export interface TaggerResult {
  perRule: RuleMatch[];       // every rule, including 0-match ones (so a "Run tagger" report is complete)
  perEvent: EventTagResult[]; // only events with ≥1 match
  totalMatched: number;       // number of events with ≥1 match
}

/** Rank a severity — lower index is MORE severe (Critical=0 … Info=4). */
function severityRank(s: Severity): number {
  const i = SEVERITIES.indexOf(s);
  return i === -1 ? SEVERITIES.length : i;
}

/** The more severe of `current` and `proposed`; `current` wins ties and when `proposed` is absent. */
export function raiseSeverity(current: Severity, proposed?: Severity): Severity {
  if (!proposed) return current;
  return severityRank(proposed) < severityRank(current) ? proposed : current;
}

function uniqPush(into: string[], seen: Set<string>, values: readonly string[]): void {
  for (const v of values) {
    if (!seen.has(v)) { seen.add(v); into.push(v); }
  }
}

/** Evaluate every rule against every event. Pure — no mutation of inputs, no I/O. */
export function runTagger(events: readonly ForensicEvent[], ruleset: CompiledRuleset): TaggerResult {
  // Per-event accumulators, built lazily so events with no match never allocate.
  const byEvent = new Map<string, { res: EventTagResult; tagSeen: Set<string>; mitreSeen: Set<string> }>();
  const perRule: RuleMatch[] = [];

  for (const rule of ruleset.rules) {
    const eventIds: string[] = [];
    for (const event of events) {
      if (!matchEvent(event, rule)) continue;
      eventIds.push(event.id);
      let slot = byEvent.get(event.id);
      if (!slot) {
        slot = { res: { eventId: event.id, tags: [], mitre: [], severity: undefined, ruleIds: [] }, tagSeen: new Set(), mitreSeen: new Set() };
        byEvent.set(event.id, slot);
      }
      uniqPush(slot.res.tags, slot.tagSeen, rule.tags);
      uniqPush(slot.res.mitre, slot.mitreSeen, rule.mitre);
      slot.res.ruleIds.push(rule.id);
      if (rule.severity) {
        slot.res.severity = slot.res.severity ? raiseSeverity(slot.res.severity, rule.severity) : rule.severity;
      }
    }
    perRule.push({
      id: rule.id,
      description: rule.description,
      view: rule.view,
      tags: rule.tags,
      mitre: rule.mitre,
      severity: rule.severity,
      eventIds,
      matched: eventIds.length,
    });
  }

  const perEvent = [...byEvent.values()].map((s) => s.res);
  return { perRule, perEvent, totalMatched: perEvent.length };
}

/**
 * Apply an event's tagger proposal to a forensic event: raise (never lower) its severity and UNION
 * (never remove) its MITRE techniques. Returns a NEW event; the input is left untouched. Tags are
 * NOT written onto the event here — they live in TagsStore, applied by the caller. Idempotent:
 * re-applying the same result yields an equal event.
 */
export function applyToForensicEvent(event: ForensicEvent, result: EventTagResult): ForensicEvent {
  const severity = raiseSeverity(event.severity, result.severity);
  const seen = new Set(event.mitreTechniques);
  const mitreTechniques = [...event.mitreTechniques];
  for (const t of result.mitre) if (!seen.has(t)) { seen.add(t); mitreTechniques.push(t); }
  if (severity === event.severity && mitreTechniques.length === event.mitreTechniques.length) {
    return event; // nothing to change — preserve identity so callers can skip the write
  }
  return { ...event, severity, mitreTechniques };
}

/** The tagger's evaluation scope (mirrors readTaggerSettings() in taggerRun.ts). */
export type TaggerScope = "both" | "forensic" | "super";

/**
 * Select the events a tagger run/preview should evaluate for a given scope. For "both", union the
 * forensic timeline with the super timeline by id (forensic wins on overlap). Pure — no I/O.
 */
export function selectScopedEvents(
  scope: TaggerScope,
  forensic: readonly ForensicEvent[],
  superEvents: readonly ForensicEvent[],
): ForensicEvent[] {
  if (scope === "forensic") return [...forensic];
  if (scope === "super") return [...superEvents];
  const seen = new Set(forensic.map((e) => e.id));
  return [...forensic, ...superEvents.filter((e) => !seen.has(e.id))];
}
