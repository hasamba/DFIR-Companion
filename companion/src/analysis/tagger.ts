// Content-based event tagger — the PURE runner. Given a set of events and a compiled ruleset, it
// reports what each rule matched and, per event, the aggregated tags / MITRE techniques / proposed
// severity. It NEVER performs I/O and NEVER mutates its inputs: applying the result to case state
// (writing tags through TagsStore, raising forensic-event severity) is the caller's job (the route
// / pipeline), so this stays trivially unit-testable and side-effect free.
//
// Invariants enforced here: MITRE is UNION-only and severity is RAISE-only (applyToForensicEvent) —
// a tagger rule can never remove a technique or downgrade a severity the AI assigned.

import type { ForensicEvent, Severity } from "./stateTypes.js";
import { matchEvent, SEVERITIES, type CompiledRuleset } from "./taggerRules.js";
import { withClrUsageLogNote } from "./clrUsageLogNote.js";

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
  tags: string[]; // union of matching rules' tags (order-stable, deduped)
  mitre: string[]; // union of matching rules' MITRE ids
  severity?: Severity; // the HIGHEST severity any matching rule requested (undefined if none set one)
  ruleIds: string[]; // ids of the rules that matched (drives per-tag authorship: `tagger:<id>`)
}

export interface TaggerResult {
  perRule: RuleMatch[]; // every rule, including 0-match ones (so a "Run tagger" report is complete)
  perEvent: EventTagResult[]; // only events with ≥1 match
  totalMatched: number; // number of events with ≥1 match
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
    if (!seen.has(v)) {
      seen.add(v);
      into.push(v);
    }
  }
}

/** Evaluate every rule against every event. Pure — no mutation of inputs, no I/O. */
export function runTagger(events: readonly ForensicEvent[], ruleset: CompiledRuleset): TaggerResult {
  const acc = createTaggerAccumulator(ruleset);
  acc.add(events);
  return acc.finish();
}

/**
 * runTagger, one batch at a time (#1444). Per-event accumulators are built lazily so rows with no
 * match never allocate, and the rule → matched-ids lists grow only with matches — so a 900k-row
 * super-timeline fed through eventBatches() costs the matches, never the case. `sampleSize` keeps
 * the first N matched events (in match order) for the dashboard's preview list; 0 keeps none.
 */
export interface TaggerAccumulator {
  add(events: readonly ForensicEvent[]): void;
  finish(): TaggerResult;
  sample(): ForensicEvent[];
}

export function createTaggerAccumulator(ruleset: CompiledRuleset, sampleSize = 0): TaggerAccumulator {
  const byEvent = new Map<string, { res: EventTagResult; tagSeen: Set<string>; mitreSeen: Set<string> }>();
  const idsByRule = ruleset.rules.map((): string[] => []);
  const sample: ForensicEvent[] = [];

  return {
    add(events) {
      ruleset.rules.forEach((rule, ruleIndex) => {
        const eventIds = idsByRule[ruleIndex];
        for (const event of events) {
          if (!matchEvent(event, rule)) continue;
          eventIds.push(event.id);
          let slot = byEvent.get(event.id);
          if (!slot) {
            slot = {
              res: { eventId: event.id, tags: [], mitre: [], severity: undefined, ruleIds: [] },
              tagSeen: new Set(),
              mitreSeen: new Set(),
            };
            byEvent.set(event.id, slot);
            if (sample.length < sampleSize) sample.push(event);
          }
          uniqPush(slot.res.tags, slot.tagSeen, rule.tags);
          uniqPush(slot.res.mitre, slot.mitreSeen, rule.mitre);
          slot.res.ruleIds.push(rule.id);
          if (rule.severity) {
            slot.res.severity = slot.res.severity
              ? raiseSeverity(slot.res.severity, rule.severity)
              : rule.severity;
          }
        }
      });
    },
    finish() {
      const perRule: RuleMatch[] = ruleset.rules.map((rule, ruleIndex) => ({
        id: rule.id,
        description: rule.description,
        view: rule.view,
        tags: rule.tags,
        mitre: rule.mitre,
        severity: rule.severity,
        eventIds: idsByRule[ruleIndex],
        matched: idsByRule[ruleIndex].length,
      }));
      const perEvent = [...byEvent.values()].map((s) => s.res);
      return { perRule, perEvent, totalMatched: perEvent.length };
    },
    sample: () => [...sample],
  };
}

/**
 * Apply an event's tagger proposal to a forensic event: raise (never lower) its severity and UNION
 * (never remove) its MITRE techniques. Returns a NEW event; the input is left untouched. Tags are
 * NOT written onto the event here — they live in TagsStore, applied by the caller. Idempotent:
 * re-applying the same result yields an equal event.
 */
export function applyToForensicEvent(input: ForensicEvent, result: EventTagResult): ForensicEvent {
  // The one rule whose meaning must reach the AI states it as a derived note (#1559).
  const event = withClrUsageLogNote(input, result.ruleIds);
  // A row the import attributed to the case's OWN collector keeps its import grade (#1477). The
  // rules that graded it Info read facts the tagger cannot see — the SYSTEM logon, the engine-written
  // script path under the collector's tool tree, the collector exe as parent — while the tagger reads
  // the retained raw message, where PersistenceSniper's `Add-Type … AdjPriv` matches the bundled
  // token-manipulation rule exactly as an intruder's would. Tags and MITRE still describe the row.
  // A row inside the host's own provisioning window keeps its capped grade too (#1529): the build
  // window is deterministic evidence the tagger cannot see, and a later manual "Run tagger" would
  // otherwise raise the provisioning-day log clear straight back to Critical.
  const severity =
    event.origin === "collector" || event.buildTime
      ? event.severity
      : raiseSeverity(event.severity, result.severity);
  const seen = new Set(event.mitreTechniques);
  const mitreTechniques = [...event.mitreTechniques];
  for (const t of result.mitre)
    if (!seen.has(t)) {
      seen.add(t);
      mitreTechniques.push(t);
    }
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

/**
 * selectScopedEvents, streamed (#1444): the same scope rule, but the super side arrives one batch
 * at a time from eventBatches() and is fed straight into the accumulator. `superBatches` is null
 * when no super-timeline store is configured — then "both" and "super" read exactly what they did
 * before: the forensic side, or nothing.
 */
export async function feedTaggerScope(
  acc: TaggerAccumulator,
  scope: TaggerScope,
  forensic: readonly ForensicEvent[],
  superBatches: AsyncIterable<readonly ForensicEvent[]> | null,
): Promise<void> {
  if (scope !== "super") acc.add(forensic);
  if (scope === "forensic" || !superBatches) return;
  const seen = scope === "both" ? new Set(forensic.map((e) => e.id)) : null;
  for await (const batch of superBatches) acc.add(seen ? batch.filter((e) => !seen.has(e.id)) : batch);
}
