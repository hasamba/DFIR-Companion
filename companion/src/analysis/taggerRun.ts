// Applying the tagger to a case: the seam shared by the manual "Run tagger" route and the
// automatic post-import hook in the pipeline. It runs the (pure) tagger over a scoped event set,
// writes the resulting tags through TagsStore (authored `tagger:<ruleId>` so they are separable from
// analyst tags and reversible), and — unless scope is super-only — returns a NEW forensic timeline
// with severity raised / MITRE unioned. Persisting the timeline is the caller's job (the route saves
// state; the pipeline folds it into the state it is already about to save).

import type { ForensicEvent } from "./stateTypes.js";
import { normalizeLabel, type TagsStore } from "./tags.js";
import { runTagger, applyToForensicEvent, type TaggerResult } from "./tagger.js";
import type { CompiledRuleset } from "./taggerRules.js";

/** Author prefix stamped on every tagger-written tag; `<ruleId>` follows. */
export const TAGGER_AUTHOR_PREFIX = "tagger:";

export type TaggerScope = "both" | "forensic" | "super";

export interface TaggerSettings {
  auto: boolean; // run automatically after every import
  scope: TaggerScope;
}

/** Read the tagger settings from the environment (TAGGER_AUTO / TAGGER_SCOPE). */
export function readTaggerSettings(env: NodeJS.ProcessEnv = process.env): TaggerSettings {
  const auto = (env.TAGGER_AUTO ?? "true").trim().toLowerCase();
  const rawScope = (env.TAGGER_SCOPE ?? "both").trim().toLowerCase();
  const scope: TaggerScope = rawScope === "forensic" || rawScope === "super" ? rawScope : "both";
  return { auto: auto !== "false" && auto !== "0" && auto !== "off", scope };
}

export interface RunAndApplyParams {
  caseId: string;
  events: readonly ForensicEvent[]; // the scoped set to EVALUATE (already selected by scope)
  ruleset: CompiledRuleset;
  forensicTimeline: readonly ForensicEvent[]; // current forensic timeline (mapped for severity/MITRE)
  tagsStore: TagsStore;
  mutateForensic: boolean; // false when scope === "super" (raw timeline only)
}

export interface RunAndApplyResult {
  result: TaggerResult;
  forensicTimeline: ForensicEvent[]; // new array (or the same reference when nothing changed)
  tagsWritten: number; // tags actually created (idempotent adds don't recount duplicates)
  mutatedCount: number; // forensic events whose severity/MITRE changed
}

/**
 * Run the ruleset over `events`, write tags, and (unless super-only) produce a mutated forensic
 * timeline. Pure except for the TagsStore writes. Idempotent: TagsStore.add dedups, and
 * applyToForensicEvent is raise-only/union-only, so a second run over the same data is a no-op.
 */
export async function runAndApplyTagger(params: RunAndApplyParams): Promise<RunAndApplyResult> {
  const { caseId, events, ruleset, forensicTimeline, tagsStore, mutateForensic } = params;
  const result = runTagger(events, ruleset);

  // Write tags per rule so each tag's author records the rule that produced it. add() is idempotent
  // per (target, label), so a tag two rules both apply is created once (first author wins). Load the
  // existing tags ONCE and track written keys locally so `tagsWritten` counts only genuinely-new tags
  // (used for the "Run tagger" display total) without an O(n) reload per add.
  const seen = new Set(
    (await tagsStore.load(caseId).catch(() => [])).map((t) => `${t.targetId}\n${normalizeLabel(t.label)}`),
  );
  let tagsWritten = 0;
  for (const rule of result.perRule) {
    if (!rule.matched || rule.tags.length === 0) continue;
    const author = `${TAGGER_AUTHOR_PREFIX}${rule.id}`;
    for (const eventId of rule.eventIds) {
      for (const label of rule.tags) {
        await tagsStore.add(caseId, { targetType: "event", targetId: eventId, label, author });
        const key = `${eventId}\n${normalizeLabel(label)}`;
        if (!seen.has(key)) {
          seen.add(key);
          tagsWritten++;
        }
      }
    }
  }

  // Forensic severity/MITRE mutation (never on the raw super-timeline). Map only events present in
  // the forensic timeline; applyToForensicEvent preserves identity when nothing changes.
  let mutatedCount = 0;
  let newTimeline: ForensicEvent[] = forensicTimeline as ForensicEvent[];
  if (mutateForensic && result.perEvent.length) {
    const byId = new Map(result.perEvent.map((r) => [r.eventId, r]));
    newTimeline = forensicTimeline.map((e) => {
      const r = byId.get(e.id);
      if (!r) return e;
      const next = applyToForensicEvent(e, r);
      if (next !== e) mutatedCount++;
      return next;
    });
  }

  return { result, forensicTimeline: newTimeline, tagsWritten, mutatedCount };
}
