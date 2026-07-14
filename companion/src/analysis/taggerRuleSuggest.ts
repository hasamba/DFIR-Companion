// Natural-language → content-tagger rule (PR #112 follow-up). The AI returns a JSON object
// describing ONE tagger rule (or a decline reason); this PURE module parses that reply leniently
// (like queryTranslate.ts), validates the proposed rule through the REAL compiler
// (compileRuleset), and emits a single-entry YAML map ready to preview/add. It never performs I/O
// and never returns a rule that would not compile — a malformed reply becomes a friendly decline,
// so a broken rule can never reach the ruleset.

import { z } from "zod";
import { stringify as stringifyYaml } from "yaml";
import { compileRuleset } from "./taggerRules.js";

// Lenient response schema — every field has a default so a slightly-off reply still parses.
export const suggestedRuleResponseSchema = z.object({
  ruleId: z.string().catch(""),
  explanation: z.string().catch(""),
  decline: z.string().catch(""),   // non-empty ⇒ the model refused; `rule` is ignored
  rule: z.unknown().catch(null),   // the raw rule object; validated via compileRuleset below
});
export type SuggestedRuleResponse = z.infer<typeof suggestedRuleResponseSchema>;

// The outcome the pipeline hands back: a validated rule (ready to preview/add) or a decline reason.
export type SuggestOutcome =
  | { kind: "rule"; ruleId: string; explanation: string; ruleYaml: string }
  | { kind: "decline"; reason: string };

const MAX_ID_LEN = 60;
const MAX_TEXT_LEN = 1200;

/** Normalize a proposed id to `[a-z0-9_]` (tagger ids are YAML keys). Empty → `fallback`. */
export function slugifyRuleId(raw: string, fallback = "rule"): string {
  const s = raw.toLowerCase().replace(/[^a-z0-9]+/g, "_").replace(/^_+|_+$/g, "").slice(0, MAX_ID_LEN);
  return s || fallback;
}

/**
 * Turn a parsed AI reply into a SuggestOutcome. Declines pass through. Otherwise the proposed rule
 * is validated by compiling a one-entry ruleset `{ ruleId: rule }`; on ANY compile error the result
 * is a decline ("couldn't turn that into a valid rule"), never a broken rule.
 */
export function sanitizeSuggestedRule(parsed: SuggestedRuleResponse): SuggestOutcome {
  const decline = parsed.decline.trim();
  if (decline) return { kind: "decline", reason: decline.slice(0, MAX_TEXT_LEN) };

  if (parsed.rule === null || parsed.rule === undefined) {
    return { kind: "decline", reason: "The AI did not return a rule. Try rephrasing the request." };
  }

  const ruleId = slugifyRuleId(parsed.ruleId);
  const singleEntry = { [ruleId]: parsed.rule };
  try {
    compileRuleset(singleEntry); // throws with a human-readable message on any problem
  } catch (err) {
    return {
      kind: "decline",
      reason: `Couldn't turn that into a valid rule — try rephrasing. (${(err as Error).message})`.slice(0, MAX_TEXT_LEN),
    };
  }
  return { kind: "rule", ruleId, explanation: parsed.explanation.trim().slice(0, MAX_TEXT_LEN), ruleYaml: stringifyYaml(singleEntry) };
}
