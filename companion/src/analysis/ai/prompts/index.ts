import { readFileSync } from "node:fs";
import { RECONCILE_PROMPT } from "../../secondOpinion.js";
import { CSV_SYSTEM_PROMPT, IMPORTER_PROMPT, LOG_SYSTEM_PROMPT, OBSERVE_PROMPT, SYSTEM_PROMPT } from "./extraction.js";
import { EXEC_SUMMARY_PROMPT, NARRATIVE_PROMPT, SYNTHESIS_PROMPT } from "./synthesis.js";
import { HUNT_SUGGEST_PROMPT, PLAYBOOK_HUNT_PROMPT, QUERY_TRANSLATE_PROMPT } from "./hunt.js";
import {
  ASK_PROMPT,
  EXPLAIN_EVENT_PROMPT,
  GAP_HYPOTHESIS_PROMPT,
  HYPOTHESIS_REVIEW_PROMPT,
  MEMORY_NEXTSTEP_PROMPT,
} from "./investigation.js";
import { FP_SIMILARITY_PROMPT, REMEDIATION_PROMPT, TAGGER_RULE_PROMPT } from "./findings.js";
import { SESSION_SUMMARY_PROMPT, STARRED_REPORT_PROMPT, VIEW_SUMMARY_PROMPT } from "./reporting.js";

/**
 * The prompt registry (#384, moved from pipeline.ts).
 *
 * The constants live in the themed files next door; this module owns the ONE thing that has to know
 * about all of them at once — resolving a built-in against its environment override. Splitting it
 * the other way (each theme resolving its own) would spread the override contract across six files
 * and make "what can an operator override?" unanswerable from any single place.
 *
 * Everything here is re-exported from pipeline.ts, because 23 modules and the eval harness import
 * these names from there.
 */

// --- User-overridable prompts -------------------------------------------------------
// Each of the four prompts above is the built-in DEFAULT. A user can override any of them
// from the environment (`companion/.env`), in priority order:
//   DFIR_AI_<NAME>_PROMPT       inline text (read at startup — restart to apply)
//   DFIR_AI_<NAME>_PROMPT_FILE  path to a file (re-read on each AI call — edit it and the
//                               change applies on the next analysis, no restart needed)
// <NAME> is one of: SYSTEM, CSV, LOG, SYNTH. A missing/unreadable/empty file logs a warning
// and falls back to the built-in prompt, so a typo never breaks analysis.
// `npm run prompts:eject` writes the four defaults to ./prompts as a starting point.
function resolvePrompt(name: "SYSTEM" | "CSV" | "LOG" | "SYNTH" | "ASK" | "EXEC" | "NARRATIVE" | "HUNTS" | "PBHUNTS" | "GAPHYP" | "MEMNEXT" | "QUERYXLATE" | "RECONCILE" | "IMPORTGEN" | "EXPLAIN" | "REMEDIATION" | "FPSIMILARITY" | "TAGGERRULE" | "HYPREVIEW" | "STARREDREPORT" | "VIEWSUMMARY" | "SESSIONSUMMARY" | "OBSERVE", fallback: string): string {
  const inline = process.env[`DFIR_AI_${name}_PROMPT`];
  if (inline && inline.trim().length > 0) return inline;
  const file = process.env[`DFIR_AI_${name}_PROMPT_FILE`];
  if (file && file.trim().length > 0) {
    try {
      const text = readFileSync(file, "utf8");
      if (text.trim().length > 0) return text;
      console.warn(`[DFIR] ${name} prompt file "${file}" is empty — using the built-in prompt.`);
    } catch (err) {
      console.warn(`[DFIR] could not read ${name} prompt file "${file}": ${(err as Error).message} — using the built-in prompt.`);
    }
  }
  return fallback;
}


export const getTaggerRulePrompt = (): string => resolvePrompt("TAGGERRULE", TAGGER_RULE_PROMPT);

// The built-in prompt text for each capability the drift check knows about (see promptCapabilities.ts),
// keyed by resolvePrompt name. Exported so the rot-guard test can assert each built-in still contains
// its own required markers (if a rewrite drops one, the drift check silently rots — the test catches it).
export const BUILTIN_PROMPT_BY_NAME: Record<string, string> = {
  SYNTH: SYNTHESIS_PROMPT,
  TAGGERRULE: TAGGER_RULE_PROMPT,
  OBSERVE: OBSERVE_PROMPT,
};
















export const getSystemPrompt = (): string => resolvePrompt("SYSTEM", SYSTEM_PROMPT);
export const getCsvPrompt = (): string => resolvePrompt("CSV", CSV_SYSTEM_PROMPT);
export const getLogPrompt = (): string => resolvePrompt("LOG", LOG_SYSTEM_PROMPT);
export const getSynthesisPrompt = (): string => resolvePrompt("SYNTH", SYNTHESIS_PROMPT);
export const getObservePrompt = (): string => resolvePrompt("OBSERVE", OBSERVE_PROMPT);

export const getAskPrompt = (): string => resolvePrompt("ASK", ASK_PROMPT);
export const getExecSummaryPrompt = (): string => resolvePrompt("EXEC", EXEC_SUMMARY_PROMPT);
export const getNarrativePrompt = (): string => resolvePrompt("NARRATIVE", NARRATIVE_PROMPT);
export const getHuntSuggestPrompt = (): string => resolvePrompt("HUNTS", HUNT_SUGGEST_PROMPT);
export const getPlaybookHuntPrompt = (): string => resolvePrompt("PBHUNTS", PLAYBOOK_HUNT_PROMPT);
export const getGapHypothesisPrompt = (): string => resolvePrompt("GAPHYP", GAP_HYPOTHESIS_PROMPT);
export const getMemoryNextStepPrompt = (): string => resolvePrompt("MEMNEXT", MEMORY_NEXTSTEP_PROMPT);
export const getQueryTranslatePrompt = (): string => resolvePrompt("QUERYXLATE", QUERY_TRANSLATE_PROMPT);
export const getReconcilePrompt = (): string => resolvePrompt("RECONCILE", RECONCILE_PROMPT);
export const getExplainEventPrompt = (): string => resolvePrompt("EXPLAIN", EXPLAIN_EVENT_PROMPT);
export const getRemediationPrompt = (): string => resolvePrompt("REMEDIATION", REMEDIATION_PROMPT);
export const getFpSimilarityPrompt = (): string => resolvePrompt("FPSIMILARITY", FP_SIMILARITY_PROMPT);
export const getHypothesisReviewPrompt = (): string => resolvePrompt("HYPREVIEW", HYPOTHESIS_REVIEW_PROMPT);
export const getStarredReportPrompt = (): string => resolvePrompt("STARREDREPORT", STARRED_REPORT_PROMPT);
export const getViewSummaryPrompt = (): string => resolvePrompt("VIEWSUMMARY", VIEW_SUMMARY_PROMPT);
export const getSessionSummaryPrompt = (): string => resolvePrompt("SESSIONSUMMARY", SESSION_SUMMARY_PROMPT);


export const getImporterPrompt = (): string => resolvePrompt("IMPORTGEN", IMPORTER_PROMPT);

// Re-exported so `import { SYSTEM_PROMPT } from ".../prompts/index.js"` works alongside the
// getters, and so pipeline.ts can re-export the whole surface in one statement.
export {
  CSV_SYSTEM_PROMPT,
  IMPORTER_PROMPT,
  LOG_SYSTEM_PROMPT,
  OBSERVE_PROMPT,
  SYSTEM_PROMPT,
} from "./extraction.js";
export { EXEC_SUMMARY_PROMPT, NARRATIVE_PROMPT, SYNTHESIS_PROMPT } from "./synthesis.js";
export { HUNT_SUGGEST_PROMPT, PLAYBOOK_HUNT_PROMPT, QUERY_TRANSLATE_PROMPT } from "./hunt.js";
export {
  ASK_PROMPT,
  EXPLAIN_EVENT_PROMPT,
  GAP_HYPOTHESIS_PROMPT,
  HYPOTHESIS_REVIEW_PROMPT,
  MEMORY_NEXTSTEP_PROMPT,
} from "./investigation.js";
export { FP_SIMILARITY_PROMPT, REMEDIATION_PROMPT, TAGGER_RULE_PROMPT } from "./findings.js";
export { SESSION_SUMMARY_PROMPT, STARRED_REPORT_PROMPT, VIEW_SUMMARY_PROMPT } from "./reporting.js";
