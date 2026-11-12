import { FAMILY_LABELS, type MainSourceResult } from "./caseMainSource.js";

// Synthesis reads the main source and its note together; one import for both.
export { computeMainSource, type MainSourceResult } from "./caseMainSource.js";
import { enabledHuntPlatforms, huntLanguageFor, LANGUAGE_LABELS } from "./huntLanguage.js";
import type { HuntPlatform } from "./huntPlatforms.js";

/**
 * The synthesis note that steers AI next steps toward the case's main evidence source (#2594).
 *
 * The core synthesis prompt asks for "the Velociraptor artifact or tool" on a collect target. On a
 * Falcon or Splunk case that sends the analyst to the wrong tool, so this user-prompt note names the
 * source and its query language. It goes in the user prompt, not the system prompt: the analyst
 * chose that over an evaluation-gated system-prompt edit.
 *
 * "" — and so a prompt and skip-hash identical to before — whenever the answer is Velociraptor
 * anyway: a Velociraptor or host-tool case, no evidence yet, or a source whose platform is disabled
 * (the hunts fall back to VQL). The main source counts forensic-timeline files only (§7).
 */
export function renderMainSourceBlock(
  effective: MainSourceResult["effective"],
  enabled: readonly HuntPlatform[] = enabledHuntPlatforms(),
): string {
  if (effective === "mixed")
    return (
      "MIXED EVIDENCE: no single tool holds most of the evidence. For a next step that searches " +
      "existing evidence, and for a collect target, name the tool that holds the evidence that step is " +
      "about (for example CrowdStrike Falcon, Splunk or Velociraptor) and what to search there.\n\n"
    );
  if (effective === null) return "";
  if (effective === "cloud-other")
    return (
      `MAIN EVIDENCE SOURCE: ${FAMILY_LABELS[effective]}. For a next step that searches existing evidence, ` +
      "and for a collect target these logs serve, name the cloud log (for example CloudTrail or the Okta " +
      "System Log) and the field to search — not a Velociraptor artifact — unless the step needs " +
      "collection from an endpoint.\n\n"
    );
  const { language } = huntLanguageFor(effective, enabled);
  if (!language || language === "vql") return "";
  const tool = FAMILY_LABELS[effective];
  const lang = LANGUAGE_LABELS[language];
  return (
    `MAIN EVIDENCE SOURCE: ${tool} — searches are written in ${lang}. For a next step that searches ` +
    `existing evidence, and for a collect target ${tool} serves, name ${tool} and the table, index or ` +
    `field to search there, in ${lang} terms — not a Velociraptor artifact — unless the step needs ` +
    "collection from an endpoint.\n\n"
  );
}
