// "Tagger rules" for the reports (#2349): which content-tagger rules graded the case's imports —
// the rules bundled with the app, a detection-rule pack (downloaded or installed from a file), an
// analyst-edited copy, or an operator file. The tagger's counterpart of the Sigma release line
// (detectionRules.ts).
//
// Read from the analysis-run ledger: every tagger run (automatic after an import, a bulk import, a
// manual Run tagger) records `configuration.parameters.rulePack`, a sentence the Companion writes
// itself (TaggerStore.provenance). A case graded by two packs over time names both, so an analyst
// can explain why the same event shape got different grades.

import type { AnalysisRunManifest } from "../analysis/analysisRunTypes.js";
import { escapeHtml } from "./escapeHtml.js";
import { oneLineMd } from "./mdText.js";

/** Every distinct tagger rule source in the ledger, first-seen order. */
export function taggerRuleSourcesIn(runs: readonly AnalysisRunManifest[]): string[] {
  const seen = new Set<string>();
  for (const run of runs) {
    const v = run.configuration?.parameters?.rulePack;
    if (typeof v === "string" && v.trim()) seen.add(v.trim().slice(0, 300));
  }
  return [...seen];
}

/** A Markdown section to append, or "" when no tagger run recorded its rules. */
export function taggerRulesMarkdown(sources: readonly string[]): string {
  if (sources.length === 0) return "";
  const lines = [
    "",
    "",
    "### Tagger rules",
    "",
    "Imported events were graded by the content tagger with these rules (each import's run is in analysis-runs.json):",
    "",
    ...sources.map((s) => `- ${oneLineMd(s)}`),
  ];
  return lines.join("\n");
}

/** The same, inserted before the HTML report's closing body tag. */
export function withTaggerRulesHtml(html: string, sources: readonly string[]): string {
  if (sources.length === 0) return html;
  const block = `<section class="meta"><h3>Tagger rules</h3><p>Imported events were graded by the content tagger with: ${sources
    .map(escapeHtml)
    .join(" · ")}</p></section>`;
  const at = html.toLowerCase().lastIndexOf("</body>");
  return at === -1 ? `${html}\n${block}` : `${html.slice(0, at)}${block}\n${html.slice(at)}`;
}
