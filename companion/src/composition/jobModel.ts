// Which model is running this job.
//
// Reported from the jobs popover: three synthesis rows in a row, each "failed — Claude Code timed
// out after 180000ms", and nothing on any of them said which model had timed out. The analyst
// could not tell "my synthesis model is too slow for this case" from "one run was unlucky", which
// is the only question that panel gets opened to answer.
//
// ONE RESOLVER, NOT EIGHT CALL SITES. Eight places register jobs and three of them
// (routes/aiSynthesis.ts, routes/import.ts, routes/mcp.ts) are frozen by the file-size ledger —
// which is the gate telling you to put new code in its own module rather than grow them. It is
// also the better shape on its own: "which model runs a synthesis" now has one answer instead of
// three that can drift apart, and a new AI job kind is a line here rather than a field someone
// forgets to pass.
//
// THE MODEL IS PINNED AT REGISTRATION, never read at render time. A job outlives a Settings
// change, so a row that re-read env would rename its own history and misattribute every finished
// run — the opposite of what the analyst opened the panel for.
import type { AnalysisPipeline } from "../analysis/pipeline.js";
import type { RegisterInput } from "../analysis/jobManager.js";
import { isAiDependent } from "../routes/importKinds.js";

/**
 * Builds the resolver createApp installs on the job manager. Returns undefined for any job no
 * model runs, and the row then shows no model rather than a guess:
 *
 *   - enrichment  — Hashlookup, reverse DNS, WHOIS and GeoIP are HTTP lookups, not inference.
 *   - mcp         — the model is whatever the Claude Code CLI defaults to unless DFIR_MCP_MODEL is
 *                   set, and naming a default nobody chose would be a guess dressed as a fact.
 *   - import      — only a csv/log import runs a model (isAiDependent); every other kind, and the
 *                   Velociraptor collect that borrows an import slot, parses locally.
 */
export function jobModelResolver(
  pipeline?: Pick<AnalysisPipeline, "analysisTextProviderModel">,
): (input: RegisterInput) => string | undefined {
  // Synthesis, deep pass and csv/log extraction are all TEXT work, and the pipeline resolves text
  // work to one provider (DFIR_AI_SYNTH_*, falling back to the vision config). Asked of the
  // pipeline rather than of process.env so the answer is the provider instance that will actually
  // run, not what the .env file says it should have been.
  const textModel = (): string | undefined => pipeline?.analysisTextProviderModel()?.model;
  return (input) => {
    if (input.kind === "synthesis" || input.kind === "deep-pass") return textModel();
    if (input.kind !== "import") return undefined;
    const kind = input.parameters?.kind;
    return typeof kind === "string" && isAiDependent(kind) ? textModel() : undefined;
  };
}
