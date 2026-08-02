import { buildAdversaryHintsResult } from "../adversaryHints.js";
import { loadAdversaryGroupsDataset, adversaryHintEnvOptions } from "../adversaryGroupsData.js";
import { gapEnvOptions } from "../gapDetect.js";
import { classifyImportYield, type ImportMetaStore, type ImportYieldWarning } from "../importMeta.js";
import { buildKnownUnknownItems, renderKnownUnknowns, type KnownUnknownItem } from "../knownUnknowns.js";
import { loadKnownPlaybooks } from "../knownPlaybooksData.js";
import { buildPlaybookMatchResult, playbookMatchEnvOptions } from "../playbookMatch.js";
import type { ForensicEvent, InvestigationState } from "../stateTypes.js";
import { loadScopedEvents, type AiCallContext } from "./aiContext.js";

/**
 * The derived prompt blocks more than one AI call feeds into its prompt (#418).
 *
 * Extracted from AnalysisPipeline as their own module rather than filed with either consumer,
 * because that is the point of them: synthesis and hunt suggestion must see the SAME gap list, and
 * the known-unknowns panel must show the analyst the same one again. A copy in each caller is how
 * those three drift apart.
 *
 * Everything here is DEFENSIVE by construction. A block is context, not evidence — a dataset that
 * fails to load, a corrupt import-meta file or a playbook match that throws must degrade to an empty
 * string, never fail the synthesis or the hunt call that was only decorating its prompt with it.
 */

/** What a block builder needs beyond the shared AI-call seam. */
export interface PromptBlockContext extends AiCallContext {
  readonly opts: AiCallContext["opts"] & { importMetaStore?: ImportMetaStore };
}

// The STRUCTURED known-unknowns for a case (investigation-guidance #9) — the SINGLE source the
// synthesis prompt block AND the GET /cases/:id/known-unknowns panel both consume, so the model and
// the analyst provably see the same gap list. Defensive: a failure here must never break synthesis.
export function knownUnknownItems(
  state: InvestigationState,
  scopedEvents: ForensicEvent[],
  yieldWarning?: ImportYieldWarning | null,
): KnownUnknownItem[] {
  try {
    const hints = buildAdversaryHintsResult(state, loadAdversaryGroupsDataset(), adversaryHintEnvOptions());
    // #230: the top playbook match, so an unobserved step of a chain the case otherwise follows
    // becomes a named gap. Scored over the SCOPED events, exactly as the panel and report see them.
    const playbook = buildPlaybookMatchResult(scopedEvents, loadKnownPlaybooks(), playbookMatchEnvOptions());
    return buildKnownUnknownItems(state, scopedEvents, {
      gapOptions: gapEnvOptions(),
      nextTechniques: hints.nextTechniques,
      playbookMatch: playbook.matches[0] ?? null,
      yieldWarning,
    });
  } catch {
    return [];
  }
}

// The classified source-yield warning for the LAST import (investigation-guidance #10) — a large file
// that yielded ZERO events via AI triage (the northpeak blind spot). Defensive: null when no store,
// no import-meta, or nothing anomalous.
export async function loadYieldWarning(
  ctx: PromptBlockContext,
  caseId: string,
): Promise<ImportYieldWarning | null> {
  if (!ctx.opts.importMetaStore) return null;
  try {
    return classifyImportYield(await ctx.opts.importMetaStore.load(caseId));
  } catch {
    return null;
  }
}

// Known-unknowns preamble (#165): the gaps in the story (silent windows, uncovered ATT&CK phases,
// the matched actors' likely-next techniques) so synthesis + hunts treat what's MISSING as open
// questions, not just what the evidence shows. Pure block; the offline adversary dataset is cached.
export async function knownUnknownsBlock(
  ctx: PromptBlockContext,
  state: InvestigationState,
  scopedEvents: ForensicEvent[],
  caseId: string,
): Promise<string> {
  const max = Math.max(0, Number(process.env.DFIR_SYNTH_KNOWN_UNKNOWNS_MAX) || 10);
  return renderKnownUnknowns(
    knownUnknownItems(state, scopedEvents, await loadYieldWarning(ctx, caseId)),
    max,
  );
}

// Read-only: the structured evidence-gap items for a case (scope + false-positive filtered, exactly
// as synthesis sees them). Powers the "Evidence gaps" dashboard panel and the report section.
export async function knownUnknownsForCase(
  ctx: PromptBlockContext,
  caseId: string,
): Promise<KnownUnknownItem[]> {
  const loaded = await ctx.opts.stateStore.load(caseId);
  const { scoped } = await loadScopedEvents(ctx, caseId, loaded);
  return knownUnknownItems(loaded, scoped, await loadYieldWarning(ctx, caseId));
}

// Candidate-threat-actor preamble (#165), OFF by default (DFIR_SYNTH_ADVERSARY_HINTS). Feeds the
// technique-overlap hints (already shown in the report) into synthesis as LOW-CONFIDENCE candidates.
// Gated because feeding model-derived attribution back into the model is a confirmation-bias loop;
// labelled "NOT attribution". Pure + cached dataset; defensive — never breaks synthesis.
export function adversaryHintBlock(state: InvestigationState): string {
  if (!/^(1|true|on|yes)$/i.test(process.env.DFIR_SYNTH_ADVERSARY_HINTS ?? "")) return "";
  try {
    const r = buildAdversaryHintsResult(state, loadAdversaryGroupsDataset(), adversaryHintEnvOptions());
    if (!r.hints.length) return "";
    const top = r.hints
      .slice(0, 5)
      .map((h) => `${h.name} (${h.overlapCount}/${h.groupTechniqueCount} techniques)`)
      .join(", ");
    return `CANDIDATE THREAT ACTORS (technique-overlap hypothesis, NOT attribution — ${r.caveat}): ${top}\n\n`;
  } catch {
    return "";
  }
}
