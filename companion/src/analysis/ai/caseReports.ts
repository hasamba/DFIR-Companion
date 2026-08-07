import type { AIProvider } from "../../providers/provider.js";
import { z } from "zod";
import { buildMitigationsResult } from "../attackMitigations.js";
import { loadMitigationsDataset } from "../attackMitigationsData.js";
import { buildD3fendResult } from "../d3fendMap.js";
import { loadD3fendDataset, d3fendEnvOptions } from "../d3fendData.js";
import type { HypothesisStore } from "../hypothesisStore.js";
import { sanitizeHypothesisReviews, type HypothesisReviewItem } from "../hypothesis.js";
import {
  execSummarySchema,
  hypothesisReviewSchema,
  remediationPlanSchema,
  type ExecSummary,
  type RemediationPlan,
} from "../responseSchema.js";
import type { ForensicEvent, InvestigationState } from "../stateTypes.js";
import { buildSynthesisContext } from "../synthSelect.js";
import {
  getExecSummaryPrompt,
  getHypothesisReviewPrompt,
  getNarrativePrompt,
  getRemediationPrompt,
} from "./prompts/index.js";
import {
  callAiJson,
  fitTimelineText,
  loadScopedEvents,
  promptOverhead,
  type AiCallContext,
} from "./aiContext.js";

/**
 * The four "write me a document about this case" AI calls (#418).
 *
 * Moved from AnalysisPipeline, which held them as methods; each is now a free function taking an
 * AiCallContext, and the pipeline keeps a one-line delegation so every route and test is untouched.
 *
 * They belong together because they answer the same question with different audiences in mind —
 * what happened, for the report / for management / for the team that has to fix it / for the analyst
 * arguing with themselves. All four read the same in-scope, non-false-positive slice of the case,
 * ground themselves in the same synthesis context block, and are single-shot. Only the narrative
 * writes anything back, and only its own field.
 */

/** What the two hypothesis-aware reports need on top of the shared AI-call seam. */
export interface CaseReportContext extends AiCallContext {
  readonly opts: AiCallContext["opts"] & { hypothesisStore?: HypothesisStore };
}

/** `[timestamp] [severity] description` — the row shape for the two audience-facing reports. */
const renderPlainEvent = (e: ForensicEvent): string =>
  `[${e.timestamp || "(undated)"}] [${e.severity}] ${e.description.slice(0, 240)}`;

/** The same row with its id, for the calls whose answer must cite specific events back. */
const renderIdentifiedEvent = (e: ForensicEvent): string =>
  `[${e.id}] ${e.timestamp || "(undated)"} [${e.severity}] ${e.description.slice(0, 240)}`;

const findingsWithIds = (state: InvestigationState): string =>
  state.findings
    .slice(0, 150)
    .map((f) => `[${f.id}] [${f.severity}] ${f.title}`)
    .join("\n") || "(none)";

const findingsPlain = (state: InvestigationState): string =>
  state.findings
    .slice(0, 150)
    .map((f) => `[${f.severity}] ${f.title}`)
    .join("\n") || "(none)";

// Write the case's narrative timeline — the prose account that leads the report. The ONE report here
// that persists: it re-reads state after the AI call so imports/edits that arrived during it aren't
// clobbered, then saves only its own field.
export async function generateNarrative(
  ctx: AiCallContext,
  caseId: string,
): Promise<{ narrativeTimeline: string }> {
  const provider = ctx.opts.synthesisProvider ?? ctx.requireProvider("narrative generation");
  const loaded = await ctx.opts.stateStore.load(caseId);
  const { scoped } = await loadScopedEvents(ctx, caseId, loaded);

  const findingsText = findingsPlain(loaded);
  const contextBlock = buildSynthesisContext(loaded, scoped, await ctx.getKevCatalog());
  const narrativePrompt = getNarrativePrompt();
  const timelineText = fitTimelineText(
    scoped,
    renderPlainEvent,
    promptOverhead(narrativePrompt, contextBlock, loaded.attackerPath || "", findingsText),
  );

  const userPrompt =
    contextBlock +
    `ATTACKER PATH: ${loaded.attackerPath || "(not reconstructed)"}\n\n` +
    `FINDINGS:\n${findingsText}\n\n` +
    `FORENSIC TIMELINE (${scoped.length} in-scope events):\n${timelineText}\n\n` +
    `Write the narrative timeline as JSON.`;

  const narrativeSchema = z.object({ narrativeTimeline: z.string().catch("") });
  const result = await callAiJson(
    ctx,
    caseId,
    loaded,
    provider,
    "narrative",
    narrativePrompt,
    userPrompt,
    (raw) => narrativeSchema.parse(raw),
  );

  // Re-read state before saving so imports/edits that arrived during the AI call aren't clobbered.
  const fresh = await ctx.opts.stateStore.load(caseId);
  await ctx.opts.stateStore.save({ ...fresh, narrativeTimeline: result.narrativeTimeline });
  return result;
}

// Generate a management-facing executive summary of the case (single-shot, no state change).
// Text-only over the synthesized digest, like ask(); returns plain prose for the analyst to
// review and save into the report's executive-summary section.
export async function executiveSummary(ctx: AiCallContext, caseId: string): Promise<ExecSummary> {
  const provider = ctx.opts.synthesisProvider ?? ctx.requireProvider("executive summary");
  const loaded = await ctx.opts.stateStore.load(caseId);
  const { scoped } = await loadScopedEvents(ctx, caseId, loaded);

  const findingsText = findingsPlain(loaded);
  const contextBlock = buildSynthesisContext(loaded, scoped, await ctx.getKevCatalog());
  const timelineText = fitTimelineText(
    scoped,
    renderPlainEvent,
    promptOverhead(getExecSummaryPrompt(), contextBlock, loaded.attackerPath || "", findingsText),
  );

  const userPrompt =
    contextBlock +
    `ATTACKER PATH: ${loaded.attackerPath || "(not reconstructed)"}\n\n` +
    `FINDINGS:\n${findingsText}\n\n` +
    `FORENSIC TIMELINE (${scoped.length} in-scope events):\n${timelineText}\n\n` +
    `Write the executive summary as JSON.`;

  return callAiJson(
    ctx,
    caseId,
    loaded,
    provider,
    "exec-summary",
    getExecSummaryPrompt(),
    userPrompt,
    (raw) => execSummarySchema.parse(raw),
  );
}

// Incident-specific remediation plan (#178): a concrete, prioritized action list for the IR team,
// GROUNDED in the deterministic ATT&CK Mitigations for the case's techniques so the model turns
// generic guidance into specific steps instead of hallucinating. Single-shot, no state change.
export async function remediationPlan(ctx: AiCallContext, caseId: string): Promise<RemediationPlan> {
  const provider = ctx.opts.synthesisProvider ?? ctx.requireProvider("remediation plan");
  const loaded = await ctx.opts.stateStore.load(caseId);
  const { scoped } = await loadScopedEvents(ctx, caseId, loaded);
  const filtered: InvestigationState = { ...loaded, forensicTimeline: scoped };

  const findingsText =
    loaded.findings
      .slice(0, 100)
      .map(
        (f) =>
          `[${f.severity}] ${f.title}${f.mitreTechniques?.length ? ` (${f.mitreTechniques.join(", ")})` : ""}`,
      )
      .join("\n") || "(none)";

  const { mitigationsText, d3fendText } = renderControlGrounding(filtered);

  const contextBlock = buildSynthesisContext(loaded, scoped, await ctx.getKevCatalog());

  const userPrompt =
    contextBlock +
    `ATTACKER PATH: ${loaded.attackerPath || "(not reconstructed)"}\n\n` +
    `FINDINGS:\n${findingsText}\n\n` +
    `RECOMMENDED ATT&CK MITIGATIONS (use these as the basis for concrete steps):\n${mitigationsText}\n\n` +
    `RELEVANT D3FEND COUNTERMEASURES (the defensive technique/sensor for each — cite alongside the ATT&CK mitigation where it fits):\n${d3fendText}\n\n` +
    `Write the incident-specific remediation plan as JSON.`;

  return callAiJson(
    ctx,
    caseId,
    loaded,
    provider,
    "remediation",
    getRemediationPrompt(),
    userPrompt,
    (raw) => remediationPlanSchema.parse(raw),
  );
}

// On-demand hypothesis falsification review (issue #71). A focused, human-readable devil's-advocate
// pass over the OPEN hypotheses: for each, the plain-English evidence FOR and AGAINST it plus an
// ADVISORY recommended status. One text-only AI call; EPHEMERAL — no state change, and crucially it
// NEVER mutates a hypothesis's status (the analyst-freeze contract); the recommendation is surfaced for
// the analyst to apply. Returns { reviews: [] } with no AI call when there are no open hypotheses.
export async function hypothesisReview(
  ctx: CaseReportContext,
  caseId: string,
): Promise<{ reviews: HypothesisReviewItem[] }> {
  if (!ctx.opts.hypothesisStore) throw new Error("hypotheses not configured");
  const provider = ctx.opts.synthesisProvider ?? ctx.requireProvider("hypothesis review");
  const loaded = await ctx.opts.stateStore.load(caseId);

  const allHypotheses = await ctx.opts.hypothesisStore.load(caseId);
  // Review OPEN, non-exhausted hypotheses (analyst- or synthesis-authored). Resolved/exhausted ones
  // are already settled, so re-litigating them wastes tokens and invites status churn.
  const open = allHypotheses.filter((h) => h.status === "open" && !h.exhausted);
  if (!open.length) return { reviews: [] };

  const { scoped } = await loadScopedEvents(ctx, caseId, loaded);
  const validEventIds = new Set(scoped.map((e) => e.id));

  const userPrompt = await buildHypothesisReviewPrompt(ctx, loaded, scoped, open);

  const knownHypotheses = new Map(open.map((h) => [h.id, h.title] as const));
  return callAiJson(
    ctx,
    caseId,
    loaded,
    provider,
    "hypothesis-review",
    getHypothesisReviewPrompt(),
    userPrompt,
    (raw) => ({
      reviews: sanitizeHypothesisReviews(
        hypothesisReviewSchema.parse(raw).reviews,
        knownHypotheses,
        validEventIds,
      ),
    }),
  );
}

/**
 * The deterministic control grounding for a remediation plan: the ATT&CK mitigations mapped to this
 * case's techniques, and the D3FEND countermeasures (defensive techniques/sensors) for the same set,
 * so the plan can cite the relevant D3FEND control alongside each M-code. These are the facts the
 * model builds steps FROM — it does not get to invent a mitigation.
 */
function renderControlGrounding(filtered: InvestigationState): {
  mitigationsText: string;
  d3fendText: string;
} {
  const mit = buildMitigationsResult(filtered, loadMitigationsDataset());
  const d3f = buildD3fendResult(filtered, loadD3fendDataset(), d3fendEnvOptions());
  return {
    mitigationsText:
      mit.byMitigation
        .slice(0, 30)
        .map((m) => `- ${m.id} ${m.name} (covers ${m.techniques.join(", ")}): ${m.description}`)
        .join("\n") || "(no mapped ATT&CK mitigations)",
    d3fendText:
      d3f.byTactic
        .flatMap((g) =>
          g.countermeasures.map((c) => `- ${c.name} [${c.tactic}] (covers ${c.techniques.join(", ")})`),
        )
        .slice(0, 40)
        .join("\n") || "(no mapped D3FEND countermeasures)",
  };
}

/** Just the fields the review prompt renders — not the full stored hypothesis. */
interface OpenHypothesis {
  id: string;
  title: string;
  expectedOutcome?: string;
  relatedEventIds: string[];
  contradictingEventIds: string[];
}

/** The review prompt: case grounding, then the timeline trimmed to whatever budget is left. */
async function buildHypothesisReviewPrompt(
  ctx: CaseReportContext,
  loaded: InvestigationState,
  scoped: ForensicEvent[],
  open: OpenHypothesis[],
): Promise<string> {
  const findingsText = findingsWithIds(loaded);
  const contextBlock = buildSynthesisContext(loaded, scoped, await ctx.getKevCatalog());
  const hypothesesText = renderOpenHypotheses(open);
  const timelineText = fitTimelineText(
    scoped,
    renderIdentifiedEvent,
    promptOverhead(
      getHypothesisReviewPrompt(),
      contextBlock,
      loaded.attackerPath || "",
      findingsText,
      hypothesesText,
    ),
  );
  return (
    contextBlock +
    `ATTACKER PATH: ${loaded.attackerPath || "(not reconstructed)"}\n\n` +
    `FINDINGS:\n${findingsText}\n\n` +
    `FORENSIC TIMELINE (${scoped.length} in-scope events):\n${timelineText}\n\n` +
    `OPEN HYPOTHESES TO REVIEW:\n${hypothesesText}\n\n` +
    `Review each open hypothesis for supporting AND refuting evidence, and return the JSON.`
  );
}

/**
 * The open hypotheses with the evidence already linked to them, so the model reviews the
 * analyst's/synthesis's current picture rather than starting cold.
 */
function renderOpenHypotheses(open: OpenHypothesis[]): string {
  return open
    .map((h) => {
      const parts = [`[${h.id}] ${h.title}`];
      if (h.expectedOutcome) parts.push(`    decided by: ${h.expectedOutcome}`);
      if (h.relatedEventIds.length)
        parts.push(`    currently-supporting events: ${h.relatedEventIds.join(", ")}`);
      if (h.contradictingEventIds.length)
        parts.push(`    known contradicting events: ${h.contradictingEventIds.join(", ")}`);
      return parts.join("\n");
    })
    .join("\n");
}
