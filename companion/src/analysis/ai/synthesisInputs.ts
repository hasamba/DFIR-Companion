import { createHash } from "node:crypto";
import type { AiControlStore } from "../aiControl.js";
import type { FalsePositiveMarker } from "../falsePositive.js";
import { renderPriorHuntsBlock } from "../huntOutcomes.js";
import type { HypothesisStore } from "../hypothesisStore.js";
import type { IncidentTypeStore } from "../incidentTypeStore.js";
import { renderIncidentTypeBlock } from "../incidentTypes.js";
import type { NotebookStore } from "../notebookStore.js";
import type { PlaybookTask } from "../playbook.js";
import type { PlaybookStore } from "../playbookStore.js";
import { renderPlaybookProgressBlock, renderRefutedHypothesesBlock } from "../priorWork.js";
import type { ScopeWindow } from "../scope.js";
import type { ForensicEvent, InvestigationState } from "../stateTypes.js";
import { loadHuntOutcomes, type HuntContext } from "./hunts.js";

/**
 * The PURE INPUTS to a synthesis run, and the hash that decides whether it needs to happen at all
 * (#453, split from `synthesize`).
 *
 * Every block here is something synthesis READS and never rewrites — the analyst's notebook, their
 * hypotheses, what prior hunts and playbook tasks already established, the incident type they
 * picked. That property is what makes them safe to hash: including anything synthesis rewrites
 * would make two consecutive runs hash differently and never skip.
 *
 * So the loading and the hashing belong together. They were ~110 lines apart in `synthesize`, and
 * the invariant tying them — "in this hash iff synthesis never rewrites it" — was a comment on the
 * hash asking you to go and check each one. Adding a block now means adding a field to
 * `SynthesisInputBlocks`, which is where the hash reads from.
 */

/** The stores the input blocks come from. `SynthesisContext` extends this. */
export interface SynthesisInputContext extends HuntContext {
  readonly opts: HuntContext["opts"] & {
    notebookStore?: NotebookStore;
    aiControlStore?: AiControlStore;
    hypothesisStore?: HypothesisStore;
    playbookStore?: PlaybookStore;
    incidentTypeStore?: IncidentTypeStore;
  };
}

/** Prompt blocks synthesis reads but never rewrites. Every one of them feeds the skip-hash. */
export interface SynthesisInputBlocks {
  notebookBlock: string;
  analystHypothesesBlock: string;
  refutedHypothesesBlock: string;
  priorHuntsBlock: string;
  playbookProgressBlock: string;
  incidentTypeBlock: string;
}

export interface SynthesisInputs {
  blocks: SynthesisInputBlocks;
  /** Also needed by the delta fold, to demote next-steps that repeat a completed task. */
  playbookTasks: PlaybookTask[];
}

/** Bounded so a case with a long hypothesis list can't crowd out the timeline. */
const MAX_OPEN_HYPOTHESES = 15;

export async function loadSynthesisInputs(
  ctx: SynthesisInputContext,
  caseId: string,
): Promise<SynthesisInputs> {
  const notebookBlock = await buildNotebookBlock(ctx, caseId);
  const hypotheses = await buildHypothesisBlocks(ctx, caseId);
  // Prior-work feedback (investigation-guidance #2): the hunt hit/miss ledger (#157, previously fed
  // only to the hunt prompts) and the playbook DONE/SKIPPED digest, so synthesis builds on completed
  // work and dead hunts instead of re-recommending them. A hit is a pivot; a miss is negative
  // evidence — either way, collecting one must trigger a fresh synthesis, hence the hash.
  const priorHuntsBlock = renderPriorHuntsBlock(await loadHuntOutcomes(ctx, caseId));
  const playbookTasks = ctx.opts.playbookStore ? await ctx.opts.playbookStore.load(caseId) : [];
  // Incident-type framing (#236): the one-line hint for the type the analyst picked at case
  // creation, so the model prioritizes ransomware / BEC / exfil techniques.
  const incidentType = ctx.opts.incidentTypeStore
    ? await ctx.opts.incidentTypeStore.loadType(caseId)
    : null;

  return {
    playbookTasks,
    blocks: {
      notebookBlock,
      analystHypothesesBlock: hypotheses.analyst,
      refutedHypothesesBlock: hypotheses.refuted,
      priorHuntsBlock,
      playbookProgressBlock: renderPlaybookProgressBlock(playbookTasks),
      incidentTypeBlock: renderIncidentTypeBlock(incidentType),
    },
  };
}

/**
 * Analyst notebook context: when both notebookStore and aiControlStore are wired and the analyst has
 * opted in (includeNotebook: true in ai-control.json), append the notebook entries to the synthesis
 * prompt so the AI incorporates investigator hypotheses.
 */
async function buildNotebookBlock(ctx: SynthesisInputContext, caseId: string): Promise<string> {
  if (!ctx.opts.notebookStore || !ctx.opts.aiControlStore) return "";
  const aiCtrl = await ctx.opts.aiControlStore.load(caseId);
  if (!aiCtrl.includeNotebook) return "";
  const entries = await ctx.opts.notebookStore.load(caseId);
  if (!entries.length) return "";
  return (
    "ANALYST NOTEBOOK (investigator notes and open questions — take these into account when synthesizing findings and the attacker path):\n" +
    entries.map((e) => `[${e.type.toUpperCase()}] ${e.text}`).join("\n") +
    "\n\n"
  );
}

/**
 * Two blocks off one store read.
 *
 * Analyst hypotheses as steering (issue #140): the investigator's OPEN, analyst-owned hypotheses, so
 * the model actively hunts evidence to support/refute them. It is NOT asked to flip their status —
 * those are frozen by mergeHypotheses and the analyst stays in control; the steering shows up as
 * findings/events the analyst then judges. Only analyst-authored or analyst-touched OPEN ones, which
 * are pure inputs never rewritten by synthesis, so hashing them cannot cause a re-synthesis loop.
 *
 * Refuted hypotheses feed back as NEGATIVE KNOWLEDGE (investigation-guidance #2): a theory the
 * analyst ruled out must not be re-asserted or re-opened.
 */
async function buildHypothesisBlocks(
  ctx: SynthesisInputContext,
  caseId: string,
): Promise<{ analyst: string; refuted: string }> {
  const store = ctx.opts.hypothesisStore;
  if (!store) return { analyst: "", refuted: "" };
  await applyHuntExhaustion(ctx, caseId);

  const all = await store.load(caseId);
  const open = all
    .filter((h) => h.status === "open" && !h.exhausted && (h.source === "analyst" || h.analystTouched))
    .slice(0, MAX_OPEN_HYPOTHESES);
  const analyst = open.length
    ? "ANALYST HYPOTHESES TO TEST (the investigator proposed these — actively look for evidence that " +
      "SUPPORTS or REFUTES each and surface it in findings/events; you may add a corroborating hypothesis, " +
      "but do NOT mark the analyst's own hypothesis resolved):\n" +
      open
        .map((h) => `- ${h.title}${h.expectedOutcome ? ` (decided by: ${h.expectedOutcome})` : ""}`)
        .join("\n") +
      "\n\n"
    : "";
  return { analyst, refuted: renderRefutedHypothesesBlock(all) };
}

/**
 * ACH exhaustion (investigation-guidance #14): before reading hypotheses, flag the ones whose linked
 * or technique-matched hunts have come back empty — so the negative-knowledge block and the "to
 * test" list reflect them. Derived from collected hunt outcomes; persisted; idempotent.
 */
async function applyHuntExhaustion(ctx: SynthesisInputContext, caseId: string): Promise<void> {
  const outcomes = await loadHuntOutcomes(ctx, caseId);
  const huntSignals = outcomes
    .filter((o) => o.status === "collected")
    .map((o) => ({
      ...(o.relatedHypothesisId ? { relatedHypothesisId: o.relatedHypothesisId } : {}),
      techniques: o.mitreTechniques ?? [],
      missed: o.foundEvidence === false,
      title: o.title,
    }));
  if (huntSignals.some((s) => s.missed))
    await ctx.opts.hypothesisStore?.applyExhaustion(caseId, huntSignals);
}

export interface SynthHashInput {
  /** The in-scope timeline the model would reason over. */
  scopedEvents: ForensicEvent[];
  iocs: InvestigationState["iocs"];
  scope: ScopeWindow;
  markers: FalsePositiveMarker[];
  blocks: SynthesisInputBlocks;
  /** Deep-pass observations: a pure input, but one that changes what the model can see. */
  observationsBlock: string;
}

/**
 * Skip-if-unchanged: hash only the STABLE INPUTS to synthesis.
 *
 * NOT the findings / MITRE / threads / summary, which synthesis itself rewrites — including those
 * would make two consecutive runs hash differently and never skip. If the inputs are identical to
 * the last successful run, the caller returns the saved state and makes no AI call.
 */
export function computeSynthHash(i: SynthHashInput): string {
  const b = i.blocks;
  return createHash("sha1")
    .update(
      JSON.stringify({
        ev: i.scopedEvents.map((e) => [e.id, e.severity, e.timestamp, e.description]),
        io: i.iocs.map((x) => [x.id, x.value, (x.enrichments ?? []).map((e) => e.verdict).join(",")]),
        sc: i.scope,
        lg: i.markers.map((m) => m.id),
        nb: b.notebookBlock,
        hy: b.analystHypothesesBlock,
        // Prior-work feedback (#2): completing a task, collecting a hunt, or refuting a hypothesis
        // changes these strings, so an otherwise-identical timeline re-synthesizes to fold in the
        // new negative knowledge instead of skipping. Pure inputs — synthesis never rewrites them.
        pw: b.priorHuntsBlock + b.playbookProgressBlock + b.refutedHypothesesBlock,
        // Re-picking the incident type reframes what the model should prioritize — an otherwise
        // identical timeline must re-synthesize rather than skip.
        it: b.incidentTypeBlock,
        // Deep-pass observations are a pure INPUT synthesis never rewrites, but they change what the
        // model can see — so a run carrying fresh ones must never be skipped as "inputs unchanged".
        ob: i.observationsBlock,
      }),
    )
    .digest("hex");
}
