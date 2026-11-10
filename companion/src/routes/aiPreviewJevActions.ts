import {
  recordAiPreviewCapture,
  type AiPreviewCapture,
  type AiPreviewPresidio,
} from "../analysis/ai/aiPreviewScope.js";
import type { JevQuestion } from "../analysis/ai/jev/jevClient.js";
import { resolveJevSettings, type JevSettings } from "../analysis/ai/jev/jevConfig.js";
import { batchJevState, gradeEvents } from "../analysis/ai/jev/jevGrader.js";
import { buildContainmentState } from "../analysis/ai/jev/containmentState.js";
import { CONTAINMENT_QUESTIONS } from "../analysis/ai/jev/containmentQuestions.js";
import { AnonymizationChangedError, anonRevision } from "../analysis/anonRevision.js";
import { containmentRequest } from "./containmentCheckPrepare.js";
import { jevMasking, type JevMasking } from "./jevMasking.js";
import { jevScanText } from "./jevPresidioGate.js";
import { reviewCaseContext, selectReviewRows, type ReviewRequest } from "./jevReviewPrepare.js";
import type { RouteContext } from "./context.js";
import type { RouteAiPreviewAction } from "./aiPreviewRouteAction.js";

/**
 * "Preview what the AI will see" for the two decision-model (Jev) requests (#2515): the missed-evidence
 * review and the containment check.
 *
 * They do not go through the AI-call gate, so the preview runs their own preparation — the SAME
 * functions the real routes call (jevReviewPrepare.ts, containmentCheckPrepare.ts, the shared masking
 * step) — and stops where the route would call Jev. Nothing is sent, no cost or grade is recorded, no
 * activity entry, no job; the read-only storage scope refuses any write.
 *
 * The clear view is built from EXACTLY the rows the masked request carries: the review hands its batch
 * to the capture, and the containment view keeps exactly the events the masked build selected. Jev
 * plans batches and truncates rows on MASKED text, so rebuilding the clear view independently could
 * show different rows.
 */

interface JevBuilt extends JevMasking {
  readonly masked: unknown;
  readonly clear: unknown;
  readonly questions: Readonly<Record<string, JevQuestion>>;
}

/** What the real route's Presidio gate would do with this state, with nothing saved (#1952). */
async function jevPresidio(ctx: RouteContext, caseId: string, b: JevBuilt): Promise<AiPreviewPresidio> {
  const known = b.masker.known;
  const pipeline = ctx.options.pipeline;
  if (!known || !pipeline) return { state: "off", held: [] };
  return pipeline.presidioPreviewMasked(caseId, jevScanText(b.masked), known, b.masker.control);
}

/**
 * The capture, after the Presidio question. The real Jev routes mask once and HOLD a request whose
 * masked body went stale (#1840, `assertAnonRevision` before every attempt) — they never re-mask — so
 * a change during the preview ends it the same way, instead of showing a stale masking.
 */
async function captureJev(
  ctx: RouteContext,
  caseId: string,
  kind: string,
  settings: JevSettings,
  b: JevBuilt,
): Promise<AiPreviewCapture> {
  const presidio = await jevPresidio(ctx, caseId, b);
  if (anonRevision(caseId) !== b.maskedAt)
    throw new AnonymizationChangedError(
      "The anonymization settings or hidden values changed while the preview was being built, so the " +
        "real request would be held too. Run the preview again.",
    );
  return {
    kind,
    provider: "jev",
    model: settings.model,
    // A decision model has no system prompt: its instructions are the questions, sent unmasked.
    systemPrompt: JSON.stringify(b.questions, null, 2),
    clearPrompt: JSON.stringify(b.clear, null, 2),
    maskedPrompt: JSON.stringify(b.masked, null, 2),
    anonymized: b.masker.anon !== null,
    images: [],
    presidio,
    notes: [
      "A decision model receives a structured state, not a prompt: both panes show that state, laid out " +
        "for reading (the wire carries the same JSON on one line). The questions are in the instructions pane.",
    ],
  };
}

function jevSettingsOr(): JevSettings | string {
  const resolved = resolveJevSettings();
  return resolved.settings ?? resolved.reason ?? "the decision model is not configured";
}

const identity = (t: string): string => t;

/** The first batch the real review would send, from the same rows, mask and grader. */
async function previewReview(ctx: RouteContext, caseId: string, settings: JevSettings, body: ReviewRequest) {
  const { state, candidates } = await selectReviewRows(ctx.options, caseId, settings, body);
  if (!candidates.length) return; // the real review asks nothing either
  const masking = await jevMasking(ctx.store, caseId, state);
  const shape = settings.shape;
  const caseContext = await reviewCaseContext(ctx.store, caseId, shape, masking.masker.mask);
  // The REAL grader, stopped at its first request. Its `ask` hands over the batch, so the clear view
  // is the same rows under the same ids.
  await gradeEvents(
    {
      mask: masking.masker.mask,
      ask: (masked, questions, _halted, batch) =>
        recordAiPreviewCapture(async () =>
          captureJev(ctx, caseId, "jev-review", settings, {
            ...masking,
            masked,
            clear: batchJevState(
              batch.events,
              batch.ids,
              identity,
              shape,
              await reviewCaseContext(ctx.store, caseId, shape, identity),
            ),
            questions,
          }),
        ),
    },
    candidates,
    { batchSize: settings.batchSize, shape, caseContext },
  );
}

/** The state the real containment check would send for one finding. */
async function previewContainment(
  ctx: RouteContext,
  caseId: string,
  settings: JevSettings,
  findingId: string,
) {
  const state = await ctx.options.stateStore!.load(caseId);
  const built = await containmentRequest(ctx.store, caseId, state, findingId);
  if (!built) throw new Error(`finding ${findingId} not found`);
  // The clear view keeps exactly the events the masked build selected (its budget is on masked text).
  const clearAll = buildContainmentState(built.finding, state, identity, Number.POSITIVE_INFINITY).state;
  const keep = new Set(Object.keys(built.jevState.events));
  const clear = {
    ...clearAll,
    events: Object.fromEntries(Object.entries(clearAll.events).filter(([k]) => keep.has(k))),
  };
  return recordAiPreviewCapture(() =>
    captureJev(ctx, caseId, "containment-check", settings, {
      maskedAt: built.maskedAt,
      masker: built.masker,
      masked: built.jevState,
      clear,
      questions: CONTAINMENT_QUESTIONS,
    }),
  );
}

const MULTI_REVIEW =
  "The review asks once per batch of rows, several batches at a time. This is the first batch; the " +
  "later ones carry other rows the same way, so they are not previewed.";

export const JEV_PREVIEW_ACTIONS: Readonly<Record<string, RouteAiPreviewAction>> = {
  "jev-review": {
    label: "Missed-evidence review (decision model)",
    multiRequest: MULTI_REVIEW,
    needs: "jev",
    prepare: async (ctx, caseId, params) => {
      const settings = jevSettingsOr();
      if (typeof settings === "string") return settings;
      if (!ctx.options.superTimelineStore || !ctx.options.stateStore)
        return "the super-timeline is not configured";
      // The same body fields the review route reads: `all`, `limit`, `filters` (selectReviewRows).
      const filters =
        params.filters && typeof params.filters === "object" && !Array.isArray(params.filters)
          ? params.filters
          : undefined;
      const body: ReviewRequest = {
        all: params.all === true || params.all === "true",
        ...(params.limit !== undefined ? { limit: params.limit } : {}),
        ...(filters ? { filters } : {}),
      };
      return () => previewReview(ctx, caseId, settings, body);
    },
  },
  "containment-check": {
    label: "Containment check on a finding (decision model)",
    needs: "jev",
    prepare: async (ctx, caseId, params) => {
      const settings = jevSettingsOr();
      if (typeof settings === "string") return settings;
      if (!ctx.options.stateStore) return "investigation state not configured";
      const findingId = typeof params.findingId === "string" ? params.findingId.trim() : "";
      if (!findingId) return "findingId is required";
      return () => previewContainment(ctx, caseId, settings, findingId);
    },
  },
};
