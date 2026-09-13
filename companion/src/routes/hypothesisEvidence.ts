import type { Express, Request, Response } from "express";
import { FalsePositiveStore, falsePositiveEventIds } from "../analysis/falsePositive.js";
import {
  assessHypothesisEvidence,
  describeHypothesisEvidence,
  hypothesisQualifier,
  type AssessmentEligibility,
  type EvidenceRow,
  type HypothesisAssessment,
} from "../analysis/hypothesisDiagnostics.js";
import type { Hypothesis } from "../analysis/hypothesis.js";
import type { ForensicEvent } from "../analysis/stateTypes.js";
import { sendPipelineError } from "./presidioApproval.js";
import type { RouteContext } from "./context.js";

// Hypothesis evidence (#933 item 22): the GET that hands the dashboard each hypothesis with its
// evidence assessment, and the analyst's audit-trailed exclusions. The assessment is computed at
// read time from the stored lists and the case timeline, never persisted — so it is always current
// against the live set of alternatives. CRUD for the hypotheses themselves stays in aiSynthesis.ts.

// What the dashboard receives per hypothesis. `evidence` resolves each id the assessment names to
// the event's time/description/uncertainty so the card need not look events up itself.
export interface HypothesisView extends Hypothesis {
  assessment: HypothesisAssessment;
  qualifier: string;
  evidence: EvidenceRow[];
}

export function withAssessments(
  hypotheses: readonly Hypothesis[],
  events: readonly ForensicEvent[],
  elig: AssessmentEligibility,
): HypothesisView[] {
  const assessments = assessHypothesisEvidence(hypotheses, elig);
  return hypotheses.map((h) => {
    const assessment = assessments.get(h.id)!;
    return {
      ...h,
      assessment,
      qualifier: hypothesisQualifier(h, assessment),
      evidence: [...describeHypothesisEvidence(assessment, events).values()],
    };
  });
}

export function registerHypothesisEvidenceRoutes(app: Express, ctx: RouteContext): void {
  const { store, options } = ctx;
  const falsePositives = new FalsePositiveStore(store);

  app.get("/cases/:id/hypotheses", async (req: Request, res: Response) => {
    if (!options.hypothesisStore) return res.status(501).json({ error: "hypotheses not configured" });
    try {
      const hypotheses = await options.hypothesisStore.load(req.params.id);
      // Eligibility: the case timeline as stored, minus the analyst's false-positive marks. Without a
      // state store every linked id is taken as present — the reading then says less, never more.
      const state = options.stateStore ? await options.stateStore.load(req.params.id) : null;
      const events = state?.forensicTimeline ?? [];
      const elig: AssessmentEligibility = {
        eligibleEventIds: state ? new Set(events.map((e) => e.id)) : undefined,
        falsePositiveEventIds: falsePositiveEventIds(await falsePositives.load(req.params.id)),
      };
      return res.status(200).json(withAssessments(hypotheses, events, elig));
    } catch (err) {
      return sendPipelineError(res, err);
    }
  });

  // Exclude one linked observation from this hypothesis's assessment. Body: { eventId, reason, by? }.
  // The event, the link and every other hypothesis's reading are untouched.
  app.post("/cases/:id/hypotheses/:hid/exclusions", async (req: Request, res: Response) => {
    if (!options.hypothesisStore) return res.status(501).json({ error: "hypotheses not configured" });
    const eventId = typeof req.body?.eventId === "string" ? req.body.eventId.trim() : "";
    const reason = typeof req.body?.reason === "string" ? req.body.reason.trim() : "";
    if (!eventId) return res.status(400).json({ error: "eventId is required" });
    if (!reason) return res.status(400).json({ error: "a reason is required — it is the audit trail" });
    const by = typeof req.body?.by === "string" ? req.body.by : "analyst";
    try {
      const out = await options.hypothesisStore.excludeEvidence(
        req.params.id,
        req.params.hid,
        eventId,
        reason,
        by,
      );
      if (out === "not-found") return res.status(404).json({ error: "hypothesis not found" });
      if (out === "not-linked")
        return res.status(400).json({ error: "that observation is not linked to this hypothesis" });
      options.onHypotheses?.(req.params.id);
      return res.status(200).json(out);
    } catch (err) {
      return sendPipelineError(res, err);
    }
  });

  // Restore an excluded observation. The exclusion entry stays, dated and signed, as history.
  app.delete("/cases/:id/hypotheses/:hid/exclusions/:eventId", async (req: Request, res: Response) => {
    if (!options.hypothesisStore) return res.status(501).json({ error: "hypotheses not configured" });
    const by = typeof req.query?.by === "string" ? req.query.by : "analyst";
    try {
      const out = await options.hypothesisStore.restoreEvidence(
        req.params.id,
        req.params.hid,
        req.params.eventId,
        by,
      );
      if (!out) return res.status(404).json({ error: "no active exclusion for that observation" });
      options.onHypotheses?.(req.params.id);
      return res.status(200).json(out);
    } catch (err) {
      return sendPipelineError(res, err);
    }
  });
}
