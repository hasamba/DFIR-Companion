import type { Express, Request, Response } from "express";
import { z } from "zod";
import { requestAuthentication } from "../auth/types.js";
import {
  ATTRIBUTION_TIERS,
  InvalidBuildsOnError,
  InvalidSupersedesIdError,
} from "../analysis/attributionAssertionStore.js";
import { matchAdversaryGroupId } from "../analysis/attributionGroupMatch.js";
import { loadAdversaryGroupsDataset } from "../analysis/adversaryGroupsData.js";
import { humanIdentityFor } from "./evidenceAttestation.js";
import type { RouteContext } from "./context.js";

/**
 * Decision-linked attribution assertions (#933 item 20) — an analyst's own claim that a
 * cluster/campaign/operator/sponsor label applies to activity in this case, kept structurally
 * separate from adversaryHints.ts's own statistical technique-overlap similarity (never a source
 * of automatic attribution — see attributionAssertionStore.ts's own header comment).
 *   - GET    /cases/:id/attribution-assertions        — every assertion (audit trail, all tiers),
 *     each optionally annotated with `matchedAdversaryGroupId` when its own `label` matches a
 *     known ATT&CK group name/alias (read-time only, informational, never written to the record).
 *   - POST   /cases/:id/attribution-assertions         — record one new assertion.
 *   - DELETE /cases/:id/attribution-assertions/:assertionId — retract one assertion.
 *
 * `:id` needs no isValidCaseId check: createApp mounts createCaseIdGate() on `/cases/:id`.
 *
 * WRITES REQUIRE A HUMAN IDENTITY, reusing routes/evidenceAttestation.ts's own `humanIdentityFor`
 * exactly — same trust model as every other analyst-attested store in this codebase.
 */

// Bounds and the periodStart/periodEnd ordering check are kept in exact sync with
// attributionAssertionSchema (attributionAssertionStore.ts) — same reasoning as
// huntRequirements.ts's own deadline-schema sync: a mismatch could turn a 400-class rejection
// into a store-level 500.
const createRequestSchema = z
  .object({
    tier: z.enum(ATTRIBUTION_TIERS),
    label: z.string().trim().min(1).max(200),
    sources: z.string().trim().min(1).max(2000),
    periodStart: z.string().datetime({ offset: true }).optional(),
    periodEnd: z.string().datetime({ offset: true }).optional(),
    alternatives: z.string().trim().min(1).max(2000),
    analystAssessment: z.string().trim().min(1).max(2000),
    relatedTechniqueIds: z.array(z.string()).max(200).optional(),
    relatedEventIds: z.array(z.string()).max(500).optional(),
    relatedIocIds: z.array(z.string()).max(500).optional(),
    buildsOn: z.array(z.string()).max(50).optional(),
    supersedesId: z.string().trim().min(1).max(200).optional(),
  })
  .refine(
    (a) =>
      !a.periodStart || !a.periodEnd || new Date(a.periodEnd).getTime() >= new Date(a.periodStart).getTime(),
    { message: "periodEnd must not be before periodStart", path: ["periodEnd"] },
  );

export function registerAttributionAssertionRoutes(app: Express, ctx: RouteContext): void {
  const { options } = ctx;

  function configured(res: Response): boolean {
    if (!options.attributionAssertionStore) {
      res.status(501).json({ error: "attribution-assertion store not configured" });
      return false;
    }
    return true;
  }

  function humanIdentity(req: Request): string | null {
    return humanIdentityFor(requestAuthentication(req), Boolean(options.teamAuth));
  }

  app.get("/cases/:id/attribution-assertions", async (req: Request, res: Response) => {
    if (!configured(res)) return;
    try {
      const all = await options.attributionAssertionStore!.load(req.params.id);
      // The AdversaryGroup cross-reference is optional and informational — a failure loading the
      // bundled dataset must never break the primary audit-trail read.
      let groups: ReturnType<typeof loadAdversaryGroupsDataset>["groups"] = [];
      try {
        groups = loadAdversaryGroupsDataset().groups;
      } catch {
        groups = [];
      }
      const byId = new Map(all.map((a) => [a.id, a]));
      const annotated = all.map((a) => ({
        ...a,
        matchedAdversaryGroupId: matchAdversaryGroupId(a.label, groups),
        // Retraction never cascades silently (design doc's own guardrail): flag it instead.
        buildsOnRetracted: a.buildsOn.some((id) => byId.get(id)?.status === "retracted"),
      }));
      return res.status(200).json({ assertions: annotated });
    } catch (err) {
      return res.status(500).json({ error: (err as Error).message });
    }
  });

  app.post("/cases/:id/attribution-assertions", async (req: Request, res: Response) => {
    if (!configured(res)) return;
    // 403 here is reachable only for an AUTHENTICATED but non-human caller (a service token) —
    // an entirely unauthenticated request under real team-auth is already stopped upstream with
    // 401 before this handler runs; in local mode (no team-auth) humanIdentity() always returns
    // "local", so this branch never fires at all. Same posture as every sibling route reusing
    // humanIdentityFor (evidenceAttestation.ts, huntRequirements.ts).
    const createdBy = humanIdentity(req);
    if (!createdBy) {
      return res
        .status(403)
        .json({ error: "recording an attribution assertion requires a human analyst session" });
    }
    const parsed = createRequestSchema.safeParse(req.body);
    if (!parsed.success) {
      return res.status(400).json({ error: parsed.error.message });
    }
    try {
      const assertion = await options.attributionAssertionStore!.create(req.params.id, {
        ...parsed.data,
        createdBy,
        createdAt: new Date().toISOString(),
      });
      return res.status(200).json({ assertion });
    } catch (err) {
      if (err instanceof InvalidBuildsOnError || err instanceof InvalidSupersedesIdError) {
        return res.status(400).json({ error: err.message });
      }
      return res.status(500).json({ error: (err as Error).message });
    }
  });

  app.delete("/cases/:id/attribution-assertions/:assertionId", async (req: Request, res: Response) => {
    if (!configured(res)) return;
    const retractedBy = humanIdentity(req);
    if (!retractedBy) {
      return res
        .status(403)
        .json({ error: "retracting an attribution assertion requires a human analyst session" });
    }
    const reason = typeof req.body?.reason === "string" ? req.body.reason.trim().slice(0, 2000) : undefined;
    try {
      const assertions = await options.attributionAssertionStore!.retract(
        req.params.id,
        req.params.assertionId,
        retractedBy,
        new Date().toISOString(),
        reason,
      );
      return res.status(200).json({ assertions });
    } catch (err) {
      return res.status(500).json({ error: (err as Error).message });
    }
  });
}
