import type { Express, Request, Response } from "express";
import { z } from "zod";
import { requestAuthentication } from "../auth/types.js";
import { resolvedSubjectScopeSchema } from "../analysis/hypothesis.js";
import { loadHostAliasIndex } from "../analysis/hostScopeLoad.js";
import { buildHuntChecklist } from "../analysis/huntRequirementChecklist.js";
import { humanIdentityFor } from "./evidenceAttestation.js";
import type { RouteContext } from "./context.js";

/**
 * Decision-linked hunting and collection requirements (#933 item 17) — an internal storage/API
 * foundation, same scoping choice already made for collectionGenerationStore (#1108): no dashboard
 * authoring panel in v1, route-only. Turns an analyst's own decision/audience/deadline/scope/
 * expected-evidence statement into a bounded, READ-ONLY checklist computed live from the case's
 * existing events and hypotheses — never a hunt execution, never an auto-collection, never a
 * provider query, never an indicator block.
 *   - GET    /cases/:id/hunt-requirements                    — every requirement (audit trail).
 *   - GET    /cases/:id/hunt-requirements/:reqId/checklist   — the live checklist for one requirement.
 *   - POST   /cases/:id/hunt-requirements                    — record one new requirement.
 *   - DELETE /cases/:id/hunt-requirements/:reqId             — revoke one requirement.
 *
 * `:id` needs no isValidCaseId check: createApp mounts createCaseIdGate() on `/cases/:id`.
 *
 * WRITES REQUIRE A HUMAN IDENTITY, reusing routes/evidenceAttestation.ts's own `humanIdentityFor`
 * exactly — same trust model as every other analyst-attested store in this codebase.
 */

const createRequestSchema = z.object({
  decision: z.string().trim().min(1).max(2000),
  audience: z.string().trim().min(1).max(500),
  deadline: z.string().trim().min(1),
  subjectScope: resolvedSubjectScopeSchema,
  expectedObservableEvidence: z.string().trim().min(1).max(2000),
  supersedesId: z.string().trim().min(1).optional(),
});

export function registerHuntRequirementRoutes(app: Express, ctx: RouteContext): void {
  const { options } = ctx;

  function configured(res: Response): boolean {
    if (!options.huntRequirementStore) {
      res.status(501).json({ error: "hunt-requirement store not configured" });
      return false;
    }
    return true;
  }

  function humanIdentity(req: Request): string | null {
    return humanIdentityFor(requestAuthentication(req), Boolean(options.teamAuth));
  }

  function aliasIndexFor(caseId: string) {
    return loadHostAliasIndex(
      {
        ...(options.assetOverridesStore ? { assetOverrides: options.assetOverridesStore } : {}),
        ...(options.velociraptorClientStore ? { fleet: options.velociraptorClientStore } : {}),
      },
      caseId,
    );
  }

  app.get("/cases/:id/hunt-requirements", async (req: Request, res: Response) => {
    if (!configured(res)) return;
    try {
      const all = await options.huntRequirementStore!.load(req.params.id);
      return res.status(200).json({ requirements: all });
    } catch (err) {
      return res.status(500).json({ error: (err as Error).message });
    }
  });

  app.post("/cases/:id/hunt-requirements", async (req: Request, res: Response) => {
    if (!configured(res)) return;
    const createdBy = humanIdentity(req);
    if (!createdBy) {
      return res.status(403).json({ error: "recording a hunt requirement requires a human analyst session" });
    }
    const parsed = createRequestSchema.safeParse(req.body);
    if (!parsed.success) {
      return res.status(400).json({ error: parsed.error.message });
    }
    try {
      const requirement = await options.huntRequirementStore!.create(req.params.id, {
        ...parsed.data,
        createdBy,
        createdAt: new Date().toISOString(),
      });
      return res.status(200).json({ requirement });
    } catch (err) {
      return res.status(500).json({ error: (err as Error).message });
    }
  });

  app.delete("/cases/:id/hunt-requirements/:reqId", async (req: Request, res: Response) => {
    if (!configured(res)) return;
    const revokedBy = humanIdentity(req);
    if (!revokedBy) {
      return res.status(403).json({ error: "revoking a hunt requirement requires a human analyst session" });
    }
    const reason = typeof req.body?.reason === "string" ? req.body.reason.trim().slice(0, 2000) : undefined;
    try {
      const requirements = await options.huntRequirementStore!.revoke(
        req.params.id,
        req.params.reqId,
        revokedBy,
        new Date().toISOString(),
        reason,
      );
      return res.status(200).json({ requirements });
    } catch (err) {
      return res.status(500).json({ error: (err as Error).message });
    }
  });

  app.get("/cases/:id/hunt-requirements/:reqId/checklist", async (req: Request, res: Response) => {
    if (!configured(res)) return;
    if (!options.stateStore || !options.hypothesisStore) {
      return res.status(501).json({ error: "state/hypothesis store not configured" });
    }
    try {
      const caseId = req.params.id;
      const all = await options.huntRequirementStore!.load(caseId);
      const requirement = all.find((r) => r.id === req.params.reqId);
      if (!requirement) return res.status(404).json({ error: "hunt requirement not found" });

      const [state, hypotheses, attested, aliasIndex] = await Promise.all([
        options.stateStore.load(caseId),
        options.hypothesisStore.load(caseId),
        options.evidenceAttestationStore
          ? options.evidenceAttestationStore.activeAttestations(caseId)
          : new Map(),
        aliasIndexFor(caseId),
      ]);

      const checklist = buildHuntChecklist({
        requirement,
        events: state.forensicTimeline,
        hypotheses,
        attested,
        aliasIndex,
        now: new Date().toISOString(),
      });
      return res.status(200).json({ requirement, checklist });
    } catch (err) {
      return res.status(500).json({ error: (err as Error).message });
    }
  });
}
