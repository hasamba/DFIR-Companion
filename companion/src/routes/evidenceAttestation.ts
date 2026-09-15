import type { Express, Request, Response } from "express";
import { requestAuthentication } from "../auth/types.js";
import { EVIDENCE_CLASSES, type EvidenceClass } from "../analysis/refutationGate.js";
import type { EvidenceAttestation } from "../analysis/evidenceAttestationStore.js";
import type { RouteContext } from "./context.js";

/**
 * Analyst-attested evidence-class coverage (#1111).
 *   - GET    /cases/:id/evidence-attestations           — every attestation (audit trail).
 *   - POST   /cases/:id/evidence-attestations/:class     — attest one class (requires a reason).
 *   - DELETE /cases/:id/evidence-attestations/:class     — revoke the current attestation for one class.
 *
 * `:id` needs no isValidCaseId check: createApp mounts createCaseIdGate() on `/cases/:id`.
 */
export function registerEvidenceAttestationRoutes(app: Express, ctx: RouteContext): void {
  const { options } = ctx;

  function configured(res: Response): boolean {
    if (!options.evidenceAttestationStore) {
      res.status(501).json({ error: "evidence-attestation store not configured" });
      return false;
    }
    return true;
  }

  function parseClass(res: Response, raw: string): EvidenceClass | undefined {
    if ((EVIDENCE_CLASSES as readonly string[]).includes(raw)) return raw as EvidenceClass;
    res.status(400).json({ error: `class must be one of ${EVIDENCE_CLASSES.join(", ")}` });
    return undefined;
  }

  app.get("/cases/:id/evidence-attestations", async (req: Request, res: Response) => {
    if (!configured(res)) return;
    try {
      const all = await options.evidenceAttestationStore!.load(req.params.id);
      return res.status(200).json({ attestations: all });
    } catch (err) {
      return res.status(500).json({ error: (err as Error).message });
    }
  });

  app.post("/cases/:id/evidence-attestations/:class", async (req: Request, res: Response) => {
    if (!configured(res)) return;
    const evidenceClass = parseClass(res, req.params.class);
    if (!evidenceClass) return;
    const reason = typeof req.body?.reason === "string" ? req.body.reason.trim().slice(0, 2000) : "";
    if (!reason) {
      return res.status(400).json({ error: "a reason is required to attest evidence-class coverage" });
    }
    try {
      const attestations = await options.evidenceAttestationStore!.attest(req.params.id, {
        evidenceClass,
        confirmedBy: requestAuthentication(req)?.identity.displayName ?? "local",
        confirmedAt: new Date().toISOString(),
        reason,
      });
      return res.status(200).json({ attestations });
    } catch (err) {
      return res.status(500).json({ error: (err as Error).message });
    }
  });

  app.delete("/cases/:id/evidence-attestations/:class", async (req: Request, res: Response) => {
    if (!configured(res)) return;
    const evidenceClass = parseClass(res, req.params.class);
    if (!evidenceClass) return;
    try {
      const attestations: EvidenceAttestation[] = await options.evidenceAttestationStore!.revoke(
        req.params.id,
        evidenceClass,
        requestAuthentication(req)?.identity.displayName ?? "local",
        new Date().toISOString(),
      );
      return res.status(200).json({ attestations });
    } catch (err) {
      return res.status(500).json({ error: (err as Error).message });
    }
  });
}
