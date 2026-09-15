import type { Express, Request, Response } from "express";
import { requestAuthentication, type RequestAuthentication } from "../auth/types.js";
import { EVIDENCE_CLASSES, type EvidenceClass } from "../analysis/refutationGate.js";
import type { EvidenceAttestation } from "../analysis/evidenceAttestationStore.js";
import type { RouteContext } from "./context.js";

// The analyst's own display name — "local" only when team-auth is off entirely (solo mode, the
// same convention routes/hostScope.ts already uses). Returns null when team-auth IS on but the
// caller is not a live human session, so the route can refuse the write outright. A standalone
// function (not a request-scoped closure) so it is unit-testable without a real Express/auth
// harness — the whole point is a pure decision from an auth result plus a boolean.
export function humanIdentityFor(
  auth: RequestAuthentication | undefined,
  teamAuthEnabled: boolean,
): string | null {
  if (!teamAuthEnabled) return "local";
  if (auth?.kind !== "session" || auth.identity.kind === "service") return null;
  return auth.identity.displayName;
}

/**
 * Analyst-attested evidence-class coverage (#1111).
 *   - GET    /cases/:id/evidence-attestations           — every attestation (audit trail).
 *   - POST   /cases/:id/evidence-attestations/:class     — attest one class (requires a reason).
 *   - DELETE /cases/:id/evidence-attestations/:class     — revoke the current attestation for one class.
 *
 * `:id` needs no isValidCaseId check: createApp mounts createCaseIdGate() on `/cases/:id`.
 *
 * WRITES REQUIRE A HUMAN IDENTITY (mirrors routes/reportVersions.ts's own `requestActor`). This
 * store's whole trust model rests on "an IDENTIFIED ANALYST confirms" — a service token (an
 * automation credential, or a compromised integration) creating an attestation would let something
 * other than a person keep a refutation standing, which is exactly the boundary this feature exists
 * to enforce. Team-auth OFF (single-user local mode) has no service-token concept at all, so it is
 * always allowed, same as every other write route in that mode.
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

  function humanIdentity(req: Request): string | null {
    return humanIdentityFor(requestAuthentication(req), Boolean(options.teamAuth));
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
    const confirmedBy = humanIdentity(req);
    if (!confirmedBy) {
      return res.status(403).json({ error: "evidence attestation requires a human analyst session" });
    }
    const reason = typeof req.body?.reason === "string" ? req.body.reason.trim().slice(0, 2000) : "";
    if (!reason) {
      return res.status(400).json({ error: "a reason is required to attest evidence-class coverage" });
    }
    try {
      const attestations = await options.evidenceAttestationStore!.attest(req.params.id, {
        evidenceClass,
        confirmedBy,
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
    const revokedBy = humanIdentity(req);
    if (!revokedBy) {
      return res.status(403).json({ error: "revoking an attestation requires a human analyst session" });
    }
    try {
      const attestations: EvidenceAttestation[] = await options.evidenceAttestationStore!.revoke(
        req.params.id,
        evidenceClass,
        revokedBy,
        new Date().toISOString(),
      );
      return res.status(200).json({ attestations });
    } catch (err) {
      return res.status(500).json({ error: (err as Error).message });
    }
  });
}
