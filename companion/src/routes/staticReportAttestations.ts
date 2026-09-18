import type { Express, Request, Response } from "express";
import { z } from "zod";
import { requestAuthentication } from "../auth/types.js";
import { loadHostAliasIndex } from "../analysis/hostScopeLoad.js";
import { resolveHost } from "../analysis/hostAlias.js";
import {
  InvalidStaticReportAttestationError,
  type StaticReportAttestation,
} from "../analysis/staticReportAttestationStore.js";
import { reportEventsByFingerprint, staticReportMatches } from "../analysis/staticReportMatch.js";
import { humanIdentityFor } from "./evidenceAttestation.js";
import type { RouteContext } from "./context.js";

/**
 * Analyst-attested binding of a static-analysis report (olevba, capa, FLOSS) to a subject host
 * and evidence volume (#1316) — route-only, same scoping as collectionGenerationStore (#1108) and
 * huntRequirements (933.17). An attestation is a claim the analyst signs, never a verification.
 *   - GET    /cases/:id/static-report-attestations               — audit trail, read-time annotated.
 *   - POST   /cases/:id/static-report-attestations               — record one attestation.
 *   - DELETE /cases/:id/static-report-attestations/:attId        — revoke one (404 unknown).
 *   - GET    /cases/:id/static-report-attestations/:attId/matches — the read-time join, never persisted.
 *
 * `:id` needs no isValidCaseId check: createApp mounts createCaseIdGate() on `/cases/:id`.
 * WRITES REQUIRE A HUMAN IDENTITY via routes/evidenceAttestation.ts's own `humanIdentityFor`.
 */

const SHA256 = /^[0-9a-fA-F]{64}$/;
const MD5 = /^[0-9a-fA-F]{32}$/;

const createRequestSchema = z.object({
  reportFingerprint: z.string().trim().regex(SHA256),
  subjectHost: z.string().trim().min(1).max(120),
  evidenceVolume: z
    .object({
      mountPoint: z.string().trim().min(1).max(64),
      originalVolume: z.string().trim().min(1).max(64).optional(),
    })
    .optional(),
  documentSha256: z.string().trim().regex(SHA256).optional(),
  documentMd5: z.string().trim().regex(MD5).optional(),
  supersedesId: z.string().trim().min(1).max(200).optional(),
});

export function registerStaticReportAttestationRoutes(app: Express, ctx: RouteContext): void {
  const { options } = ctx;

  function configured(res: Response): boolean {
    if (!options.staticReportAttestationStore) {
      res.status(501).json({ error: "static-report attestation store not configured" });
      return false;
    }
    if (!options.stateStore) {
      res.status(501).json({ error: "state store not configured" });
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

  app.get("/cases/:id/static-report-attestations", async (req: Request, res: Response) => {
    if (!configured(res)) return;
    try {
      const caseId = req.params.id;
      const [all, state, aliasIndex] = await Promise.all([
        options.staticReportAttestationStore!.load(caseId),
        options.stateStore!.load(caseId),
        aliasIndexFor(caseId),
      ]);
      const events = state.forensicTimeline;
      const hosts = new Set(events.map((e) => (e.asset ? resolveHost(aliasIndex, e.asset) : "")));
      const attestations = all.map((a: StaticReportAttestation) => {
        const subjectHostCanonical = resolveHost(aliasIndex, a.subjectHost);
        return {
          ...a,
          subjectHostCanonical,
          subjectHostKnown: hosts.has(subjectHostCanonical),
          reportPresent: reportEventsByFingerprint(events, a.reportFingerprint) !== null,
        };
      });
      return res.status(200).json({ attestations });
    } catch (err) {
      return res.status(500).json({ error: (err as Error).message });
    }
  });

  app.post("/cases/:id/static-report-attestations", async (req: Request, res: Response) => {
    if (!configured(res)) return;
    const attestedBy = humanIdentity(req);
    if (!attestedBy) {
      return res
        .status(403)
        .json({ error: "attesting a static-analysis report requires a human analyst session" });
    }
    const parsed = createRequestSchema.safeParse(req.body);
    if (!parsed.success) {
      return res.status(400).json({ error: parsed.error.message });
    }
    try {
      const caseId = req.params.id;
      const state = await options.stateStore!.load(caseId);
      const report = reportEventsByFingerprint(state.forensicTimeline, parsed.data.reportFingerprint);
      if (!report) {
        return res.status(400).json({
          error: `no event in case ${caseId} carries report fingerprint ${parsed.data.reportFingerprint.slice(0, 16)}… — import the report first, then attest it`,
        });
      }
      const attestation = await options.staticReportAttestationStore!.create(caseId, {
        ...parsed.data,
        tool: report.tool,
        ...(report.toolReportedSha256 ? { toolReportedSha256: report.toolReportedSha256 } : {}),
        ...(report.toolReportedMd5 ? { toolReportedMd5: report.toolReportedMd5 } : {}),
        attestedBy,
        attestedAt: new Date().toISOString(),
      });
      return res.status(200).json({ attestation });
    } catch (err) {
      if (err instanceof InvalidStaticReportAttestationError || err instanceof z.ZodError) {
        return res.status(400).json({ error: err.message });
      }
      return res.status(500).json({ error: (err as Error).message });
    }
  });

  app.delete("/cases/:id/static-report-attestations/:attId", async (req: Request, res: Response) => {
    if (!configured(res)) return;
    const revokedBy = humanIdentity(req);
    if (!revokedBy) {
      return res
        .status(403)
        .json({ error: "revoking a static-report attestation requires a human analyst session" });
    }
    const reason = typeof req.body?.reason === "string" ? req.body.reason.trim().slice(0, 2000) : undefined;
    try {
      const attestations = await options.staticReportAttestationStore!.revoke(
        req.params.id,
        req.params.attId,
        revokedBy,
        new Date().toISOString(),
        reason,
      );
      return res.status(200).json({ attestations });
    } catch (err) {
      if (err instanceof InvalidStaticReportAttestationError) {
        return res.status(404).json({ error: err.message });
      }
      return res.status(500).json({ error: (err as Error).message });
    }
  });

  app.get("/cases/:id/static-report-attestations/:attId/matches", async (req: Request, res: Response) => {
    if (!configured(res)) return;
    try {
      const caseId = req.params.id;
      const all = await options.staticReportAttestationStore!.load(caseId);
      const attestation = all.find((a) => a.id === req.params.attId);
      if (!attestation) return res.status(404).json({ error: "static-report attestation not found" });
      const [state, aliasIndex] = await Promise.all([
        options.stateStore!.load(caseId),
        aliasIndexFor(caseId),
      ]);
      const matches = staticReportMatches({ attestation, events: state.forensicTimeline, aliasIndex });
      return res.status(200).json({ attestation, ...matches });
    } catch (err) {
      return res.status(500).json({ error: (err as Error).message });
    }
  });
}
