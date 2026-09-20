import type { Express, Request, Response } from "express";
import { z } from "zod";
import { requestAuthentication } from "../auth/types.js";
import { loadHostAliasIndex } from "../analysis/hostScopeLoad.js";
import { resolveHost } from "../analysis/hostAlias.js";
import {
  InvalidStaticReportAttestationError,
  type StaticReportAttestation,
} from "../analysis/staticReportAttestationStore.js";
import {
  isAnalystSideRow,
  reportEventsByFingerprint,
  staticReportEventProjection,
  staticReportMatches,
  STATIC_REPORT_ATTESTATION_CAVEAT,
  type StaticReportEventShape,
} from "../analysis/staticReportMatch.js";
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
 *
 * READS forensic ∪ super-timeline (#1389): every FLOSS row, and every olevba/capa finding row, is
 * graded Info, so the settle-time demote moves them to the super-timeline — a FLOSS report never
 * had a forensic row to carry its fingerprint, and a victim's Info file-create row is what the hash
 * join needs to see. These routes are plain analyst-facing reads with no AI in their call graph, so
 * joining both stores is the same recipe threatIntel.ts, proxyHostIdentity.ts and
 * resolverEndpointIdentity.ts (#1243) use, not the AI-boundary promotion pattern (see
 * ARCHITECTURE.md's forensic/super-timeline boundary). One difference from those readers: a row
 * promoted through /super-timeline/promote sits in BOTH stores under one id (timeline.ts), and the
 * match join emits one row per victim event, so the union is deduplicated by id, forensic row first.
 * Same full-load tradeoff as those routes — `.all(caseId)` materializes the super-timeline.
 */

const WHERE_LOOKED = "forensic timeline or super-timeline";

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

  // Forensic ∪ super-timeline, one row per id (header). No super-timeline store → forensic only.
  // Every row is the matcher's own lean projection (#1444): the super side streams through it, so
  // a capped case costs a few short fields per row, never the 900k full events at once.
  async function caseEventsFor(caseId: string): Promise<StaticReportEventShape[]> {
    const state = await options.stateStore!.load(caseId);
    const seen = new Set<string>();
    const union: StaticReportEventShape[] = [];
    for (const e of state.forensicTimeline) {
      if (seen.has(e.id)) continue;
      seen.add(e.id);
      union.push(staticReportEventProjection(e));
    }
    if (!options.superTimelineStore) return union;
    const superRows = await options.superTimelineStore.collect(caseId, (e) => {
      if (seen.has(e.id)) return undefined;
      seen.add(e.id);
      return staticReportEventProjection(e);
    });
    return union.concat(superRows);
  }

  app.get("/cases/:id/static-report-attestations", async (req: Request, res: Response) => {
    if (!configured(res)) return;
    try {
      const caseId = req.params.id;
      const [all, events, aliasIndex] = await Promise.all([
        options.staticReportAttestationStore!.load(caseId),
        caseEventsFor(caseId),
        aliasIndexFor(caseId),
      ]);
      // Victim rows only, the same read as staticReportMatches' subjectHostKnown (#1349).
      const hosts = new Set(
        events
          .filter((e) => !isAnalystSideRow(e))
          .map((e) => (e.asset ? resolveHost(aliasIndex, e.asset) : "")),
      );
      const attestations = all.map((a: StaticReportAttestation) => {
        const subjectHostCanonical = resolveHost(aliasIndex, a.subjectHost);
        return {
          ...a,
          subjectHostCanonical,
          subjectHostKnown: hosts.has(subjectHostCanonical),
          reportPresent: reportEventsByFingerprint(events, a.reportFingerprint) !== null,
        };
      });
      return res.status(200).json({ attestations, caveat: STATIC_REPORT_ATTESTATION_CAVEAT });
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
      const events = await caseEventsFor(caseId);
      const report = reportEventsByFingerprint(events, parsed.data.reportFingerprint);
      if (!report) {
        return res.status(400).json({
          error: `no event in case ${caseId} (${WHERE_LOOKED}) carries report fingerprint ${parsed.data.reportFingerprint.slice(0, 16)}… — import the report first, then attest it`,
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
      const [events, aliasIndex] = await Promise.all([caseEventsFor(caseId), aliasIndexFor(caseId)]);
      const matches = staticReportMatches({ attestation, events, aliasIndex });
      return res.status(200).json({ attestation, ...matches });
    } catch (err) {
      return res.status(500).json({ error: (err as Error).message });
    }
  });
}
