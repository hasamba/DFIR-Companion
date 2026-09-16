import type { Express, Request, Response } from "express";
import { z } from "zod";
import { requestAuthentication, type RequestAuthentication } from "../auth/types.js";
import { resolveHost } from "../analysis/hostAlias.js";
import { loadHostAliasIndex } from "../analysis/hostScopeLoad.js";
import {
  collectionDomains,
  completenessStates,
  persistenceFilters,
  generationOrderSchema,
} from "../analysis/canonicalCollectionGeneration.js";
import { comparePersistenceGenerations } from "../analysis/persistenceGenerationComparator.js";
import { humanIdentityFor } from "./evidenceAttestation.js";
import type { RouteContext } from "./context.js";

/** The human-only write actor, as {id, displayName} — Codex design-review finding M3: a display
 * name alone is not a stable identity. A standalone, pure function (mirrors humanIdentityFor's own
 * precedent) so it is unit-testable without a real Express/session harness. Reuses
 * humanIdentityFor's own authorization decision unmodified; this only adds the richer shape for
 * storage. */
export function actorFrom(
  auth: RequestAuthentication | undefined,
  teamAuthEnabled: boolean,
): { id: string; displayName: string } | null {
  if (!humanIdentityFor(auth, teamAuthEnabled)) return null;
  if (!teamAuthEnabled) return { id: "local", displayName: "local" };
  if (auth?.kind !== "session") return null; // unreachable given humanIdentityFor's own check above
  return { id: auth.identity.id, displayName: auth.identity.displayName };
}

/**
 * Durable, coverage-tracked collection-generation ledger (#1108) — an internal storage/API
 * foundation, not yet an examiner-facing feature (no dashboard authoring panel in v1; see
 * RECOMMENDATION-1108.md's own M6 finding for why that is a deliberate scoping decision, not an
 * oversight). No comparator reads this yet — 932.2's own follow-on.
 *   - GET    /cases/:id/collection-generations[?host=]  — every generation (optionally filtered
 *     by host, re-resolved against the CURRENT alias index so a later merge is honored for every
 *     stored row with no rewrite needed).
 *   - POST   /cases/:id/collection-generations          — record one new generation.
 *   - DELETE /cases/:id/collection-generations/:generationId — revoke one generation.
 *
 * `:id` needs no isValidCaseId check: createApp mounts createCaseIdGate() on `/cases/:id`.
 *
 * WRITES REQUIRE A HUMAN IDENTITY, reusing routes/evidenceAttestation.ts's own `humanIdentityFor`
 * exactly (never re-implemented) — the same trust model: an automated credential recording what a
 * collection covered would let something other than a person vouch for it.
 */

const compareQuerySchema = z.object({
  host: z.string().trim().min(1).optional(),
  domain: z.enum(collectionDomains).optional(),
});

const recordRequestSchema = z.object({
  rawHost: z.string().trim().min(1).max(200),
  domain: z.enum(collectionDomains),
  order: generationOrderSchema,
  importSeq: z.number().int().positive(),
  completenessState: z.enum(completenessStates),
  filtersApplied: z.array(z.enum(persistenceFilters)).optional(),
  checked: z.string().trim().max(2000).optional(),
  gaps: z.string().trim().max(2000).optional(),
});

export function registerCollectionGenerationRoutes(app: Express, ctx: RouteContext): void {
  const { options } = ctx;

  function configured(res: Response): boolean {
    if (!options.collectionGenerationStore) {
      res.status(501).json({ error: "collection-generation store not configured" });
      return false;
    }
    return true;
  }

  function actorFor(req: Request): { id: string; displayName: string } | null {
    return actorFrom(requestAuthentication(req), Boolean(options.teamAuth));
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

  app.get("/cases/:id/collection-generations", async (req: Request, res: Response) => {
    if (!configured(res)) return;
    try {
      const all = await options.collectionGenerationStore!.all(req.params.id);
      const hostFilter = typeof req.query.host === "string" ? req.query.host : undefined;
      if (!hostFilter) return res.status(200).json({ generations: all });
      const index = await aliasIndexFor(req.params.id);
      const target = resolveHost(index, hostFilter);
      const filtered = all.filter((g) => resolveHost(index, g.rawHost) === target);
      return res.status(200).json({ generations: filtered });
    } catch (err) {
      return res.status(500).json({ error: (err as Error).message });
    }
  });

  // #1128: read-only over already-stored data — no auth beyond the existing case-scoped access,
  // since this derives a view rather than writing (Codex design-review finding L1: `humanIdentityFor`
  // would wrongly exclude a legitimate case-scoped service-token reader).
  app.get("/cases/:id/collection-generations/compare", async (req: Request, res: Response) => {
    if (!configured(res)) return;
    const parsed = compareQuerySchema.safeParse(req.query);
    if (!parsed.success) {
      return res.status(400).json({ error: parsed.error.message });
    }
    try {
      const active = await options.collectionGenerationStore!.active(req.params.id);
      const index = await aliasIndexFor(req.params.id);
      const { cohorts: all, truncatedCohorts } = comparePersistenceGenerations(active, index);
      let cohorts = all;
      if (parsed.data.host) {
        const target = resolveHost(index, parsed.data.host);
        cohorts = cohorts.filter((c) => c.resolvedHost === target);
      }
      return res.status(200).json({ cohorts, truncatedCohorts });
    } catch (err) {
      return res.status(500).json({ error: (err as Error).message });
    }
  });

  app.get("/cases/:id/collection-generations/:generationId/verify", async (req: Request, res: Response) => {
    if (!configured(res)) return;
    try {
      const result = await options.collectionGenerationStore!.verifyArtifact(
        req.params.id,
        req.params.generationId,
      );
      return res.status(200).json(result);
    } catch (err) {
      return res.status(500).json({ error: (err as Error).message });
    }
  });

  app.post("/cases/:id/collection-generations", async (req: Request, res: Response) => {
    if (!configured(res)) return;
    const actor = actorFor(req);
    if (!actor) {
      return res
        .status(403)
        .json({ error: "recording a collection generation requires a human analyst session" });
    }
    const parsed = recordRequestSchema.safeParse(req.body);
    if (!parsed.success) {
      return res.status(400).json({ error: parsed.error.message });
    }
    try {
      const aliasIndex = await aliasIndexFor(req.params.id);
      const generation = await options.collectionGenerationStore!.record(req.params.id, {
        ...parsed.data,
        recordedBy: actor,
        aliasIndex,
      });
      return res.status(201).json({ generation });
    } catch (err) {
      return res.status(400).json({ error: (err as Error).message });
    }
  });

  app.delete("/cases/:id/collection-generations/:generationId", async (req: Request, res: Response) => {
    if (!configured(res)) return;
    const actor = actorFor(req);
    if (!actor) {
      return res
        .status(403)
        .json({ error: "revoking a collection generation requires a human analyst session" });
    }
    try {
      const generations = await options.collectionGenerationStore!.revoke(
        req.params.id,
        req.params.generationId,
        actor,
        new Date().toISOString(),
      );
      return res.status(200).json({ generations });
    } catch (err) {
      return res.status(500).json({ error: (err as Error).message });
    }
  });
}
