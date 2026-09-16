import type { Express, Request, Response } from "express";
import { readFile, stat } from "node:fs/promises";
import { join } from "node:path";
import { z } from "zod";
import { requestAuthentication } from "../auth/types.js";
import { mobileBackupDomains, completenessStates } from "../analysis/canonicalMobileBackupGeneration.js";
import { compareMobileGenerations } from "../analysis/mobileAppPresenceComparator.js";
import { parseBackupInfo, parseInstalledApps } from "../analysis/mobileBackupGenerationStore.js";
import { actorFrom } from "./collectionGenerations.js";
import type { RouteContext } from "./context.js";

/**
 * Examiner-attested mobile-backup-pairing ledger (#1132) — see RECOMMENDATION-1132.md for the
 * full design rationale, including the 6 High findings a Codex adversarial design review round
 * found in the first draft.
 *   - GET    /cases/:id/mobile-backup-generations/candidate-imports — recent imports classified
 *     as backup-info/installed-apps/neither, with a read-only preview, so the recording UI can
 *     work without a general "list imports" feature existing anywhere else in the app.
 *   - GET    /cases/:id/mobile-backup-generations[?device=]  — every generation.
 *   - POST   /cases/:id/mobile-backup-generations            — record one attested pairing.
 *   - DELETE /cases/:id/mobile-backup-generations/:generationId — revoke one generation.
 *   - GET    /cases/:id/mobile-backup-generations/:generationId/verify — both-artifact verification.
 *   - GET    /cases/:id/mobile-backup-generations/compare[?device=] — read-only comparison.
 *
 * `:id` needs no isValidCaseId check: createApp mounts createCaseIdGate() on `/cases/:id`.
 *
 * WRITES REQUIRE A HUMAN IDENTITY (reuses collectionGenerations.ts's own `actorFrom`/
 * `humanIdentityFor` exactly) — an attestation that two uploads are the same physical backup is
 * exactly the kind of claim an automated credential must never vouch for (Codex finding H1).
 */

const MAX_CANDIDATE_IMPORTS = 200;
// Both real artifact types are small metadata exports (a device's own Info.plist properties, or
// one row per installed app) — well under a megabyte even for a large app inventory. A file past
// this size is classified `looksLike: null` WITHOUT being read at all (Codex code-review finding:
// this endpoint could otherwise be pointed at an unrelated multi-hundred-MB import and made to
// fully read+parse it on every request, exhausting memory / blocking the event loop).
const MAX_CANDIDATE_FILE_BYTES = 5 * 1024 * 1024;

const compareQuerySchema = z.object({
  device: z.string().trim().min(1).optional(),
});

const deviceListQuerySchema = z.object({
  device: z.string().trim().min(1).optional(),
});

const recordRequestSchema = z
  .object({
    backupInfoImportSeq: z.number().int().positive(),
    installedAppsImportSeq: z.number().int().positive(),
    domain: z.enum(mobileBackupDomains),
    completenessState: z.enum(completenessStates),
    filtersApplied: z.array(z.string()).optional(),
    declaredSequence: z.number().int().positive().optional(),
    dateUnavailableReason: z.string().trim().min(1).max(2000).optional(),
    attestedSameBackup: z.literal(true),
    checked: z.string().trim().max(2000).optional(),
    gaps: z.string().trim().max(2000).optional(),
  })
  .strict();

type CandidateKind = "backup-info" | "installed-apps" | null;

interface CandidateImport {
  importSeq: number;
  originalName: string;
  importedAt: string;
  looksLike: CandidateKind;
  preview:
    | { kind: "backup-info"; deviceIdentity: { kind: string; value: string }; capturedAt: string }
    | { kind: "installed-apps"; appCount: number }
    | null;
}

export function registerMobileBackupGenerationRoutes(app: Express, ctx: RouteContext): void {
  const { options, store } = ctx;

  function configured(res: Response): boolean {
    if (!options.mobileBackupGenerationStore) {
      res.status(501).json({ error: "mobile-backup-generation store not configured" });
      return false;
    }
    return true;
  }

  function actorFor(req: Request): { id: string; displayName: string } | null {
    return actorFrom(requestAuthentication(req), Boolean(options.teamAuth));
  }

  app.get("/cases/:id/mobile-backup-generations/candidate-imports", async (req: Request, res: Response) => {
    if (!configured(res)) return;
    try {
      let log: string;
      try {
        log = await readFile(store.importsLogPath(req.params.id), "utf8");
      } catch (err) {
        if ((err as NodeJS.ErrnoException).code === "ENOENT") return res.status(200).json({ candidates: [] });
        throw err;
      }
      const rows: { sequenceNumber: number; filename: string; originalName: string; importedAt: string }[] =
        [];
      for (const line of log.split("\n")) {
        if (!line.trim()) continue;
        try {
          rows.push(JSON.parse(line));
        } catch {
          /* skip a malformed audit line */
        }
      }
      const recent = rows.slice(-MAX_CANDIDATE_IMPORTS).reverse();
      const candidates: CandidateImport[] = [];
      for (const row of recent) {
        const path = join(store.importsDir(req.params.id), row.filename);
        const skip = {
          importSeq: row.sequenceNumber,
          originalName: row.originalName,
          importedAt: row.importedAt,
          looksLike: null,
          preview: null,
        } as const;
        let size: number;
        try {
          size = (await stat(path)).size;
        } catch {
          candidates.push(skip);
          continue;
        }
        if (size > MAX_CANDIDATE_FILE_BYTES) {
          candidates.push(skip);
          continue;
        }
        let text: string;
        try {
          text = await readFile(path, "utf8");
        } catch {
          candidates.push(skip);
          continue;
        }
        try {
          const info = parseBackupInfo(text);
          candidates.push({
            importSeq: row.sequenceNumber,
            originalName: row.originalName,
            importedAt: row.importedAt,
            looksLike: "backup-info",
            preview: {
              kind: "backup-info",
              deviceIdentity: info.deviceIdentity,
              capturedAt: info.capturedAt,
            },
          });
          continue;
        } catch {
          /* not a backup-info export */
        }
        try {
          const apps = parseInstalledApps(text);
          candidates.push({
            importSeq: row.sequenceNumber,
            originalName: row.originalName,
            importedAt: row.importedAt,
            looksLike: "installed-apps",
            preview: { kind: "installed-apps", appCount: apps.facts.length },
          });
          continue;
        } catch {
          /* not an installed-apps export either */
        }
        candidates.push(skip);
      }
      return res.status(200).json({ candidates });
    } catch (err) {
      return res.status(500).json({ error: (err as Error).message });
    }
  });

  app.get("/cases/:id/mobile-backup-generations", async (req: Request, res: Response) => {
    if (!configured(res)) return;
    const parsed = deviceListQuerySchema.safeParse(req.query);
    if (!parsed.success) return res.status(400).json({ error: parsed.error.message });
    try {
      const all = await options.mobileBackupGenerationStore!.all(req.params.id);
      if (!parsed.data.device) return res.status(200).json({ generations: all });
      const target = parsed.data.device.toLowerCase();
      const filtered = all.filter((g) => g.deviceIdentity.value.toLowerCase() === target);
      return res.status(200).json({ generations: filtered });
    } catch (err) {
      return res.status(500).json({ error: (err as Error).message });
    }
  });

  // Read-only over already-stored data — no auth beyond the existing case-scoped access, matching
  // collectionGenerations.ts's own compare route (Codex design-review finding L1, reused).
  app.get("/cases/:id/mobile-backup-generations/compare", async (req: Request, res: Response) => {
    if (!configured(res)) return;
    const parsed = compareQuerySchema.safeParse(req.query);
    if (!parsed.success) return res.status(400).json({ error: parsed.error.message });
    try {
      const active = await options.mobileBackupGenerationStore!.active(req.params.id);
      // Filter the INPUT by device before the comparator's own MAX_COHORTS cap runs, never its
      // output after (the #1138 fix, applied here from the start).
      const scoped = parsed.data.device
        ? active.filter((g) => g.deviceIdentity.value.toLowerCase() === parsed.data.device!.toLowerCase())
        : active;
      const { cohorts, truncatedCohorts } = compareMobileGenerations(scoped);
      return res.status(200).json({ cohorts, truncatedCohorts });
    } catch (err) {
      return res.status(500).json({ error: (err as Error).message });
    }
  });

  app.get(
    "/cases/:id/mobile-backup-generations/:generationId/verify",
    async (req: Request, res: Response) => {
      if (!configured(res)) return;
      try {
        const result = await options.mobileBackupGenerationStore!.verifyArtifacts(
          req.params.id,
          req.params.generationId,
        );
        return res.status(200).json(result);
      } catch (err) {
        return res.status(500).json({ error: (err as Error).message });
      }
    },
  );

  app.post("/cases/:id/mobile-backup-generations", async (req: Request, res: Response) => {
    if (!configured(res)) return;
    const actor = actorFor(req);
    if (!actor) {
      return res
        .status(403)
        .json({ error: "recording a mobile-backup-generation requires a human analyst session" });
    }
    const parsed = recordRequestSchema.safeParse(req.body);
    if (!parsed.success) {
      return res.status(400).json({ error: parsed.error.message });
    }
    try {
      const generation = await options.mobileBackupGenerationStore!.record(req.params.id, {
        ...parsed.data,
        recordedBy: actor,
      });
      return res.status(201).json({ generation });
    } catch (err) {
      return res.status(400).json({ error: (err as Error).message });
    }
  });

  app.delete("/cases/:id/mobile-backup-generations/:generationId", async (req: Request, res: Response) => {
    if (!configured(res)) return;
    const actor = actorFor(req);
    if (!actor) {
      return res
        .status(403)
        .json({ error: "revoking a mobile-backup-generation requires a human analyst session" });
    }
    try {
      const generations = await options.mobileBackupGenerationStore!.revoke(
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
