import type { Express, Request, Response } from "express";
import { isValidCaseId } from "../storage/caseStore.js";
import { seedDemoCase } from "../analysis/seedDemoCase.js";
import { isTerminal } from "../analysis/jobRegistry.js";
import type { RouteContext } from "./context.js";

/**
 * Seed the built-in demo case ("GlobalTech Industries — BEC & Ransomware Precursor").
 *   - POST /cases/seed-demo — optional { caseId?: string, force?: boolean }; 201 on success,
 *     409 when the case already exists and force is not set.
 *
 * Available in both the dev server and the portable EXE so users don't need tsx/Node installed.
 *
 * Split out of routes/caseLifecycle.ts when the body-caseId validation below was added (#427):
 * that file is at its size-ledger cap, and this route is the one case-creation path the global
 * gate does not cover, which is worth being able to see whole.
 *
 * Unlike every other case route, `isValidCaseId` here is NOT redundant with createApp's
 * `app.use('/cases/:id', createCaseIdGate())`. That gate reads `req.params.id`, which for this
 * path is the literal segment `seed-demo` — itself a valid id — so the BODY caseId is never
 * inspected by it. Unvalidated, that id flows into seedDemoCase's `join(casesRoot, caseId)`: a
 * `..` id aims the mkdir/writeFile scaffold, and force's `rm -rf`, outside the cases root, and
 * `store.getCaseMeta` below reads a case.json from there. Demo mode's gate in server.ts
 * allow-lists this one mutating route, so on a public deployment it is reachable unauthenticated.
 */
export function registerSeedDemoRoutes(app: Express, ctx: RouteContext): void {
  const { store, options } = ctx;

  app.post("/cases/seed-demo", async (req: Request, res: Response) => {
    try {
      const rawCaseId = req.body?.caseId ?? undefined;
      if (rawCaseId !== undefined && (typeof rawCaseId !== "string" || !isValidCaseId(rawCaseId))) {
        return res.status(400).json({
          error:
            "caseId must use only letters, numbers, dots, dashes, or underscores, and may not contain path traversal",
        });
      }
      const caseId = typeof rawCaseId === "string" ? rawCaseId : undefined;
      const force = req.body?.force === true;
      // Guard against clobbering an in-progress case. force previously overwrote case.json +
      // investigation state for an OPEN case with a running synthesis/import job, destroying the
      // analyst's findings/timeline mid-flight and leaving orphan files (the demo only writes its
      // own captures/imports, so extra screenshots/imports survived as orphans). Refuse when the
      // case exists and is open, or has a non-terminal job — mirroring /restore-backup's check.
      if (force) {
        const existing = caseId && (await store.getCaseMeta(caseId).catch(() => null));
        if (existing) {
          const status = existing.status ?? "open"; // absent means open
          if (status === "open") {
            return res.status(409).json({
              error: `case "${caseId}" is open — close it before force-seeding the demo over it (or delete it)`,
            });
          }
          const busy = options.jobManager?.list(caseId).find((j) => !isTerminal(j.status));
          if (busy) {
            return res.status(409).json({
              error: `a ${busy.kind}${busy.label ? ` (${busy.label})` : ""} job is in progress for this case — cancel it or wait, then seed`,
              jobId: busy.id,
              kind: busy.kind,
            });
          }
        }
      }
      const result = await seedDemoCase(store.casesRoot, { caseId, force });
      options.teamAuth?.grantCreator(req, result.caseId);
      return res.status(201).json(result);
    } catch (err) {
      const e = err as NodeJS.ErrnoException;
      if (e.code === "EEXIST") return res.status(409).json({ error: e.message });
      // seedDemoCase re-validates the id itself (the CLI shares it). If its check fires when the
      // one above did not, that is a caller bug, not a server fault — 400, not 500.
      if (e.code === "EINVAL") return res.status(400).json({ error: e.message });
      return res.status(500).json({ error: (err as Error).message });
    }
  });
}
