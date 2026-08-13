import type { Express, Request, Response } from "express";
import { requestAuthentication } from "../auth/types.js";
import { canonicalHostName } from "../analysis/hostAlias.js";
import { emptyHostFingerprint, type HostScopeLedger } from "../analysis/hostScope.js";
import { loadHostScopeLedger, caseTacticsOf } from "../analysis/hostScopeLoad.js";
import type { HostScopeStatus } from "../analysis/hostScopeStore.js";
import { ScopeStore } from "../analysis/scope.js";
import type { IrisTactic } from "../analysis/mitreTactics.js";
import type { RouteContext } from "./context.js";

/**
 * Host scope & clearance ledger.
 *   - GET  /cases/:id/host-scope        — the derived ledger (never persisted).
 *   - POST /cases/:id/host-scope/:host  — record an analyst decision (append-only).
 *
 * `:id` needs no isValidCaseId check: createApp mounts createCaseIdGate() on `/cases/:id`.
 */
const DECIDABLE: readonly HostScopeStatus[] = [
  "unknown",
  "suspected",
  "confirmed",
  "cleared",
  "out-of-scope",
];
const NEEDS_REASON: readonly HostScopeStatus[] = ["cleared", "out-of-scope"];

export function registerHostScopeRoutes(app: Express, ctx: RouteContext): void {
  const { options } = ctx;
  // ScopeStore is not an AppOptions field — ReportWriterImpl constructs its own the same way.
  const scopeStore = new ScopeStore(ctx.store);

  async function context(caseId: string): Promise<{
    window: { start: string | null; end: string | null };
    tactics: IrisTactic[];
  }> {
    const state = await options.stateStore!.load(caseId);
    return { window: await scopeStore.load(caseId), tactics: caseTacticsOf(state) };
  }

  async function ledger(caseId: string): Promise<HostScopeLedger> {
    return loadHostScopeLedger(
      {
        state: options.stateStore!,
        superTimeline: options.superTimelineStore!,
        decisions: options.hostScopeStore!,
        scope: scopeStore,
        ...(options.assetOverridesStore ? { assetOverrides: options.assetOverridesStore } : {}),
        ...(options.velociraptorClientStore ? { fleet: options.velociraptorClientStore } : {}),
      },
      caseId,
    );
  }

  function configured(res: Response): boolean {
    if (!options.hostScopeStore || !options.stateStore || !options.superTimelineStore) {
      res.status(501).json({ error: "host-scope store not configured" });
      return false;
    }
    return true;
  }

  app.get("/cases/:id/host-scope", async (req: Request, res: Response) => {
    if (!configured(res)) return;
    try {
      return res.status(200).json(await ledger(req.params.id));
    } catch (err) {
      return res.status(500).json({ error: (err as Error).message });
    }
  });

  app.post("/cases/:id/host-scope/:host", async (req: Request, res: Response) => {
    if (!configured(res)) return;
    const caseId = req.params.id;
    const host = canonicalHostName(req.params.host);
    const to = req.body?.to as HostScopeStatus;
    const reason = typeof req.body?.reason === "string" ? req.body.reason.trim().slice(0, 500) : "";

    if (!host) return res.status(400).json({ error: "host is required" });
    if (!DECIDABLE.includes(to)) {
      return res.status(400).json({ error: `to must be one of ${DECIDABLE.join(", ")}` });
    }
    if (NEEDS_REASON.includes(to) && !reason) {
      return res.status(400).json({ error: `a reason is required to record "${to}"` });
    }

    try {
      // Read the ledger first so the decision records the CURRENT evidence as its basis — otherwise
      // every decision would be flagged stale the moment it is written. A host the case holds no
      // evidence for still gets the deterministic empty-evidence fingerprint, so a legitimate
      // "decommissioned before the incident" call is not born needing review.
      const before = await ledger(caseId);
      const row = before.hosts.find((h) => h.name === host);
      const { window, tactics } = await context(caseId);

      await options.hostScopeStore!.append(caseId, {
        host,
        from: row?.effectiveStatus ?? "unknown",
        to,
        reason,
        analyst: requestAuthentication(req)?.identity.displayName ?? "local",
        at: new Date().toISOString(),
        basis: {
          sources: row?.sources ?? [],
          windowCovered: row?.eligibility.criteria.find((c) => c.id === "window-coverage")?.met ?? false,
          tacticsCovered: row?.eligibility.criteria.find((c) => c.id === "technique-coverage")?.met
            ? tactics
            : [],
          evidenceFingerprint: row?.fingerprint ?? emptyHostFingerprint(window, tactics),
        },
      });
      return res.status(200).json(await ledger(caseId));
    } catch (err) {
      return res.status(500).json({ error: (err as Error).message });
    }
  });
}
