import type { Express, Request, Response } from "express";
import { logActivity } from "../analysis/activityLog.js";
import { deriveSemanticKey } from "../analysis/semanticKey.js";
import { reconcileSimulationVerdict } from "../analysis/simulationVerdict.js";
import { loadHostAliasIndex } from "../analysis/hostScopeLoad.js";
import { applySeverityRestores, severityCapOf } from "../analysis/findingSeverityRestore.js";
import type { Finding } from "../analysis/stateTypes.js";
import type { RouteContext } from "./context.js";

// Analyst severity restore (#1973): "Restore High" on a finding a grading gate capped. POST stores
// the restore and DELETE removes it. Both apply STRAIGHT to the stored findings, like the
// simulation override: no synthesis starts and nothing is marked out of date, because the step is
// deterministic. The simulation step runs again after the restore, so its case-wide cap still holds.
// Its own module because routes/findings.ts sits at its size ledger.
export function registerFindingSeverityRestoreRoutes(app: Express, ctx: RouteContext): void {
  const path = "/cases/:id/findings/:findingId/severity-restore";
  app.post(path, (req, res) => handle(ctx, req, res, true));
  app.delete(path, (req, res) => handle(ctx, req, res, false));
}

async function handle(ctx: RouteContext, req: Request, res: Response, restore: boolean) {
  const { options } = ctx;
  const stateStore = options.stateStore;
  const store = options.findingSeverityRestoreStore;
  if (!stateStore || !store) return res.status(501).json({ error: "severity restore not configured" });
  const caseId = req.params.id;
  const findingId = String(req.params.findingId ?? "").trim();
  if (!findingId) return res.status(400).json({ error: "findingId is required" });
  const by = typeof req.body?.updatedBy === "string" ? req.body.updatedBy.slice(0, 200) : "";
  let finding: Finding | undefined;
  try {
    finding = (await stateStore.load(caseId)).findings.find((f) => f.id === findingId);
  } catch (err) {
    return res.status(500).json({ error: `could not read case state: ${(err as Error).message}` });
  }
  if (!finding) return res.status(404).json({ error: `finding ${findingId} is not in case ${caseId}` });
  const cap = severityCapOf(finding);
  if (restore && !cap)
    return res.status(409).json({ error: `finding ${findingId} has no severity cap to restore` });
  try {
    // Record first, then the findings, both before answering: a synthesis persisting in between
    // reads the new record, and this write re-applies it over that result.
    if (restore)
      await store.restore(caseId, findingId, {
        semanticKey: finding.semanticKey || deriveSemanticKey(finding),
        by,
      });
    else await store.clear(caseId, findingId);
    const next = await applyNow(ctx, caseId);
    options.onState?.(next);
    void logActivity(options.activityLogStore, options.onActivity, caseId, {
      category: "triage",
      action: "finding-severity-restore",
      actor: by,
      detail: restore
        ? `finding ${findingId}: severity restored to ${cap?.from} over the ${cap?.gates.join(", ")} cap`
        : `finding ${findingId}: severity restore undone; the ${cap?.gates.join(", ") ?? "grading"} cap applies again`,
      targetType: "finding",
      targetId: findingId,
    });
    return res.status(200).json({ restored: restore });
  } catch (err) {
    return res.status(500).json({ error: (err as Error).message });
  }
}

// Re-apply every restore record, then the simulation step with the analyst's own override and the
// same host identities synthesis uses.
async function applyNow(ctx: RouteContext, caseId: string) {
  const { options } = ctx;
  const stateStore = options.stateStore!;
  const records = await options.findingSeverityRestoreStore!.load(caseId);
  const treatAsReal = (await options.synthMetaStore?.treatAsReal(caseId)) ?? false;
  const aliasIndex = await loadHostAliasIndex(
    {
      ...(options.assetOverridesStore ? { assetOverrides: options.assetOverridesStore } : {}),
      ...(options.velociraptorClientStore ? { fleet: options.velociraptorClientStore } : {}),
    },
    caseId,
  );
  return ctx.runStateExclusive(caseId, async () => {
    const state = await stateStore.load(caseId);
    const restored = applySeverityRestores(state, records);
    const applied = reconcileSimulationVerdict(restored, { treatAsReal, aliasIndex });
    if (applied !== state) await stateStore.save({ ...applied, updatedAt: new Date().toISOString() });
    return applied;
  });
}
