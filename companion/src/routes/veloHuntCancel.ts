/**
 * Cancel a running bundle hunt from its job card.
 *
 *   POST /cases/:id/velociraptor/hunt-jobs/:huntId/cancel   body { velociraptor: "none" | "stop" | "delete" }
 *
 * The analyst picks what happens on the Velociraptor server: nothing (stop tracking here only), stop
 * the hunt, or delete it with its collected results. Whatever they pick, the companion stops the
 * hunt's auto-collect timer and status poll and never collects it again.
 *
 * ORDER MATTERS. The job is marked "cancelled" FIRST, then its timers are cleared, and only then is
 * Velociraptor asked to stop or delete. The other way round, the status poller would see the hunt
 * STOPPED and start a collect — the cancel itself would trigger an import. The collect path refuses a
 * cancelled job, and a poll already on the network is discarded as stale once the status changed.
 *
 * A refused stop / delete is recorded on the job (`cancelled.serverError`) and returned, so the card
 * can say the hunt may still be running in Velociraptor instead of implying it was stopped.
 *
 * Lives in its own file because routes/velociraptor.ts is at its size-ledger cap.
 */
import type { Express, Request, Response } from "express";
import type { RouteContext } from "./context.js";
import type { VeloHuntCancelAction, VeloHuntJob } from "../analysis/veloHuntStore.js";
import { requestAuthentication } from "../auth/types.js";
import { logActivity } from "../analysis/activityLog.js";
import { deleteHuntOnServer, stopHuntOnServer } from "../integrations/velociraptor/huntControl.js";
import { caseVelo } from "./veloServers.js";

const ACTIONS: readonly VeloHuntCancelAction[] = ["none", "stop", "delete"];
const CANCELLABLE = new Set(["running", "unreachable"]);

function parseAction(raw: unknown): VeloHuntCancelAction | null {
  return ACTIONS.includes(raw as VeloHuntCancelAction) ? (raw as VeloHuntCancelAction) : null;
}

const ACTION_TEXT: Record<VeloHuntCancelAction, string> = {
  none: "stopped tracking it here (it keeps running in Velociraptor)",
  stop: "stopped it in Velociraptor",
  delete: "deleted it from Velociraptor",
};

export function registerVeloHuntCancelRoutes(app: Express, ctx: RouteContext): void {
  const { options } = ctx;

  app.post("/cases/:id/velociraptor/hunt-jobs/:huntId/cancel", async (req: Request, res: Response) => {
    const huntStore = options.veloHuntStore;
    if (!huntStore) return res.status(501).json({ error: "hunt store not configured" });
    const caseId = req.params.id;
    const huntId = req.params.huntId;
    const action = parseAction(req.body?.velociraptor);
    if (!action) return res.status(400).json({ error: "velociraptor must be one of: none, stop, delete" });
    // Only a stop / delete needs the server; "none" works even when Velociraptor is unreachable.
    const vc = action === "none" ? null : caseVelo(ctx, caseId, res);
    if (action !== "none" && !vc) return;

    const view = (await ctx.listVeloHuntJobViews(caseId)).find((j) => j.huntId === huntId);
    if (!view) return res.status(404).json({ error: `no Velociraptor hunt ${huntId} for this case` });
    if (view.collectActive)
      return res
        .status(409)
        .json({ error: "results are being collected for this hunt — wait for it to finish" });
    if (!CANCELLABLE.has(view.status))
      return res
        .status(409)
        .json({ error: `this hunt is ${view.status} — only a running hunt can be cancelled` });

    const by = requestAuthentication(req)?.identity.displayName;
    let refused = null as string | null;
    const marked = await huntStore.update(caseId, huntId, (cur): VeloHuntJob | null => {
      if (!CANCELLABLE.has(cur.status)) {
        refused = cur.status;
        return null;
      }
      return { ...cur, status: "cancelled", cancelled: { at: new Date().toISOString(), by, action } };
    });
    if (!marked) return res.status(404).json({ error: `no Velociraptor hunt ${huntId} for this case` });
    if (refused)
      return res.status(409).json({ error: `this hunt just became ${refused} — it was not cancelled` });
    ctx.stopVeloHuntTimers(caseId, huntId);

    let serverError: string | undefined;
    if (vc) {
      const result =
        action === "delete"
          ? await deleteHuntOnServer(vc.client, huntId)
          : await stopHuntOnServer(vc.client, huntId);
      if (!result.ok) serverError = result.error;
    }
    const job = serverError
      ? ((await huntStore.update(caseId, huntId, (cur) =>
          cur.cancelled ? { ...cur, cancelled: { ...cur.cancelled, serverError } } : null,
        )) ?? marked)
      : marked;
    options.onVeloHunt?.(caseId);
    void logActivity(options.activityLogStore, options.onActivity, caseId, {
      actor: by,
      category: "hunt",
      action: "cancel-hunt",
      detail:
        `cancelled hunt ${huntId} ("${marked.bundleName}") and ${ACTION_TEXT[action]}` +
        (serverError ? ` — Velociraptor refused: ${serverError}` : ""),
      targetType: "hunt",
      targetId: huntId,
      outcome: serverError ? "error" : "success",
    });
    return res.status(200).json({ job, ...(serverError ? { serverError } : {}) });
  });
}
