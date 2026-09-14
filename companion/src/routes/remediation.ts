import type { Express, Request, Response } from "express";
import { logActivity } from "../analysis/activityLog.js";
import {
  receiptNeedsOverride,
  RESIDUAL_RISK_STATUSES,
  taskLinkState,
  validateBoundaryInput,
  type RemediationBoundary,
  type ResidualRiskStatus,
} from "../analysis/remediationBoundary.js";
import { runRemediationVerify } from "../analysis/remediationRun.js";
import { receiptIsStale } from "../analysis/remediationVerify.js";
import type { ForensicEvent } from "../analysis/stateTypes.js";
import type { RouteContext } from "./context.js";

// Post-remediation recurrence checks (#930 item 9 — #969). The analyst declares a boundary,
// triggers a verify (facts and a receipt, never a verdict), attaches evidence, and records the
// residual-risk status against a receipt. Nothing here runs on its own, alerts, isolates, deletes
// or re-checks; the only automatic thing is the arithmetic of the read.
const ATTACH_PER_CALL_MAX = 50;

export function registerRemediationRoutes(app: Express, ctx: RouteContext): void {
  const { options } = ctx;
  const store = () => options.remediationStore;

  const withMarks = async (caseId: string, boundaries: RemediationBoundary[]) => {
    const tasks = options.playbookStore ? await options.playbookStore.load(caseId).catch(() => []) : [];
    const current = await currentHighWater(caseId);
    return boundaries.map((b) => ({
      ...b,
      taskLink: taskLinkState(b.task, tasks),
      receipts: b.receipts.map((r) => ({ ...r, stale: current ? receiptIsStale(r, current) : false })),
    }));
  };

  const currentHighWater = async (caseId: string) => {
    if (!options.stateStore || !options.superTimelineStore) return null;
    try {
      const [state, meta] = await Promise.all([
        options.stateStore.load(caseId),
        options.superTimelineStore.meta(caseId),
      ]);
      return {
        forensic: { rows: state.forensicTimeline.length, updatedAt: state.updatedAt ?? "" },
        super: { rows: meta.rows, generation: meta.generation },
      };
    } catch {
      return null;
    }
  };

  app.get("/cases/:id/remediation", async (req: Request, res: Response) => {
    const s = store();
    if (!s) return res.status(501).json({ error: "remediation store not configured" });
    try {
      return res
        .status(200)
        .json({ boundaries: await withMarks(req.params.id, await s.load(req.params.id)) });
    } catch (err) {
      return res.status(500).json({ error: (err as Error).message });
    }
  });

  app.post("/cases/:id/remediation", async (req: Request, res: Response) => {
    const s = store();
    if (!s) return res.status(501).json({ error: "remediation store not configured" });
    if (!(await ctx.store.caseExists(req.params.id)))
      return res.status(404).json({ error: "case not found" });
    const v = validateBoundaryInput(req.body ?? {}, new Date().toISOString());
    if (!v.ok) return res.status(400).json({ error: v.error });
    try {
      const out = await s.declare(req.params.id, v.boundary);
      if (out === "full")
        return res.status(400).json({ error: "this case already holds the maximum number of boundaries" });
      void logActivity(options.activityLogStore, options.onActivity, req.params.id, {
        category: "triage",
        action: "remediation-declared",
        actor: v.boundary.declaredBy ?? "",
        detail: `${v.boundary.artifact.kind} ${v.boundary.artifact.value} on ${v.boundary.host} at ${v.boundary.remediatedAt}`,
        targetType: "remediation",
        targetId: v.boundary.id,
      });
      return res.status(201).json({ boundary: out });
    } catch (err) {
      return res.status(500).json({ error: (err as Error).message });
    }
  });

  app.delete("/cases/:id/remediation/:bid", async (req: Request, res: Response) => {
    const s = store();
    if (!s) return res.status(501).json({ error: "remediation store not configured" });
    try {
      return (await s.remove(req.params.id, req.params.bid))
        ? res.status(204).end()
        : res.status(404).json({ error: "boundary not found" });
    } catch (err) {
      return res.status(500).json({ error: (err as Error).message });
    }
  });

  app.post("/cases/:id/remediation/:bid/verify", async (req: Request, res: Response) => {
    const s = store();
    if (!s || !options.stateStore || !options.superTimelineStore)
      return res.status(501).json({ error: "remediation verify not configured" });
    try {
      const boundary = (await s.load(req.params.id)).find((b) => b.id === req.params.bid);
      if (!boundary) return res.status(404).json({ error: "boundary not found" });
      const facts = await runRemediationVerify(
        {
          state: options.stateStore,
          superTimeline: {
            meta: (c) => options.superTimelineStore!.meta(c),
            scanWindow: (c, t, budget) => options.superTimelineStore!.scanWindow(c, t, budget),
            cap: options.superTimelineStore.cap,
          },
          ...(options.clockSkewStore ? { clockSkew: options.clockSkewStore } : {}),
          ...(options.importMetaStore ? { importMeta: options.importMetaStore } : {}),
          ...(options.assetOverridesStore ? { assetOverrides: options.assetOverridesStore } : {}),
          ...(options.velociraptorClientStore ? { fleet: options.velociraptorClientStore } : {}),
        },
        req.params.id,
        boundary,
      );
      await s.addReceipt(req.params.id, boundary.id, facts.receipt);
      return res.status(200).json(facts);
    } catch (err) {
      return res.status(500).json({ error: (err as Error).message });
    }
  });

  app.patch("/cases/:id/remediation/:bid/status", async (req: Request, res: Response) => {
    const s = store();
    if (!s) return res.status(501).json({ error: "remediation store not configured" });
    const status = req.body?.status as ResidualRiskStatus;
    if (!(RESIDUAL_RISK_STATUSES as readonly string[]).includes(status))
      return res.status(400).json({ error: `status must be one of ${RESIDUAL_RISK_STATUSES.join(", ")}` });
    const receiptId = typeof req.body?.receiptId === "string" ? req.body.receiptId : "";
    if (status !== "unreviewed" && !receiptId)
      return res
        .status(400)
        .json({ error: "a status other than unreviewed must name the receipt it was read against" });
    const note = typeof req.body?.note === "string" ? req.body.note : undefined;
    const overrideNote = typeof req.body?.override === "string" ? req.body.override.trim() : "";
    try {
      const boundary = (await s.load(req.params.id)).find((b) => b.id === req.params.bid);
      if (!boundary) return res.status(404).json({ error: "boundary not found" });
      if (receiptId) {
        const receipt = boundary.receipts.find((r) => r.id === receiptId);
        if (!receipt) return res.status(404).json({ error: "receipt not found on this boundary" });
        if (status === "checked-not-observed") {
          const reasons = receiptNeedsOverride(receipt);
          if (reasons.length && !overrideNote)
            return res.status(409).json({
              error: `checked-not-observed needs an override note: ${reasons.join("; ")}`,
              reasons,
            });
        }
      }
      const next = await s.setStatus(req.params.id, boundary.id, {
        status,
        ...(note !== undefined ? { note } : {}),
        ...(overrideNote ? { overrideNote } : {}),
        ...(receiptId ? { receiptId } : {}),
        at: new Date().toISOString(),
      });
      if (!next) return res.status(404).json({ error: "boundary not found" });
      void logActivity(options.activityLogStore, options.onActivity, req.params.id, {
        category: "triage",
        action: "remediation-status",
        actor: typeof req.body?.updatedBy === "string" ? req.body.updatedBy : "",
        detail: `${boundary.artifact.kind} ${boundary.artifact.value} on ${boundary.host}: ${status}${receiptId ? ` (receipt ${receiptId})` : ""}`,
        targetType: "remediation",
        targetId: boundary.id,
      });
      return res.status(200).json({ boundary: (await withMarks(req.params.id, [next]))[0] });
    } catch (err) {
      return res.status(500).json({ error: (err as Error).message });
    }
  });

  app.post("/cases/:id/remediation/:bid/attach", async (req: Request, res: Response) => {
    const s = store();
    if (!s || !options.stateStore) return res.status(501).json({ error: "remediation store not configured" });
    const ids: string[] = Array.isArray(req.body?.eventIds)
      ? [...new Set((req.body.eventIds as unknown[]).map((x) => String(x).trim()).filter(Boolean))]
      : [];
    if (!ids.length) return res.status(400).json({ error: "eventIds is required" });
    if (ids.length > ATTACH_PER_CALL_MAX)
      return res.status(400).json({ error: `attach at most ${ATTACH_PER_CALL_MAX} events per call` });
    try {
      const boundary = (await s.load(req.params.id)).find((b) => b.id === req.params.bid);
      if (!boundary) return res.status(404).json({ error: "boundary not found" });
      const state = await options.stateStore.load(req.params.id);
      const forensic = new Set(state.forensicTimeline.map((e) => e.id));
      const toPromote: ForensicEvent[] = [];
      for (const id of ids) {
        if (forensic.has(id)) continue;
        const row = options.superTimelineStore
          ? await options.superTimelineStore.get(req.params.id, id)
          : null;
        if (!row)
          return res
            .status(404)
            .json({ error: `event ${id} is in neither the forensic timeline nor the super-timeline` });
        toPromote.push(row);
      }
      // A super-timeline row enters the case the way every analyst promotion does — by promotion,
      // with its intent — so the forensic / super-timeline boundary is kept literally.
      if (toPromote.length) {
        if (!options.pipeline) return res.status(501).json({ error: "promotion not configured" });
        await options.pipeline.promoteSuperTimeline(req.params.id, toPromote, {
          importedAt: new Date().toISOString(),
          intent: "remediation-check",
          note: `attached as remediation evidence for ${boundary.id}`,
        });
      }
      const out = await s.attach(req.params.id, boundary.id, ids);
      if (out === "full")
        return res
          .status(400)
          .json({ error: "this boundary already holds the maximum number of evidence rows" });
      if (!out) return res.status(404).json({ error: "boundary not found" });
      return res
        .status(200)
        .json({ boundary: (await withMarks(req.params.id, [out]))[0], promoted: toPromote.length });
    } catch (err) {
      return res.status(500).json({ error: (err as Error).message });
    }
  });
}
