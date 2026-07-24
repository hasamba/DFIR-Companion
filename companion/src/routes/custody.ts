import type { Express, Request, Response } from "express";
import { createHash } from "node:crypto";
import { readFile } from "node:fs/promises";
import { logActivity } from "../analysis/activityLog.js";
import type { RouteContext } from "./context.js";

export function registerCustodyRoutes(app: Express, ctx: RouteContext): void {
  const { store, options } = ctx;

  app.get("/cases/:id/custody", async (req: Request, res: Response) => {
    if (!options.custodyStore) return res.status(501).json({ error: "custody not configured" });
    const caseId = req.params.id;
    if (!(await store.caseExists(caseId))) return res.status(404).json({ error: `case ${caseId} does not exist` });
    try {
      const records = await options.custodyStore.load(caseId);
      return res.status(200).json({ records });
    } catch (err) {
      return res.status(500).json({ error: (err as Error).message });
    }
  });

  app.post("/cases/:id/custody", async (req: Request, res: Response) => {
    if (!options.custodyStore) return res.status(501).json({ error: "custody not configured" });
    const caseId = req.params.id;
    if (!(await store.caseExists(caseId))) return res.status(404).json({ error: `case ${caseId} does not exist` });
    const artifactPath = typeof req.body?.artifactPath === "string" ? req.body.artifactPath.trim() : "";
    if (!artifactPath) return res.status(400).json({ error: "artifactPath is required" });
    const collectedBy = typeof req.body?.collectedBy === "string" ? req.body.collectedBy.trim() : "";
    const source = typeof req.body?.source === "string" ? req.body.source.trim() : "";
    const trigger = typeof req.body?.trigger === "string" ? req.body.trigger.trim() : "";
    let sha256: string;
    try {
      const bytes = await readFile(artifactPath);
      sha256 = createHash("sha256").update(bytes).digest("hex");
    } catch (err) {
      return res.status(400).json({ error: `could not read artifact: ${(err as Error).message}` });
    }
    try {
      const record = await options.custodyStore.record(caseId, {
        artifactPath,
        sha256,
        collectedBy: collectedBy || "analyst",
        collectedAt: new Date().toISOString(),
        source,
        trigger,
        caseId,
      });
      logActivity(options.activityLogStore, options.onActivity, caseId, {
        category: "triage", action: "custody-record", actor: collectedBy || "analyst",
        detail: `recorded custody for ${artifactPath} (${sha256.slice(0, 12)}…)`,
      });
      return res.status(201).json({ ok: true, record });
    } catch (err) {
      return res.status(500).json({ error: (err as Error).message });
    }
  });

  app.get("/cases/:id/custody/verify", async (req: Request, res: Response) => {
    if (!options.custodyStore) return res.status(501).json({ error: "custody not configured" });
    const caseId = req.params.id;
    if (!(await store.caseExists(caseId))) return res.status(404).json({ error: `case ${caseId} does not exist` });
    try {
      const mismatches = await options.custodyStore.verifyIntegrity(caseId);
      logActivity(options.activityLogStore, options.onActivity, caseId, {
        category: "triage", action: "custody-verify",
        detail: mismatches.length === 0 ? "integrity verified — no mismatches" : `${mismatches.length} mismatch(es)`,
      });
      return res.status(200).json({ ok: mismatches.length === 0, mismatches });
    } catch (err) {
      return res.status(500).json({ error: (err as Error).message });
    }
  });
}
