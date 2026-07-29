import type { Express, Request, Response } from "express";
import { hashFile, isCustodyEvent, CUSTODY_EVENTS } from "../analysis/custody.js";
import { buildCustodyManifest } from "../analysis/custodyManifest.js";
import { logActivity } from "../analysis/activityLog.js";
import type { RouteContext } from "./context.js";

export function registerCustodyRoutes(app: Express, ctx: RouteContext): void {
  const { store, options, instanceSecret } = ctx;

  // The signed manifest for this case, on demand. Signed with the instance secret, so a manifest
  // fetched here verifies on this installation and nowhere else — which is the point (#231).
  app.get("/cases/:id/custody/manifest", async (req: Request, res: Response) => {
    if (!options.custodyStore) return res.status(501).json({ error: "custody not configured" });
    const caseId = req.params.id;
    if (!(await store.caseExists(caseId))) return res.status(404).json({ error: `case ${caseId} does not exist` });
    try {
      return res.status(200).json(await buildCustodyManifest(store, options.custodyStore, caseId, instanceSecret));
    } catch (err) {
      return res.status(500).json({ error: (err as Error).message });
    }
  });

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

  // Body: { artifactPath, collectedBy?, source?, trigger? }. artifactPath is an absolute path on
  // the server and is read as given — same intentional trust level as POST /import-file and
  // DFIR_NSRL_FILE: a localhost operator tool, not an internet-facing upload. Evidence commonly
  // lives outside the case directory (mounted images, tool output dirs), so the path is not
  // constrained to it.
  app.post("/cases/:id/custody", async (req: Request, res: Response) => {
    if (!options.custodyStore) return res.status(501).json({ error: "custody not configured" });
    const caseId = req.params.id;
    if (!(await store.caseExists(caseId))) return res.status(404).json({ error: `case ${caseId} does not exist` });
    // Same write guard as the other evidence routes: a closed or archived case takes no new records.
    const caseMeta = await store.getCaseMeta(caseId).catch(() => null);
    if (caseMeta?.status === "closed" || caseMeta?.status === "archived") {
      const action = caseMeta.status === "archived" ? "restore it" : "reopen it";
      return res.status(423).json({ error: `Case "${caseId}" is ${caseMeta.status} — ${action} before recording custody` });
    }
    const artifactPath = typeof req.body?.artifactPath === "string" ? req.body.artifactPath.trim() : "";
    if (!artifactPath) return res.status(400).json({ error: "artifactPath is required" });
    const collectedBy = typeof req.body?.collectedBy === "string" ? req.body.collectedBy.trim() : "";
    const source = typeof req.body?.source === "string" ? req.body.source.trim() : "";
    const trigger = typeof req.body?.trigger === "string" ? req.body.trigger.trim() : "";
    // An unrecognized event is rejected rather than quietly filed as a collection: this is the route
    // an analyst uses to record a transfer or a release, and a custody chain that silently relabels
    // what happened to the evidence is worse than one that refuses the entry.
    const rawEvent = req.body?.event;
    if (rawEvent !== undefined && !isCustodyEvent(rawEvent)) {
      return res.status(400).json({ error: `event must be one of: ${CUSTODY_EVENTS.join(", ")}` });
    }
    let sha256: string;
    try {
      sha256 = await hashFile(artifactPath);
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
        event: rawEvent,
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

  // Verify ONE case in the background — what the dashboard fires when an analyst opens a case
  // (#231). Returns immediately: a case with a 40 GB image would otherwise hold the request open
  // for minutes. Throttled inside the monitor, so flipping between cases re-hashes nothing.
  app.post("/cases/:id/custody/verify", async (req: Request, res: Response) => {
    if (!options.integrityMonitor) return res.status(501).json({ error: "evidence integrity monitor not configured" });
    const caseId = req.params.id;
    if (!(await store.caseExists(caseId))) return res.status(404).json({ error: `case ${caseId} does not exist` });
    void options.integrityMonitor.verifyCaseIfStale(caseId).catch(() => { /* alerting happens inside the monitor */ });
    return res.status(202).json({ started: true });
  });

  app.get("/cases/:id/custody/verify", async (req: Request, res: Response) => {
    if (!options.custodyStore) return res.status(501).json({ error: "custody not configured" });
    const caseId = req.params.id;
    if (!(await store.caseExists(caseId))) return res.status(404).json({ error: `case ${caseId} does not exist` });
    try {
      // Two independent questions: did the EVIDENCE change (re-hash each artifact), and did the LOG
      // change (walk the chain). Either alone misses a whole class of tampering — swapping a file
      // leaves the chain intact, and rewriting who collected it leaves every hash intact.
      const [mismatches, chainBreaks] = await Promise.all([
        options.custodyStore.verifyIntegrity(caseId),
        options.custodyStore.verifyChain(caseId),
      ]);
      const problems = [
        mismatches.length ? `${mismatches.length} mismatch(es)` : "",
        chainBreaks.length ? `${chainBreaks.length} chain break(s)` : "",
      ].filter(Boolean);
      logActivity(options.activityLogStore, options.onActivity, caseId, {
        category: "triage", action: "custody-verify",
        detail: problems.length === 0 ? "integrity verified — no mismatches, chain intact" : problems.join(", "),
      });
      return res.status(200).json({ ok: problems.length === 0, mismatches, chainBreaks });
    } catch (err) {
      return res.status(500).json({ error: (err as Error).message });
    }
  });
}
