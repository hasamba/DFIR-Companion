import type { Express, Request, Response } from "express";
import { logActivity } from "../analysis/activityLog.js";
import { normalizeHuntExpirySeconds } from "../integrations/velociraptor/velociraptorApi.js";
import { vqlSizeProblem } from "../analysis/vqlInput.js";
import { isValidCaseId } from "../storage/caseStore.js";
import type { RouteContext } from "./context.js";

// The two bare (case-less) VQL routes: run a query, launch a fleet hunt. Split out of
// routes/velociraptor.ts for #832 — they were the only Velociraptor actions that reached the fleet
// without a line in any case's activity log. An optional `caseId` in the body names the case the
// analyst is working in; when it is given, the action is recorded there (what was run, against what,
// how it ended), and the store stamps the authenticated identity in team mode. Without it the
// pre-existing case-less contract holds: the request logger is the only trace.

// How much of the VQL an activity entry keeps. Enough to recognise the query, small enough that a
// compiled Sigma rule (tens of KB) cannot turn the append-only log into a copy of every hunt.
export const VQL_DETAIL_LIMIT = 500;

export function truncateVql(vql: string): string {
  return vql.length > VQL_DETAIL_LIMIT ? vql.slice(0, VQL_DETAIL_LIMIT) + "…" : vql;
}

export function registerVelociraptorVqlRoutes(app: Express, ctx: RouteContext): void {
  const { options, store } = ctx;
  const logLine = (msg: string): void => ctx.serverLogger.info(msg);

  // Resolve the optional caseId. Returns the id to log under ("" when the caller named none), or
  // sends the refusal and returns null. A caseId that is present but unknown is refused BEFORE the
  // query runs: silently dropping the audit line would defeat the point of sending one.
  async function auditCase(req: Request, res: Response): Promise<string | null> {
    const raw = req.body?.caseId;
    if (raw === undefined || raw === null || raw === "") return "";
    const caseId = typeof raw === "string" ? raw.trim() : "";
    if (!caseId || !isValidCaseId(caseId)) {
      res.status(400).json({ error: "caseId must be a valid case id" });
      return null;
    }
    if (!(await store.caseExists(caseId))) {
      res.status(404).json({ error: `case "${caseId}" not found` });
      return null;
    }
    return caseId;
  }

  // Awaited, not fire-and-forget: the response must not leave before the audit line has landed,
  // or a caller that reads the log right after gets a fleet action with no record of it.
  function record(
    caseId: string,
    action: "run-vql" | "launch-hunt",
    detail: string,
    outcome: "success" | "error",
    targetId?: string,
  ): Promise<void> {
    if (!caseId) return Promise.resolve();
    return logActivity(options.activityLogStore, options.onActivity, caseId, {
      category: "hunt",
      action,
      detail,
      outcome,
      ...(targetId ? { targetType: "hunt", targetId } : {}),
    });
  }

  // Run a VQL query against the configured Velociraptor server (via its API) and return the rows.
  // Powers the hunt-pivot modal's "Run in Velociraptor" button. 501 when not configured. The VQL is
  // analyst-authored (from the generated pivots) — localhost only, opt-in via DFIR_VELOCIRAPTOR_*.
  app.post("/velociraptor/run", async (req: Request, res: Response) => {
    if (!options.velociraptorClient)
      return res
        .status(501)
        .json({ error: "Velociraptor API not configured (set DFIR_VELOCIRAPTOR_API_CONFIG)" });
    const vql = typeof req.body?.vql === "string" ? req.body.vql.trim() : "";
    if (!vql) return res.status(400).json({ error: "vql is required" });
    if (vqlSizeProblem(vql)) return res.status(400).json({ error: vqlSizeProblem(vql) });
    const caseId = await auditCase(req, res);
    if (caseId === null) return;
    try {
      logLine(`[velociraptor] run query (${vql.length} chars)`);
      const result = await options.velociraptorClient.run(vql);
      logLine(`[velociraptor] query DONE -> ${result.total} rows${result.truncated ? " (truncated)" : ""}`);
      await record(
        caseId,
        "run-vql",
        `ran VQL on the server -> ${result.total} row(s)${result.truncated ? " (truncated)" : ""}: ${truncateVql(vql)}`,
        "success",
      );
      return res.status(200).json(result);
    } catch (err) {
      logLine(`[velociraptor] query ERROR: ${(err as Error).message}`);
      await record(caseId, "run-vql", `VQL failed: ${(err as Error).message} — ${truncateVql(vql)}`, "error");
      return res.status(502).json({ error: (err as Error).message });
    }
  });

  // Launch a HUNT that runs the pivot VQL on ALL enrolled endpoints (packages it as a CLIENT
  // artifact, then creates the hunt). This is the dashboard's "Run hunt on all clients" action.
  app.post("/velociraptor/hunt", async (req: Request, res: Response) => {
    if (!options.velociraptorClient)
      return res
        .status(501)
        .json({ error: "Velociraptor API not configured (set DFIR_VELOCIRAPTOR_API_CONFIG)" });
    const vql = typeof req.body?.vql === "string" ? req.body.vql.trim() : "";
    const description = typeof req.body?.description === "string" ? req.body.description : "";
    if (!vql) return res.status(400).json({ error: "vql is required" });
    if (vqlSizeProblem(vql)) return res.status(400).json({ error: vqlSizeProblem(vql) });
    const expirySeconds = normalizeHuntExpirySeconds(req.body?.expirySeconds); // relative; defaults to one hour
    const caseId = await auditCase(req, res);
    if (caseId === null) return;
    try {
      logLine(`[velociraptor] launch hunt: ${description.slice(0, 80)} (expires in ${expirySeconds}s)`);
      const result = await options.velociraptorClient.launchHunt(vql, description, { expirySeconds });
      logLine(
        `[velociraptor] hunt launched -> ${result.huntId} (artifact ${result.artifact}, ${result.sources.length} source(s))`,
      );
      await record(
        caseId,
        "launch-hunt",
        `fleet hunt ${result.huntId} "${description}" launched on all clients: ${truncateVql(vql)}`,
        "success",
        result.huntId,
      );
      return res.status(200).json(result);
    } catch (err) {
      logLine(`[velociraptor] hunt ERROR: ${(err as Error).message}`);
      await record(
        caseId,
        "launch-hunt",
        `fleet hunt "${description}" failed: ${(err as Error).message} — ${truncateVql(vql)}`,
        "error",
      );
      return res.status(502).json({ error: (err as Error).message });
    }
  });
}
