import type { Express, Request, Response } from "express";
import { logActivity } from "../analysis/activityLog.js";
import type { FindingOutcomePatch } from "../analysis/findingOutcome.js";
import {
  CONTROL_DISPOSITIONS,
  EXECUTION_OUTCOMES,
  type ControlDisposition,
  type ExecutionOutcome,
} from "../analysis/stateTypes.js";
import type { RouteContext } from "./context.js";

// Analyst attack-outcome statements per finding (#930 item 8), on the two axes defined in
// stateTypes.ts: `execution` (was the action itself observed) and `control` (what a security
// control did). Kept in a per-case side file so a re-synthesis never wipes them — see
// findingOutcome.ts. GET lists every record; PATCH upserts one finding's axes/note (null on both
// axes plus an empty note clears the record). Mirrors finding-workflow: the dashboard fetches the
// list and merges it onto the finding cards; the report writer applies it in loadFilteredState.
//
// Its own module rather than routes/findings.ts because that file sits at its size ledger.
export function registerFindingOutcomeRoutes(app: Express, ctx: RouteContext): void {
  const { options } = ctx;

  app.get("/cases/:id/finding-outcome", async (req: Request, res: Response) => {
    if (!options.findingOutcomeStore)
      return res.status(501).json({ error: "finding outcome not configured" });
    try {
      return res.status(200).json(await options.findingOutcomeStore.load(req.params.id));
    } catch (err) {
      return res.status(500).json({ error: (err as Error).message });
    }
  });

  app.patch("/cases/:id/findings/:findingId/outcome", async (req: Request, res: Response) => {
    if (!options.findingOutcomeStore)
      return res.status(501).json({ error: "finding outcome not configured" });
    // Only apply the fields the caller sent, so a control-only PATCH leaves execution intact. A
    // value outside the vocabulary is a 400, not a silent null: the client is wrong and must hear so.
    const patch: FindingOutcomePatch = {};
    const execution = readAxis(req.body?.execution, EXECUTION_OUTCOMES);
    if (execution === "invalid")
      return res
        .status(400)
        .json({ error: `execution must be one of ${EXECUTION_OUTCOMES.join(", ")} (or null to clear)` });
    if (execution !== "absent") patch.execution = execution as ExecutionOutcome | null;
    const control = readAxis(req.body?.control, CONTROL_DISPOSITIONS);
    if (control === "invalid")
      return res
        .status(400)
        .json({ error: `control must be one of ${CONTROL_DISPOSITIONS.join(", ")} (or null to clear)` });
    if (control !== "absent") patch.control = control as ControlDisposition | null;
    if (req.body?.note !== undefined) patch.note = String(req.body.note);
    if (typeof req.body?.updatedBy === "string") patch.updatedBy = req.body.updatedBy;
    if (patch.execution === undefined && patch.control === undefined && patch.note === undefined) {
      return res.status(400).json({ error: "provide execution, control and/or note to update" });
    }
    // Validation is the caller's problem (400); everything past this line is ours (500). The store
    // throws on a blank id, so that check runs here first — a disk-full on save must not come back
    // as a 400 the dashboard reads as "you sent something wrong".
    if (!String(req.params.findingId ?? "").trim())
      return res.status(400).json({ error: "findingId is required" });
    // The finding's semanticKey, so the record can refuse to attach to a different claim later. A
    // finding not in the current state (or no state store) leaves it empty — the id is then all
    // there is, as for every sibling side store.
    patch.semanticKey = await semanticKeyOf(options.stateStore, req.params.id, req.params.findingId);
    try {
      const record = await options.findingOutcomeStore.patch(req.params.id, req.params.findingId, patch);
      options.onFindingOutcome?.(req.params.id);
      void logActivity(options.activityLogStore, options.onActivity, req.params.id, {
        category: "triage",
        action: "finding-outcome",
        actor: patch.updatedBy ?? "",
        detail: record
          ? `finding ${req.params.findingId}: execution=${record.execution ?? "unset"}, control=${record.control ?? "unset"}`
          : `finding ${req.params.findingId}: outcome cleared`,
        targetType: "finding",
        targetId: req.params.findingId,
      });
      return res.status(200).json({ record });
    } catch (err) {
      return res.status(500).json({ error: (err as Error).message });
    }
  });
}

async function semanticKeyOf(
  stateStore: RouteContext["options"]["stateStore"],
  caseId: string,
  findingId: string,
): Promise<string> {
  if (!stateStore) return "";
  try {
    const state = await stateStore.load(caseId);
    return state.findings.find((f) => f.id === findingId)?.semanticKey ?? "";
  } catch {
    return "";
  }
}

// One axis from a request body: absent → "absent"; null or "" → null (clear); a vocabulary value →
// itself; anything else → "invalid".
function readAxis<T extends string>(raw: unknown, vocab: readonly T[]): T | null | "absent" | "invalid" {
  if (raw === undefined) return "absent";
  if (raw === null || raw === "") return null;
  return vocab.includes(String(raw) as T) ? (String(raw) as T) : "invalid";
}
