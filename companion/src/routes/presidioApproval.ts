import type { Response } from "express";
import { PresidioApprovalRequired } from "../analysis/presidio.js";

// Routes in this codebase catch their own errors and answer 500 directly, so there is no error
// middleware to hook. This helper is the drop-in replacement for that catch body wherever a
// route can reach an AI call: it distinguishes the approval gate from a genuine failure.
export function sendPipelineError(res: Response, err: unknown): Response {
  if (err instanceof PresidioApprovalRequired) {
    return res.status(409).json({ error: "presidio_approval_required", findings: err.findings });
  }
  return res.status(500).json({ error: (err as Error)?.message ?? String(err) });
}
