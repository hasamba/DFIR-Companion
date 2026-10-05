import type { Response } from "express";
import type { buildImportAnonContext } from "../analysis/ai/providerCall.js";
import { PresidioApprovalRequired, PresidioScanError } from "../analysis/presidio.js";
import { sendPipelineError } from "./presidioApproval.js";
import type { RouteContext } from "./context.js";

/**
 * The Presidio gate for the Jev routes (#1952).
 *
 * The Jev routes mask their payload with the case's anonymizer, but they call OpenRouter through
 * their own client, not through `analyzeRestored`, so the Presidio gate never ran on them. This
 * module is that gate for them: it scans exactly the masked values a request carries, right before
 * the send, and fails closed the same way every other AI call does — a new value holds the call
 * for approval, an unreachable analyzer stops it.
 */

type AnonContext = Awaited<ReturnType<typeof buildImportAnonContext>>;

/** Every string value in a Jev state, except the static top-level `note` (instructions, not case data). */
export function jevScanText(state: unknown): string {
  const out: string[] = [];
  const walk = (v: unknown): void => {
    if (typeof v === "string") out.push(v);
    else if (Array.isArray(v)) v.forEach(walk);
    else if (v && typeof v === "object") Object.values(v).forEach(walk);
  };
  if (state && typeof state === "object" && !Array.isArray(state)) {
    for (const [k, v] of Object.entries(state)) if (k !== "note") walk(v);
  } else walk(state);
  return out.join("\n");
}

/**
 * A check to run on a Jev state before it is sent. With anonymisation off there is nothing masked
 * for Presidio to see (the same rule as every other AI path), so the check does nothing.
 */
export function jevPresidioCheck(
  options: RouteContext["options"],
  caseId: string,
  anon: AnonContext,
): (state: unknown) => Promise<void> {
  const pipeline = options.pipeline;
  if (!anon || !pipeline) return async () => {};
  return (state) => pipeline.presidioGateMasked(caseId, jevScanText(state), anon.known, anon.control);
}

/** Answer a Presidio stop the way every other AI route does; false when `err` is not one. */
export function sendJevPresidioStop(
  res: Response,
  err: unknown,
  caseId: string,
  options: RouteContext["options"],
): boolean {
  if (!(err instanceof PresidioApprovalRequired) && !(err instanceof PresidioScanError)) return false;
  sendPipelineError(res, err, { caseId, onAiStatus: options.onAiStatus });
  return true;
}
