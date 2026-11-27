import type { Response } from "express";
import type { CaseMasker } from "../analysis/ai/maskRequest.js";
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
  masker: CaseMasker,
): (state: unknown) => Promise<void> {
  const pipeline = options.pipeline;
  const known = masker.known;
  if (!known || !pipeline) return async () => {};
  return (state) => pipeline.presidioGateMasked(caseId, jevScanText(state), known, masker.control);
}

/** The missed-evidence review's gate: one pass over every batch first, then the send-time check. */
export interface JevReviewPresidioGate {
  /** Scan every state the review will send, before the first leaves; ONE hold for all (#2980). */
  preflight(states: readonly unknown[]): Promise<void>;
  /** The send-time check (#1952). Text the preflight cleared is not scanned twice; anything else is. */
  check(state: unknown): Promise<void>;
}

/**
 * The review's gate (#2980). The send-time check alone stopped the review once per batch that held
 * a new value, each stop minutes in and after billing the batches before it. The preflight asks the
 * same question of every planned batch up front. A cleared text is skipped at send time: the same
 * text against the same known-entity snapshot gets the same answer, so a rescan only doubled the
 * Presidio work. A text the preflight never saw (a split half after a size refusal) is scanned.
 */
export function jevReviewPresidioGate(
  options: RouteContext["options"],
  caseId: string,
  masker: CaseMasker,
): JevReviewPresidioGate {
  const pipeline = options.pipeline;
  const known = masker.known;
  if (!known || !pipeline) return { preflight: async () => {}, check: async () => {} };
  let cleared: ReadonlySet<string> = new Set();
  return {
    preflight: async (states) => {
      const texts = states.map(jevScanText);
      await pipeline.presidioGateMasked(caseId, texts, known, masker.control);
      cleared = new Set(texts);
    },
    check: async (state) => {
      const text = jevScanText(state);
      if (cleared.has(text)) return;
      await pipeline.presidioGateMasked(caseId, text, known, masker.control);
    },
  };
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
