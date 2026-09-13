import type { AiStatusEvent } from "./appOptions.js";
import { redactPaths } from "../analysis/redactPaths.js";

/**
 * Strip absolute filesystem paths from an `onAiStatus` event before it reaches the live feed (#1029).
 *
 * The HTTP error surface already does this once, at the `res.json` choke point (#250). The AI-status
 * channel is a second wire: nine route catch blocks put a raw `err.message` in `detail`, and
 * `appWiring` broadcasts the event to every dashboard subscribed to the case. Node's fs errors carry
 * the full path, so an `EACCES` on a background import would name the cases root and the case
 * folder on the WebSocket. Redacting here — the one seam every caller passes through — covers every
 * current and future site with no per-handler opt-in, the same reasoning as #250.
 *
 * Only `detail` is rewritten; the other fields are timestamps and enums. Returns a new object.
 */
export function redactAiStatusEvent(event: AiStatusEvent, roots: readonly string[]): AiStatusEvent {
  if (typeof event.detail !== "string") return { ...event };
  return { ...event, detail: redactPaths(event.detail, roots) };
}
