import type { ForensicEvent } from "../stateTypes.js";
import { promptDescription } from "./promptDescription.js";

/**
 * One forensic event as a prompt line: `[id] timestamp [severity] <asset> description`.
 *
 * Shared by the gap-hypothesis prompt and the second-opinion referee prompt (#1466) so a model
 * that has learned the shape in one pass reads it the same way in the other. The description goes
 * through the head-and-tail renderer (#959) so a derived note past a long base survives (#991).
 */
export function renderEventLine(e: ForensicEvent): string {
  const asset = e.asset ? ` <${e.asset}>` : "";
  const description = promptDescription((e.description ?? "").replace(/\s+/g, " ").trim());
  return `[${e.id}] ${e.timestamp || "(undated)"} [${e.severity}]${asset} ${description}`;
}
