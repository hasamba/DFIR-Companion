import type { ForensicEvent } from "../stateTypes.js";
import { renderStructuredTags } from "../synthEvidence.js";
import { promptDescription } from "./promptDescription.js";

function lineDescription(e: ForensicEvent): string {
  return promptDescription((e.description ?? "").replace(/\s+/g, " ").trim());
}

/**
 * One forensic event as a prompt line: `[id] timestamp [severity] <asset> description`.
 *
 * The gap-hypothesis prompt's shape. The description goes through the head-and-tail renderer
 * (#959) so a derived note past a long base survives (#991).
 */
export function renderEventLine(e: ForensicEvent): string {
  const asset = e.asset ? ` <${e.asset}>` : "";
  return `[${e.id}] ${e.timestamp || "(undated)"} [${e.severity}]${asset} ${lineDescription(e)}`;
}

/**
 * One forensic event as the second-opinion referee reads it (#1960):
 * `[id] timestamp [severity] description <host:…> <proc:…> <net:…> <cmd:…> <build-time:…> …`.
 *
 * The same structured tags synthesis and the deep pass append (renderStructuredTags, the
 * deepPassRun shape), so the referee judges a disagreement with the facts both models saw. With an
 * asset, this line spells it `<host:…>` after the description, where renderEventLine puts `<asset>`
 * before it. The two lines are identical exactly when renderStructuredTags(e) is empty: no asset,
 * and no tag-producing fact, including facts read from the description or message text (a URL, an
 * ip:port, a renamed-binary note).
 */
export function renderTaggedEventLine(e: ForensicEvent): string {
  return `[${e.id}] ${e.timestamp || "(undated)"} [${e.severity}] ${lineDescription(e)}${renderStructuredTags(e)}`;
}
