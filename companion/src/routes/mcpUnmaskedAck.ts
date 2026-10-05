import type { Request, Response } from "express";
import { AnonControlStore } from "../analysis/anonControl.js";
import type { CaseStore } from "../storage/caseStore.js";

/**
 * The MCP acknowledgement gate (#1952).
 *
 * Masking cannot apply on the MCP path: the Companion is not the MCP client. Claude Code calls the
 * tools and reads their output itself, so tool output (process lists, users, hosts) and the
 * analyst's prompt reach the model in clear. On a case with anonymisation on, every MCP run route
 * therefore refuses with 409 until the request carries `ackUnmasked: true` — the analyst saw the
 * warning and chose to continue. An API caller cannot skip it. With anonymisation off for the case
 * the analyst has already chosen to send in clear, so nothing is asked.
 */

export const MCP_UNMASKED_ACK_ERROR = "mcp_unmasked_ack_required";

export const MCP_UNMASKED_WARNING =
  "MCP runs are not anonymized. This case has anonymization on, but Claude Code reads the tool " +
  "output and your instruction directly, so host names, user names, IPs and file paths reach it " +
  "unmasked. Continue only if that is acceptable for this case.";

/** Answer 409 and return true when the run needs the acknowledgement it did not carry. */
export async function refuseUnmaskedMcp(req: Request, res: Response, store: CaseStore): Promise<boolean> {
  if (req.body?.ackUnmasked === true) return false;
  const control = await new AnonControlStore(store).load(req.params.id);
  if (!control.enabled) return false;
  res.status(409).json({ error: MCP_UNMASKED_ACK_ERROR, message: MCP_UNMASKED_WARNING });
  return true;
}
