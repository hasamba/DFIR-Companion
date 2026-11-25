// One read of a Velociraptor server's enrolled clients, and whether that read was CUT (#2887).
//
// Every whole-fleet `clients()` read uses one row limit. A read that comes back AT that limit may
// have left enrolled clients out — `clients()` has no fixed order, so which ones can change between
// reads — and nothing used to say so: the endpoint picker and the inventory read as the whole fleet.
// The snapshot now carries `truncated`, the server log gets a warning, and a host that is not in a
// cut list is reported as possibly past the cut rather than as not enrolled.
import { warnLine } from "../../logging/serverLogger.js";
import { normalizeClientRow, type VeloClientRecord } from "./clientInventory.js";

/** The row limit on every whole-fleet `clients()` read: the inventory and the AI Agent Run check. */
export const CLIENT_LOOKUP_LIMIT = 100_000;
const LIMIT_TEXT = CLIENT_LOOKUP_LIMIT.toLocaleString("en-US");

export interface ClientSnapshot {
  clients: VeloClientRecord[];
  /** The read came back at the row limit, so it may not hold every enrolled client. */
  truncated: boolean;
}

/**
 * Normalize the raw `clients()` rows. The limit is compared with the RAW row count: a row dropped for
 * an invalid client id still used up one of the server's rows.
 */
export function clientSnapshot(rows: unknown[]): ClientSnapshot {
  const clients = rows.flatMap((row) => normalizeClientRow(row) ?? []);
  const truncated = rows.length >= CLIENT_LOOKUP_LIMIT;
  if (truncated)
    warnLine(
      `[velociraptor] the client list reached the ${LIMIT_TEXT} row limit — clients past it are not in the inventory or the endpoint pickers`,
    );
  return { clients, truncated };
}

/** The error for a host no inventory record matches; a cut list may simply not reach that host. */
export function hostMissMessage(
  host: string,
  truncated: boolean,
  refreshHint = "refresh the client list",
): string {
  const base = `No enrolled Velociraptor client matches host "${host}"`;
  return truncated
    ? `${base} — the server returned only the first ${LIMIT_TEXT} clients, so it may be enrolled past that; run a fleet hunt or use the Velociraptor GUI instead`
    : `${base} — ${refreshHint} or run a fleet hunt instead`;
}
