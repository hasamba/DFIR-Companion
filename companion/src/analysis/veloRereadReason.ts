// Why a cut-short Velociraptor read was NOT re-read in the window or newest-first (#1992).
//
// The reason can carry a VQL error string from the server, which is untrusted. It is stored in the
// hunt job, reaches the AI prompt through the collection inventory, and shows in reports. So it is
// folded to one line, stripped of control characters, and capped.

export const MAX_REREAD_REASON_LENGTH = 160;

// C0 controls (incl. newline, tab, ESC), DEL and C1 controls, and the Unicode line/paragraph separators.

const CONTROL_RE = /[\u0000-\u001f\u007f-\u009f\u2028\u2029]+/g;

/** A one-line, capped reason, or "" when `v` is not a non-blank string. */
export function cleanRereadReason(v: unknown): string {
  if (typeof v !== "string") return "";
  const one = v.replace(CONTROL_RE, " ").replace(/ {2,}/g, " ").trim();
  if (!one) return "";
  return one.length > MAX_REREAD_REASON_LENGTH ? `${one.slice(0, MAX_REREAD_REASON_LENGTH - 1)}…` : one;
}
