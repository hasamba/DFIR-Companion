import type { CaseMeta } from "../types.js";

/** Why an archive request is refused, as the HTTP status and the analyst-facing message. */
export interface ArchiveRefusal {
  readonly code: 400 | 409;
  readonly error: string;
}

/**
 * The status check shared by the two routes that can archive a case (#2758). An archived case
 * cannot be archived again (400). A case that is still open must be closed first (409) — the same
 * rule the delete route enforces — so an investigation in progress never leaves the active list by
 * mistake. `refuseOpen` is false for a plain encrypted export, which copies the case without
 * archiving it. A missing case is left to the caller's own 404.
 */
export function archiveStatusRefusal(
  caseId: string,
  meta: Pick<CaseMeta, "status"> | null | undefined,
  refuseOpen: boolean,
): ArchiveRefusal | undefined {
  if (!meta) return undefined;
  if (meta.status === "archived") return { code: 400, error: `case ${caseId} is already archived` };
  const open = meta.status !== "closed"; // an absent status means open
  if (refuseOpen && open) {
    return { code: 409, error: `case ${caseId} is still open — close it first, then archive it` };
  }
  return undefined;
}
