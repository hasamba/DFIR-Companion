/**
 * Shape check for the POST /cases body.
 *
 * caseId used to be the only field whose TYPE was verified. `name`, `investigator` and
 * `aiProvider` went to disk as whatever the wire sent, and the failure then surfaced somewhere
 * else entirely — a numeric `name` reaches zipArchiveFilename's `(name ?? "").trim()` and 500s the
 * archive, long after the request that caused it, with nothing in the error naming the real cause.
 *
 * Lives in its own module rather than inline in routes/caseLifecycle.ts because that file is frozen
 * at its current length by the file-size ledger (#384).
 */
import { isValidCaseId } from "../storage/caseStore.js";

export interface CaseCreateBody {
  caseId?: unknown;
  name?: unknown;
  investigator?: unknown;
  aiProvider?: unknown;
  serverSetId?: unknown;
}

/** The rejection message, or null when the body is well-formed. The caller stores `name` trimmed. */
/** `setExists` answers whether a `serverSetId` names a stored server set. */
export function validateCaseCreateBody(
  body: CaseCreateBody,
  setExists: (id: string) => boolean = () => false,
): string | null {
  const { caseId, name, investigator, aiProvider, serverSetId } = body;
  // A whitespace-only name is as missing as an absent one: it saves a case the list shows blank.
  if (!caseId || !name || (typeof name === "string" && !name.trim())) return "caseId and name are required";
  if (typeof caseId !== "string" || !isValidCaseId(caseId)) {
    return "caseId must use only letters, numbers, dots, dashes, or underscores, and may not contain path traversal";
  }
  if (typeof name !== "string") return "name must be a string";
  if (investigator != null && typeof investigator !== "string") return "investigator must be a string";
  if (aiProvider != null && typeof aiProvider !== "string") return "aiProvider must be a string or null";
  if (serverSetId != null) {
    if (typeof serverSetId !== "string") return "serverSetId must be a string";
    if (!setExists(serverSetId)) return "unknown server set";
  }
  return null;
}
