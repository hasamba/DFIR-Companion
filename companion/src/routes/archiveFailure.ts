// The status and body an archive, export or report route answers when packaging or reading a whole
// case fails. Shared so every such route answers the same way.
//
// A damaged state file (#2794) is the analyst's to fix — restore the file from a backup — so it is
// the same named 409 GET /cases/:id/state answers, never the raw sqlite text as a 500. A case folder
// that kept changing while it was packaged (#2795) is a retry-later 503 with the named message.
import type { Response } from "express";
import { StateFileCorruptError } from "../storage/stateFileCorrupt.js";
import { CaseFileVanishedError } from "../analysis/caseArchiveSettle.js";

interface ArchiveFailureResponse {
  status: number;
  body: { error: string; code: string; file?: string };
}

/** The response for a known, named failure, or null when `err` is a real server error (500). */
function archiveFailureResponse(err: unknown): ArchiveFailureResponse | null {
  if (err instanceof StateFileCorruptError)
    return { status: 409, body: { error: err.message, code: err.code, file: err.file } };
  if (err instanceof CaseFileVanishedError)
    return { status: err.httpStatus, body: { error: err.message, code: err.code } };
  return null;
}

/** Answer `err`: its named status when it is a known failure, otherwise a 500 with its message. */
export function answerArchiveFailure(res: Response, err: unknown): Response {
  const known = archiveFailureResponse(err);
  if (known) return res.status(known.status).json(known.body);
  return res.status(500).json({ error: (err as Error).message });
}
