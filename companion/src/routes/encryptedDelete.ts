// "Delete with encrypted archive" (POST /cases/:id/delete, archiveFirst: "encrypted"). Split out of
// routes/caseLifecycle.ts for #2759.
//
// The case folder goes only after a durable copy of the encrypted archive sits in the cases root —
// the same folder, and the same atomic temp-file-then-rename write, the ZIP path uses. Before
// #2759 the archive lived only in memory and the response body: a dropped socket, a closed tab or
// a proxy timeout after the delete lost the only copy of the case. A failed write throws, so the
// caller answers 500 and nothing is deleted. #2800: the write resolves only once the file and its
// folder entry are fsynced, so a crash right after the delete cannot lose the copy either.
import { basename } from "node:path";
import type { Response } from "express";
import { writeBufferNewFile } from "../analysis/archiveNoClobber.js";
import {
  attachmentContentDisposition,
  dfircaseFilename,
  exportEncryptedCase,
} from "../analysis/caseExportArchive.js";
import type { RouteContext } from "./context.js";

export interface EncryptedDeleteRequest {
  id: string;
  name: string | null | undefined;
  password: string;
}

export async function sendEncryptedArchiveThenDelete(
  ctx: RouteContext,
  res: Response,
  { id, name, password }: EncryptedDeleteRequest,
  deleteCase: () => Promise<{ deleted: boolean }>,
): Promise<Response> {
  const archive = await exportEncryptedCase(ctx.store, id, password, [], {
    runExclusive: ctx.runStateExclusive, // same lock as /export/encrypted (#2247)
  });
  // #2787: never over an earlier copy — a second delete of the same id and name gets " (2)".
  const archivePath = await writeBufferNewFile(
    ctx.store.casesRoot,
    (n) => dfircaseFilename(id, name, n),
    archive,
  );
  const filename = basename(archivePath);
  ctx.serverLogger.info(`[delete] case=${id} encrypted archive saved before deletion: ${archivePath}`);
  const { deleted } = await deleteCase();
  res.type("application/octet-stream");
  res.setHeader("Content-Disposition", attachmentContentDisposition(filename));
  res.setHeader("Cache-Control", "private, no-cache");
  res.setHeader("X-Case-Deleted", String(deleted));
  // Percent-encoded: the case name in the path may hold characters a header value cannot carry.
  res.setHeader("X-Archive-Path", encodeURIComponent(archivePath));
  return res.send(archive);
}
