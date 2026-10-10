import type { Response } from "express";
import type { CaseStore } from "../storage/caseStore.js";
import { CopyContentChangedError } from "../storage/handleCopy.js";
import { openImportPath, type GuardedFile } from "./serverPathGuard.js";
import { CHANGED_WHILE_IMPORTING, receiptedFileFor } from "./receiptedFile.js";

/**
 * The one open of the server file POST /cases/:id/import-file reads (#1834).
 *
 * The path guard opens the file and judges the open handle; the route sniffs, reads and copies
 * that handle and never the path again, so a path swapped after the check cannot be read. Sends
 * the 400/403/409 itself and returns null when it did. The handle closes when the response does:
 * every path through the route ends in a response, and nothing reads the handle after the 202
 * (a Plaso import streams from the stored copy). The copy itself goes through
 * CaseStore.saveImportFromHandle so it is hashed into the chain of custody (#2055).
 */
export async function openImportFile(
  filePath: string,
  store: { casesRoot: string; caseDir(caseId: string): string },
  caseId: string,
  res: Response,
): Promise<GuardedFile | null> {
  // The receipt middleware already opened and hashed this very path; read that handle, never a
  // second open that a swapped file could change (#2111). The middleware closes it with the response.
  const receipted = receiptedFileFor(res, filePath);
  if (receipted) return receipted.file;
  let opened;
  try {
    opened = await openImportPath(filePath, store, caseId);
  } catch (err) {
    res.status(400).json({ error: `cannot read file: ${(err as Error).message}` });
    return null;
  }
  if (opened.refusal) {
    res.status(opened.refusal.status).json({ error: opened.refusal.error });
    return null;
  }
  const { handle } = opened.file;
  res.once("close", () => void handle.close().catch(() => undefined));
  return opened.file;
}

/**
 * Copy the judged handle into the case's imports dir. When the receipt hashed this file, the copy
 * must hash the same: a file that grew or changed since is refused with 409 and no copy is kept
 * (#2111). Sends the 409 itself and returns null when it did.
 */
export async function saveReceiptedImport(
  store: CaseStore,
  caseId: string,
  storedName: string,
  src: GuardedFile,
  res: Response,
  filePath: string,
): Promise<{ path: string; bytes: number } | null> {
  const expected = receiptedFileFor(res, filePath)?.sha256;
  try {
    return await store.saveImportFromHandle(caseId, storedName, src.handle, undefined, expected);
  } catch (err) {
    if (!(err instanceof CopyContentChangedError)) throw err;
    res.status(409).json({ error: CHANGED_WHILE_IMPORTING });
    return null;
  }
}
