import type { Response } from "express";
import { openImportPath, type GuardedFile } from "./serverPathGuard.js";

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
