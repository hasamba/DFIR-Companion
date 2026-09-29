import { createWriteStream } from "node:fs";
import { unlink, type FileHandle } from "node:fs/promises";
import { pipeline } from "node:stream/promises";
import type { Response } from "express";
import { openImportPath, type GuardedFile } from "./serverPathGuard.js";
import { withCaseWrite } from "../storage/caseIncarnation.js";

/**
 * The one open of the server file POST /cases/:id/import-file reads (#1834).
 *
 * The path guard opens the file and judges the open handle; the route sniffs, reads and copies
 * that handle and never the path again, so a path swapped after the check cannot be read. Sends
 * the 400/403/409 itself and returns null when it did. The handle closes when the response does:
 * every path through the route ends in a response, and nothing reads the handle after the 202
 * (a Plaso import streams from the stored copy).
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

/**
 * Copy the whole open file to `dest`, which must not exist (never overwrite evidence already on
 * disk, #214). Returns the bytes written. A partial copy this call created is removed on failure;
 * an existing `dest` is never touched.
 */
export async function copyHandleExclusive(handle: FileHandle, dest: string): Promise<number> {
  return withCaseWrite(dest, () => copyAdmitted(handle, dest)); // refused for a deleted case (#1855)
}

async function copyAdmitted(handle: FileHandle, dest: string): Promise<number> {
  const out = createWriteStream(dest, { flags: "wx" });
  let created = false;
  out.once("open", () => (created = true));
  let bytes = 0;
  const src = handle.createReadStream({ start: 0, autoClose: false, highWaterMark: 1 << 20 });
  src.on("data", (chunk) => (bytes += chunk.length));
  try {
    await pipeline(src, out);
  } catch (err) {
    if (created) await unlink(dest).catch(() => undefined);
    throw err;
  }
  return bytes;
}
