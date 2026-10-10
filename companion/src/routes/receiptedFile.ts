import { createHash } from "node:crypto";
import type { Response } from "express";
import type { GuardedFile } from "../storage/serverPathGuard.js";

// The server file the receipt middleware (importReceipt.ts) opened and hashed (#2111). It is handed
// to the import-file / import-mac-login-item handlers so they read the SAME open handle the receipt
// hashed: re-opening the path would receipt one set of bytes and import another if the file was
// replaced in between. The middleware owns the handle and closes it when the response does.

export interface ReceiptedFile {
  /** The trimmed body `path` the handle was opened for. */
  path: string;
  file: GuardedFile;
  sha256: string;
}

export const CHANGED_WHILE_IMPORTING = "file changed while it was being imported";

export function setReceiptedFile(res: Response, receipted: ReceiptedFile): void {
  res.locals.receiptGuardedFile = receipted;
}

/** The receipted handle for exactly this path, or null (a different path, or no receipt ran). */
export function receiptedFileFor(res: Response, filePath: string): ReceiptedFile | null {
  const r = res.locals.receiptGuardedFile as ReceiptedFile | undefined;
  return r && r.path === filePath ? r : null;
}

/** True when `bytes` are not what the receipt hashed. False when there is no receipt for the path. */
export function changedSinceReceipt(res: Response, filePath: string, bytes: Buffer): boolean {
  const r = receiptedFileFor(res, filePath);
  return r !== null && createHash("sha256").update(bytes).digest("hex") !== r.sha256;
}
