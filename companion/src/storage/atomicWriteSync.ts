import { randomUUID } from "node:crypto";
import { chmodSync, renameSync, unlinkSync, writeFileSync } from "node:fs";

// Synchronous sibling of atomicWrite's writeThenRename, for small owner-only files that live
// outside a case folder (the cloud account vault, server sets). Writes a uniquely named temp file
// and renames it over `path`. If the write OR the rename throws, the temp file is removed (best
// effort) and the error is rethrown, so a failed write never leaves a sealed copy behind (#2342).
// No retries: a transient Windows lock surfaces to the caller as before.
export function atomicWriteFileSync(path: string, text: string): void {
  const tmp = `${path}.${randomUUID()}.tmp`;
  try {
    writeFileSync(tmp, text, { mode: 0o600 });
    renameSync(tmp, path);
  } catch (err) {
    discardTemp(tmp);
    throw err;
  }
  try {
    chmodSync(path, 0o600);
  } catch {
    // chmod is best effort on Windows.
  }
}

function discardTemp(tmp: string): void {
  try {
    unlinkSync(tmp);
  } catch {
    // Best effort: the temp file may never have been created.
  }
}
