import { readFileSync, writeFileSync, mkdirSync, chmodSync, statSync } from "node:fs";
import { randomBytes } from "node:crypto";
import { join } from "node:path";

const SECRET_FILE = ".instance-secret";
const SECRET_LEN = 32;

/** Load this installation's HMAC signing secret from `<casesRoot>/.instance-secret`,
 * generating and persisting a fresh one on first use. Synchronous and meant to be called
 * once at server startup (createApp is itself synchronous) — verification is stateless
 * (recompute the HMAC), so unlocked sessions survive a server restart as long as this file
 * is still present. If the file is missing or corrupt, a new secret is generated, which
 * invalidates every previously-issued unlock cookie (a safe fallback, not a security hole —
 * it just requires re-entering case passwords once). */
export function loadOrCreateInstanceSecret(casesRoot: string): Buffer {
  const path = join(casesRoot, SECRET_FILE);
  try {
    const hex = readFileSync(path, "utf8").trim();
    const secret = Buffer.from(hex, "hex");
    if (secret.length === SECRET_LEN) {
      restrictToOwner(path);
      return secret;
    }
  } catch (err) {
    if ((err as NodeJS.ErrnoException).code !== "ENOENT") throw err;
  }
  mkdirSync(casesRoot, { recursive: true });
  const secret = randomBytes(SECRET_LEN);
  writeFileSync(path, secret.toString("hex"), { encoding: "utf8", mode: 0o600 });
  // The mode above only applies when writeFileSync CREATES the file; on the corrupt-secret path
  // it is overwriting an existing one, whose mode is preserved.
  restrictToOwner(path);
  return secret;
}

/**
 * Best-effort `chmod 0600`, on both the create and the load path.
 *
 * The load path is the one that matters: an install that first ran before the mode was passed on
 * write left this file at the process umask (typically 0644 — world-readable, on a file whose
 * HMAC signs every unlock cookie). Those installs never take the create path again, so a mode on
 * create alone would never reach a single one of them — the fix would only ever protect
 * installations that were never exposed. Called on every startup, so it stays fixed even if
 * something else loosens it later.
 *
 * Skipped on Windows, where POSIX modes aren't meaningful (chmod only toggles the read-only bit)
 * and the stat would report a permanently "loose" mode, chmod-ing pointlessly on every startup.
 */
function restrictToOwner(path: string): void {
  if (process.platform === "win32") return;
  try {
    if ((statSync(path).mode & 0o077) === 0) return; // already owner-only — leave ctime alone
    chmodSync(path, 0o600);
  } catch {
    // Best-effort: a read-only mount, or a file owned by another user, must not stop the server
    // from starting — the secret itself is still usable, it's just no better protected than before.
  }
}
