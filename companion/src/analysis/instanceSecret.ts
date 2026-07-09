import { readFileSync, writeFileSync, mkdirSync } from "node:fs";
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
    if (secret.length === SECRET_LEN) return secret;
  } catch (err) {
    if ((err as NodeJS.ErrnoException).code !== "ENOENT") throw err;
  }
  mkdirSync(casesRoot, { recursive: true });
  const secret = randomBytes(SECRET_LEN);
  writeFileSync(path, secret.toString("hex"), "utf8");
  return secret;
}
