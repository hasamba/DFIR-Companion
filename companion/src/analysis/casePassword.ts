import { randomBytes, scryptSync, timingSafeEqual, createHmac } from "node:crypto";
import type { CaseMeta, CasePasswordHash } from "../types.js";

// Minimum length for a case-lock password (the dashboard's open-case gate). Distinct from
// caseExportArchive.ts's MIN_PASSWORD_LENGTH, which guards the unrelated .dfircase export
// encryption password.
export const MIN_CASE_PASSWORD_LENGTH = 6;

const SALT_LEN = 16;
const HASH_LEN = 32;

// CasePasswordHash ({ salt, hash }, both hex) is defined in ../types.js — it's the shape of
// CaseMeta.password, so it lives with CaseMeta rather than being redefined here.

/** Hash `password` under a fresh random salt. */
export function hashCasePassword(password: string): CasePasswordHash {
  const salt = randomBytes(SALT_LEN);
  const hash = scryptSync(password, salt, HASH_LEN);
  return { salt: salt.toString("hex"), hash: hash.toString("hex") };
}

/** Constant-time check of `password` against a stored hash. */
export function verifyCasePassword(password: string, stored: CasePasswordHash): boolean {
  const salt = Buffer.from(stored.salt, "hex");
  const expected = Buffer.from(stored.hash, "hex");
  const actual = scryptSync(password, salt, expected.length);
  return timingSafeEqual(actual, expected);
}

/** Strip the password hash off a CaseMeta before it ever reaches a JSON response — the
 * salt/hash must never leave the server. Callers get a `hasPassword` flag instead. Use
 * this on EVERY route that serializes a CaseMeta (list, create, status change, etc). */
export function sanitizeCaseMeta(meta: CaseMeta): Omit<CaseMeta, "password"> & { hasPassword: boolean } {
  const { password, ...rest } = meta;
  return { ...rest, hasPassword: Boolean(password) };
}

const TOKEN_SEPARATOR = ".";

interface UnlockPayload {
  caseId: string;
  salt: string;
  exp: number;
  remember: boolean;
}

/** Sign an unlock token for `caseId`, binding it to the case's CURRENT password salt (so
 * changing or removing the password invalidates every previously-issued token) and an
 * absolute expiry `ttlMs` milliseconds from now. `remember` is carried in the token itself
 * (not just the cookie's Max-Age) so a later request can tell whether THIS unlock was a
 * "remember on this computer" one — see {@link isRememberedUnlockToken}. */
export function signUnlockToken(caseId: string, salt: string, secret: Buffer, ttlMs: number, remember: boolean): string {
  const payload: UnlockPayload = { caseId, salt, exp: Date.now() + ttlMs, remember };
  const payloadB64 = Buffer.from(JSON.stringify(payload), "utf8").toString("base64url");
  const sig = createHmac("sha256", secret).update(payloadB64).digest("base64url");
  return `${payloadB64}${TOKEN_SEPARATOR}${sig}`;
}

/** Verify signature, caseId/salt match, and expiry; return the decoded payload on success or
 * null on any mismatch, tamper, or expiry. Never throws. Shared by {@link verifyUnlockToken}
 * and {@link isRememberedUnlockToken} so there's one place that defines "valid". */
function decodeVerifiedPayload(token: string, caseId: string, salt: string, secret: Buffer): UnlockPayload | null {
  const parts = token.split(TOKEN_SEPARATOR);
  if (parts.length !== 2) return null;
  const [payloadB64, sig] = parts;
  const expectedSig = createHmac("sha256", secret).update(payloadB64).digest("base64url");
  const sigBuf = Buffer.from(sig, "utf8");
  const expectedBuf = Buffer.from(expectedSig, "utf8");
  if (sigBuf.length !== expectedBuf.length || !timingSafeEqual(sigBuf, expectedBuf)) return null;

  let payload: Partial<UnlockPayload>;
  try {
    payload = JSON.parse(Buffer.from(payloadB64, "base64url").toString("utf8"));
  } catch {
    return null;
  }
  if (payload.caseId !== caseId || payload.salt !== salt) return null;
  if (typeof payload.exp !== "number" || Date.now() > payload.exp) return null;
  return payload as UnlockPayload;
}

/** Verify a token produced by {@link signUnlockToken} against the CURRENT caseId/salt.
 * Returns false on any mismatch, tamper, or expiry — never throws. */
export function verifyUnlockToken(token: string, caseId: string, salt: string, secret: Buffer): boolean {
  return decodeVerifiedPayload(token, caseId, salt, secret) !== null;
}

/** Whether a token — if it's otherwise valid — was signed with "remember on this computer".
 * False for an invalid, expired, or tampered token, same as for one that's valid but wasn't
 * remembered; callers that need to distinguish "invalid" from "valid but not remembered"
 * should call {@link verifyUnlockToken} first. */
export function isRememberedUnlockToken(token: string, caseId: string, salt: string, secret: Buffer): boolean {
  return Boolean(decodeVerifiedPayload(token, caseId, salt, secret)?.remember);
}

/** Cookie name for a case's unlock token. Safe to build directly from caseId: this is only
 * ever called once a password is known to exist on that case, and case.json only exists
 * for ids created via the validated POST /cases route (isValidCaseId's charset excludes
 * cookie-unsafe characters). */
export function unlockCookieName(caseId: string): string {
  return `dfir_unlock_${caseId}`;
}

/** Parse a raw `Cookie` request header into a name→value map. No `cookie-parser` dependency
 * is installed on this server, and only this one header shape needs parsing. */
export function parseCookieHeader(header: string | undefined): Record<string, string> {
  const out: Record<string, string> = {};
  if (!header) return out;
  for (const part of header.split(";")) {
    const eq = part.indexOf("=");
    if (eq === -1) continue;
    const name = part.slice(0, eq).trim();
    const value = part.slice(eq + 1).trim();
    if (name) out[name] = decodeURIComponent(value);
  }
  return out;
}
