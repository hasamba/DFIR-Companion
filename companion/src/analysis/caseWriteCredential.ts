import type { Response } from "express";
import {
  parseCookieHeader,
  unlockCookieName,
  verifyUnlockToken,
  verifyCasePassword,
} from "./casePassword.js";
import type { CasePasswordHash } from "../types.js";
import { getUnlockLimiter } from "../http/rateLimiter.js";

/** What a write into a password-protected case presented as proof (#2135). */
export interface CaseWriteCredentialInput {
  caseId: string;
  stored: CasePasswordHash;
  cookieHeader: string | undefined;
  bodyPassword: unknown;
  secret: Buffer;
}

export type CaseWriteDecision =
  | { ok: true }
  | { ok: false; status: 401; body: { error: "locked"; caseId: string } }
  | { ok: false; status: 429; retryAfterMs: number; body: { error: string; retryAfterMs: number } };

/**
 * The one check for an evidence WRITE into a locked case: the dashboard's unlock cookie OR the case
 * password in the request body (the browser extension's path). Shared by POST /captures and the
 * case-lock gate's POST /cases/:id/import, so both run through the SAME unlock limiter as POST
 * /cases/:id/unlock: guesses on any of the three count toward one lockout, and the lockout check,
 * the derivation and the count run as one serialized step per case (AttemptLimiter.attempt).
 *
 * A request that carries neither a cookie nor a password is refused WITHOUT counting: it guesses
 * nothing, and counting it would let a client with no password (an extension still waiting for the
 * analyst to type it) lock the analyst out of their own dashboard.
 */
export async function checkCaseWriteCredential(input: CaseWriteCredentialInput): Promise<CaseWriteDecision> {
  const { caseId, stored, secret } = input;
  const token = parseCookieHeader(input.cookieHeader)[unlockCookieName(caseId)];
  const cookieOk = Boolean(token && verifyUnlockToken(token, caseId, stored.salt, secret));
  const bodyPassword = typeof input.bodyPassword === "string" ? input.bodyPassword : "";
  const refused = { ok: false as const, status: 401 as const, body: { error: "locked" as const, caseId } };
  if (!cookieOk && !bodyPassword) return refused;

  // A valid unlock cookie is proof already; only a body password costs a derivation.
  const outcome = await getUnlockLimiter().attempt(caseId, () =>
    cookieOk ? Promise.resolve(true) : verifyCasePassword(bodyPassword, stored),
  );
  if (outcome.kind === "ok") return { ok: true };
  if (outcome.kind === "locked") {
    return {
      ok: false,
      status: 429,
      retryAfterMs: outcome.retryAfterMs,
      body: { error: "too many failed attempts, try again later", retryAfterMs: outcome.retryAfterMs },
    };
  }
  if (outcome.lockoutMs > 0) {
    return {
      ok: false,
      status: 429,
      retryAfterMs: outcome.lockoutMs,
      body: { error: "too many failed attempts, locked out", retryAfterMs: outcome.lockoutMs },
    };
  }
  return refused;
}

/** Send a refused {@link CaseWriteDecision} (429s carry Retry-After in seconds). */
export function sendCaseWriteRefusal(
  res: Response,
  decision: Exclude<CaseWriteDecision, { ok: true }>,
): void {
  if (decision.status === 429) {
    res.setHeader("Retry-After", String(Math.ceil(decision.retryAfterMs / 1000)));
  }
  res.status(decision.status).json(decision.body);
}
