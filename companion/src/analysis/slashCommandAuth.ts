import { createHmac, timingSafeEqual as cryptoTimingSafeEqual } from "node:crypto";
import { timingSafeEqual } from "./pushAuth.js";

// HMAC signature verification for inbound slash-command webhooks (#235). Slack signs each
// request with `v0:<timestamp>:<rawBody>` under the app's signing secret; the verifier
// recomputes the HMAC and compares it to the `X-Slack-Signature` header in constant time.
// Teams incoming webhooks (the webhook-based variant, not the Bot Framework) use a simpler
// shared-secret bearer token in the Authorization header.
//
// Pure + I/O-free so the verification decision is unit-tested in isolation. A 5-minute replay
// window guards against a captured request being replayed later (Slack's own recommendation).

export interface SlackSignatureInput {
  signingSecret: string;
  timestamp: string;        // the X-Slack-Request-Timestamp header
  rawBody: string;          // the raw request body (string)
  signature: string;        // the X-Slack-Signature header (starts with "v0=")
  now?: () => number;       // injectable clock (seconds since epoch) for tests
  maxAgeSeconds?: number;   // default 300 (5 min)
}

export interface SignatureVerifyResult {
  ok: boolean;
  error?: string;
}

export function verifySlackSignature(input: SlackSignatureInput): SignatureVerifyResult {
  const secret = String(input.signingSecret ?? "").trim();
  if (!secret) return { ok: false, error: "no Slack signing secret configured" };
  if (!input.signature || !input.timestamp) return { ok: false, error: "missing signature/timestamp headers" };

  const now = input.now ?? (() => Math.floor(Date.now() / 1000));
  const maxAge = input.maxAgeSeconds ?? 300;
  const ts = Number.parseInt(input.timestamp, 10);
  if (!Number.isFinite(ts)) return { ok: false, error: "invalid timestamp" };
  if (Math.abs(now() - ts) > maxAge) return { ok: false, error: "request timestamp outside the replay window" };

  const base = `v0:${input.timestamp}:${input.rawBody}`;
  const expected = "v0=" + createHmac("sha256", secret).update(base).digest("hex");
  if (!constantTimeEqual(input.signature, expected)) return { ok: false, error: "signature mismatch" };
  return { ok: true };
}

// Teams webhook-based slash commands carry a bearer token the operator configures in the Teams
// channel's webhook connector. Compare in constant time so a wrong token doesn't leak length/prefix.
// Accepts both "Bearer <token>" and a bare "<token>" presentation.
export function verifyTeamsToken(presented: string | undefined, expected: string | undefined): SignatureVerifyResult {
  const want = String(expected ?? "").trim();
  if (!want) return { ok: false, error: "no Teams token configured" };
  if (!presented) return { ok: false, error: "missing Authorization header" };
  const presentedToken = String(presented).replace(/^Bearer\s+/i, "").trim();
  if (!timingSafeEqual(presentedToken, want)) return { ok: false, error: "token mismatch" };
  return { ok: true };
}

// Constant-time buffer compare for the hex HMAC strings.
function constantTimeEqual(a: string, b: string): boolean {
  if (a.length !== b.length) return false;
  try {
    return cryptoTimingSafeEqual(Buffer.from(a), Buffer.from(b));
  } catch {
    return false;
  }
}