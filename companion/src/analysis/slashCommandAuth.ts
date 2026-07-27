import { createHmac } from "node:crypto";
import { timingSafeEqual } from "./pushAuth.js";

// Inbound authentication for the war-room slash-command bot (#235), plus the outbound allowlist
// for where a result may be delivered. Pure + I/O-free so every decision is unit-tested in
// isolation.
//
//   Slack    — signs each request with `v0:<timestamp>:<rawBody>` under the app's signing secret.
//              We recompute the HMAC and compare it to `X-Slack-Signature` in constant time. A
//              5-minute replay window (Slack's own recommendation) bounds a captured request.
//   Teams    — webhook-based slash commands (not the Bot Framework) carry a shared-secret bearer
//              token in the Authorization header.
//   Telegram — setWebhook takes a `secret_token`, which Telegram then sends back on every update
//              in `X-Telegram-Bot-Api-Secret-Token`. Same shared-secret shape as Teams.
//
// All three compares go through pushAuth's timingSafeEqual, which is length-safe (it always costs
// a full pass) — so a wrong secret leaks neither its length nor its prefix through response timing.

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
  if (!timingSafeEqual(input.signature, expected)) return { ok: false, error: "signature mismatch" };
  return { ok: true };
}

// Teams webhook-based slash commands carry a bearer token the operator configures in the Teams
// channel's webhook connector. Accepts both "Bearer <token>" and a bare "<token>" presentation.
export function verifyTeamsToken(presented: string | undefined, expected: string | undefined): SignatureVerifyResult {
  const want = String(expected ?? "").trim();
  if (!want) return { ok: false, error: "no Teams token configured" };
  if (!presented) return { ok: false, error: "missing Authorization header" };
  const presentedToken = String(presented).replace(/^Bearer\s+/i, "").trim();
  if (!timingSafeEqual(presentedToken, want)) return { ok: false, error: "token mismatch" };
  return { ok: true };
}

// Telegram echoes back the `secret_token` given to setWebhook in the
// X-Telegram-Bot-Api-Secret-Token header. Without it, anyone who learns the webhook URL can post
// updates — so an unconfigured secret refuses the request rather than running open.
export function verifyTelegramSecret(presented: string | undefined, expected: string | undefined): SignatureVerifyResult {
  const want = String(expected ?? "").trim();
  if (!want) return { ok: false, error: "no Telegram webhook secret configured" };
  if (!presented) return { ok: false, error: "missing X-Telegram-Bot-Api-Secret-Token header" };
  if (!timingSafeEqual(String(presented).trim(), want)) return { ok: false, error: "secret token mismatch" };
  return { ok: true };
}

// ── Outbound delivery allowlist ─────────────────────────────────────────────────────────
// Slack and Teams tell us where to deliver an async result via a `response_url` in the request
// body. That is a server-side fetch to a caller-supplied URL, so it is pinned to the hosts those
// platforms actually deliver on. Self-hosted Slack-compatible servers (the Mattermost setup
// DFIR_NOTIFY_CA already exists for) name themselves via DFIR_SLACK_RESPONSE_HOSTS /
// DFIR_TEAMS_RESPONSE_HOSTS. A leading "." means "this host and any subdomain of it".

export const DEFAULT_RESPONSE_HOSTS: Record<"slack" | "teams", readonly string[]> = {
  slack: ["hooks.slack.com"],
  // Classic connectors, Power Automate workflow URLs, and the Graph-hosted variant.
  teams: [".webhook.office.com", ".logic.azure.com", ".office.com"],
};

/** Does `url` point somewhere we are willing to POST a case result to? https only. */
export function isAllowedResponseUrl(
  platform: "slack" | "teams",
  url: string,
  extraHosts: readonly string[] = [],
): boolean {
  let parsed: URL;
  try {
    parsed = new URL(url);
  } catch {
    return false;
  }
  if (parsed.protocol !== "https:") return false;
  const host = parsed.hostname.toLowerCase();
  return [...DEFAULT_RESPONSE_HOSTS[platform], ...extraHosts]
    .map((h) => h.trim().toLowerCase())
    .filter(Boolean)
    .some((allowed) => (allowed.startsWith(".") ? host === allowed.slice(1) || host.endsWith(allowed) : host === allowed));
}

/** Parse a comma-separated env var into a trimmed, non-empty list. */
export function parseHostList(value: string | undefined): string[] {
  return (value ?? "").split(",").map((s) => s.trim()).filter(Boolean);
}
