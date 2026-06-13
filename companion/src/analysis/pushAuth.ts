// Auth for the generic push-ingest endpoint (#84 — POST /cases/:id/push). External tools (a SIEM
// webhook, a Velociraptor client-event poller, a custom script) POST alerts here, so — unlike the
// rest of the localhost-only API — it needs a shared secret: a GLOBAL token (DFIR_PUSH_TOKEN) and/or
// a PER-CASE token generated in Settings. Pure + I/O-free so the decision is unit-tested in isolation.
//
// OPSEC posture: push is OFF until a token is configured. With no token anywhere we DENY (403) rather
// than trust the caller — the endpoint may be reachable on 0.0.0.0 in container mode, where "localhost
// only" no longer holds. A configured-but-wrong/absent key is a 401.

export interface PushAuthInput {
  globalToken?: string;   // DFIR_PUSH_TOKEN (shared across cases)
  caseToken?: string;     // per-case generated token (state/push-token.json)
  presented?: string;     // the caller's X-DFIR-Key header
}

export interface PushAuthResult {
  ok: boolean;
  status: number;          // HTTP status to use when !ok (200 when ok)
  error?: string;          // actionable message when !ok
}

// Constant-time string compare — avoids leaking the token length/prefix through response timing. Both
// sides are compared at the length of the longer string so a length mismatch still costs a full pass.
export function timingSafeEqual(a: string, b: string): boolean {
  const x = String(a ?? "");
  const y = String(b ?? "");
  const len = Math.max(x.length, y.length);
  let diff = x.length ^ y.length;
  for (let i = 0; i < len; i++) {
    diff |= x.charCodeAt(i) ^ y.charCodeAt(i); // NaN when past the end → still mixes a nonzero bit
  }
  return diff === 0;
}

// Decide whether a push request is authorized. Trim everything (a trailing newline in a token file or
// a copy-pasted env var is a common foot-gun). An empty presented key against a configured token is a
// 401, never a silent allow.
export function resolvePushAuth(input: PushAuthInput): PushAuthResult {
  const globalToken = String(input.globalToken ?? "").trim();
  const caseToken = String(input.caseToken ?? "").trim();
  const presented = String(input.presented ?? "").trim();

  if (!globalToken && !caseToken) {
    return {
      ok: false,
      status: 403,
      error: "push ingest is disabled — set DFIR_PUSH_TOKEN or generate a per-case push token in Settings → Integrations",
    };
  }
  if (!presented) {
    return { ok: false, status: 401, error: "missing X-DFIR-Key header" };
  }
  const matches =
    (!!globalToken && timingSafeEqual(presented, globalToken)) ||
    (!!caseToken && timingSafeEqual(presented, caseToken));
  if (!matches) {
    return { ok: false, status: 401, error: "invalid X-DFIR-Key" };
  }
  return { ok: true, status: 200 };
}
