import type { FetchFn } from "../../enrichment/provider.js";
import { readBoundedText, RESPONSE_SIZE_LIMITS } from "../../providers/boundedResponse.js";
import { OutboundUrlBlockedError } from "../../routes/outboundTargetPolicy.js";

// POST a JSON payload to a Slack/Teams incoming webhook. Injectable `fetchFn` (tests pass a mock —
// no real network), bounded by a timeout. Slack replies "ok" / Teams replies "1" on success; we
// treat any non-2xx as a failure and surface the body so the dashboard shows an actionable error.

export interface WebhookResult {
  ok: boolean;
  status: number;
  error?: string;
}

// Best-effort host for the bounded-read context (e.g. an error message reading "webhook
// (hooks.slack.com) response too large"). Never throws — an unparsable url falls back to a
// generic label rather than blowing up the already-in-progress error handling.
function safeHost(url: string): string {
  try {
    return `webhook (${new URL(url).host})`;
  } catch {
    return "webhook";
  }
}

export interface PostWebhookOptions {
  /** Do not follow a 3xx; report it as the failure (#2146). A 307/308 would re-POST the case
   *  detail to wherever the redirect points, which no check on the first URL covers. */
  refuseRedirects?: boolean;
}

export async function postWebhook(
  fetchFn: FetchFn,
  url: string,
  payload: unknown,
  timeoutMs = 15_000,
  opts: PostWebhookOptions = {},
): Promise<WebhookResult> {
  let res: Response;
  try {
    res = await fetchFn(url, {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify(payload),
      signal: AbortSignal.timeout(timeoutMs),
      ...(opts.refuseRedirects ? { redirect: "manual" as const } : {}),
    });
  } catch (err) {
    // A guard refusal is a policy decision, not a network fault — show it as written.
    if (err instanceof OutboundUrlBlockedError) return { ok: false, status: 0, error: err.message };
    return { ok: false, status: 0, error: `network error: ${(err as Error).message}` };
  }

  if (opts.refuseRedirects && res.status >= 300 && res.status < 400) {
    await res.body?.cancel().catch(() => {});
    return {
      ok: false,
      status: res.status,
      error: `the server answered with a redirect (HTTP ${res.status}), which is not followed`,
    };
  }

  if (!res.ok) {
    const body = await readBoundedText(res, {
      maxBytes: RESPONSE_SIZE_LIMITS.text,
      context: safeHost(url),
    }).catch(() => "");
    const detail = body ? `: ${body.slice(0, 200)}` : "";
    return { ok: false, status: res.status, error: `webhook HTTP ${res.status}${detail}` };
  }
  return { ok: true, status: res.status };
}
