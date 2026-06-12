import type { FetchFn } from "../../enrichment/provider.js";

// POST a JSON payload to a Slack/Teams incoming webhook. Injectable `fetchFn` (tests pass a mock —
// no real network), bounded by a timeout. Slack replies "ok" / Teams replies "1" on success; we
// treat any non-2xx as a failure and surface the body so the dashboard shows an actionable error.

export interface WebhookResult {
  ok: boolean;
  status: number;
  error?: string;
}

export async function postWebhook(
  fetchFn: FetchFn,
  url: string,
  payload: unknown,
  timeoutMs = 15_000,
): Promise<WebhookResult> {
  let res: Response;
  try {
    res = await fetchFn(url, {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify(payload),
      signal: AbortSignal.timeout(timeoutMs),
    });
  } catch (err) {
    return { ok: false, status: 0, error: `network error: ${(err as Error).message}` };
  }

  if (!res.ok) {
    const body = await res.text().catch(() => "");
    const detail = body ? `: ${body.slice(0, 200)}` : "";
    return { ok: false, status: res.status, error: `webhook HTTP ${res.status}${detail}` };
  }
  return { ok: true, status: res.status };
}
