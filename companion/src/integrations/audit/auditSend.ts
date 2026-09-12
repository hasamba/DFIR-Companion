import type { FetchFn } from "../../enrichment/provider.js";
import { readBoundedText, RESPONSE_SIZE_LIMITS } from "../../providers/boundedResponse.js";
import type { AuditDestination, AuditEvent, SyslogConfig } from "../../analysis/auditExport.js";
import { formatSplunkHec, type AuditHttpRequest } from "./splunkHecFormat.js";
import { formatElasticBulk } from "./elasticBulkFormat.js";
import { formatSyslog } from "./syslogFormat.js";

// Send one batch to one destination (#929). Chooses the wire format AND the transport by type,
// which is the part #929's single "POST the batch" step could not do.
//
// Never throws: the caller advances a durable position only when `ok` is true, so a thrown error
// here would be indistinguishable from a send whose outcome we do not know. Every failure comes
// back as data.

export type SyslogSendFn = (lines: readonly string[], cfg: SyslogConfig) => Promise<void>;

export interface AuditTransport {
  fetchFn: FetchFn;
  syslogSend: SyslogSendFn;
  hostname: string;
  timeoutMs?: number;
}

export interface AuditSendResult {
  ok: boolean;
  sent: number;
  error?: string;
}

const DEFAULT_TIMEOUT_MS = 20_000;

/**
 * An error string that can be shown in the dashboard and written to the server log. The credential
 * is never in it: the request we built carries an Authorization header, and a naive
 * "failed to POST <request>" would put an HEC token into a log file and a browser response.
 */
function httpError(status: number, body: string): string {
  const detail = body.trim() ? `: ${body.trim().slice(0, 300)}` : "";
  return `HTTP ${status}${detail}`;
}

async function postJson(
  request: AuditHttpRequest,
  transport: AuditTransport,
): Promise<{ ok: boolean; status: number; body: string }> {
  const res = await transport.fetchFn(request.url, {
    method: "POST",
    headers: request.headers,
    body: request.body,
    signal: AbortSignal.timeout(transport.timeoutMs ?? DEFAULT_TIMEOUT_MS),
  });
  const body = await readBoundedText(res, {
    maxBytes: RESPONSE_SIZE_LIMITS.text,
    context: "audit export",
  }).catch(() => "");
  return { ok: res.ok, status: res.status, body };
}

/**
 * Read an Elasticsearch bulk response and decide whether it PROVES delivery.
 *
 * The bar is proof, not the absence of a complaint. Elasticsearch reports per-document acceptance
 * in the body, so a 2xx whose body cannot be read as a bulk response says nothing about what was
 * stored — and a reverse proxy answering `200` with an HTML error page is the ordinary shape of
 * that. Reading such a body as "no item errors" let the caller advance its durable position and
 * skip those records for good, which is the one failure an audit feed must not have. An
 * unreadable, item-less, or short response is therefore a failed send: the batch is re-sent, and
 * `create` with the entry id means a re-send cannot duplicate what did land.
 *
 * A 409 on a `create` is the exception that stays a success. It means the cluster already holds
 * that record — exactly what a retry of a batch whose response was lost looks like — and treating
 * the conflict as an error would stall the feed on the same batch forever.
 */
function elasticDeliveryError(body: string, expected: number): string | undefined {
  let parsed: unknown;
  try {
    parsed = JSON.parse(body);
  } catch {
    return "bulk response was not readable JSON — delivery unconfirmed";
  }
  const doc = parsed as {
    errors?: boolean;
    items?: Array<Record<string, { status?: number; error?: { type?: string; reason?: string } }>>;
  };
  if (!Array.isArray(doc?.items)) {
    return "bulk response carried no items array — delivery unconfirmed";
  }
  if (doc.items.length !== expected) {
    return `bulk response acknowledged ${doc.items.length} of ${expected} record(s) — delivery unconfirmed`;
  }
  for (const item of doc.items) {
    for (const outcome of Object.values(item)) {
      const status = outcome?.status ?? 0;
      if (status === 409) continue; // already stored — see above
      if (outcome?.error) {
        const { type, reason } = outcome.error;
        return `${type ?? "item error"}${reason ? `: ${reason}` : ""}`;
      }
      // A create that neither errored nor returned a 2xx/409 status is not an acknowledgement.
      if (status < 200 || status >= 300) {
        return `bulk item returned status ${status} — delivery unconfirmed`;
      }
    }
  }
  return undefined;
}

export async function sendAuditBatch(
  destination: AuditDestination,
  events: readonly AuditEvent[],
  transport: AuditTransport,
): Promise<AuditSendResult> {
  if (events.length === 0) return { ok: true, sent: 0 };

  try {
    if (destination.type === "splunk") {
      if (!destination.splunk) return { ok: false, sent: 0, error: "splunk destination not configured" };
      const { ok, status, body } = await postJson(formatSplunkHec(events, destination.splunk), transport);
      if (!ok) return { ok: false, sent: 0, error: httpError(status, body) };
      return { ok: true, sent: events.length };
    }

    if (destination.type === "elastic") {
      if (!destination.elastic) return { ok: false, sent: 0, error: "elastic destination not configured" };
      const { ok, status, body } = await postJson(formatElasticBulk(events, destination.elastic), transport);
      if (!ok) return { ok: false, sent: 0, error: httpError(status, body) };
      const deliveryError = elasticDeliveryError(body, events.length);
      if (deliveryError) return { ok: false, sent: 0, error: deliveryError };
      return { ok: true, sent: events.length };
    }

    if (!destination.syslog) return { ok: false, sent: 0, error: "syslog destination not configured" };
    const lines = formatSyslog(events, destination.syslog, transport.hostname);
    await transport.syslogSend(lines, destination.syslog);
    return { ok: true, sent: events.length };
  } catch (err) {
    return { ok: false, sent: 0, error: (err as Error).message };
  }
}
