import type { AuditEvent, ElasticConfig } from "../../analysis/auditExport.js";
import type { AuditHttpRequest } from "./splunkHecFormat.js";

// Elasticsearch _bulk payload for the audit-log export (#929) — the second of the three wire
// formats, sharing nothing with Splunk HEC but the fact that it travels over HTTP.

/**
 * An action line and a source line per record, newline-terminated.
 *
 * `create` (not `index`) with the activity entry's own id is what makes a retry safe. The exporter
 * advances its position only after a send succeeds, so a batch whose response is lost WILL be sent
 * again; with `index` that silently doubles every row in the audit index, and with `create` the
 * cluster answers 409 for the records it already holds and stores the rest.
 */
export function formatElasticBulk(events: readonly AuditEvent[], cfg: ElasticConfig): AuditHttpRequest {
  const lines: string[] = [];
  for (const event of events) {
    lines.push(JSON.stringify({ create: { _index: cfg.index, _id: event.id } }));
    lines.push(JSON.stringify(event));
  }
  const headers: Record<string, string> = { "content-type": "application/x-ndjson" };
  // An API key wins over basic auth when both are stored: it is the narrower credential.
  if (cfg.apiKey) headers.Authorization = `ApiKey ${cfg.apiKey}`;
  else if (cfg.username && cfg.password) {
    headers.Authorization = `Basic ${Buffer.from(`${cfg.username}:${cfg.password}`).toString("base64")}`;
  }
  return {
    url: `${cfg.url.replace(/\/+$/, "")}/_bulk`,
    headers,
    // The trailing newline is required — a bulk body without it is rejected outright.
    body: lines.length ? `${lines.join("\n")}\n` : "",
  };
}
