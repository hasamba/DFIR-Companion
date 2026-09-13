import type { AuditEvent, SplunkConfig } from "../../analysis/auditExport.js";

// Splunk HTTP Event Collector payload for the audit-log export (#929).
//
// #929 proposed one exporter that "POSTs them to the configured endpoint" for all three targets.
// That does not work: HEC has its own envelope and its own authorization scheme, and neither is
// shared with Elasticsearch or syslog. This module is the Splunk half of that split.

export interface AuditHttpRequest {
  url: string;
  headers: Record<string, string>;
  body: string;
}

/** HEC's single-event endpoint. Batching is expressed as concatenated envelopes, not as an array. */
const HEC_EVENT_PATH = "/services/collector/event";

/**
 * One HEC envelope per record, newline-separated.
 *
 * `time` is epoch SECONDS, which is what HEC parses. Passing the ISO string instead is accepted by
 * the endpoint and silently indexed at receipt time, so every forwarded action would appear to have
 * happened when the batch was sent rather than when the analyst did it — the one property an audit
 * feed cannot get wrong.
 */
export function formatSplunkHec(events: readonly AuditEvent[], cfg: SplunkConfig): AuditHttpRequest {
  const body = events
    .map((event) =>
      JSON.stringify({
        time: Date.parse(event.timestamp) / 1000,
        ...(cfg.index ? { index: cfg.index } : {}),
        ...(cfg.sourcetype ? { sourcetype: cfg.sourcetype } : {}),
        event,
      }),
    )
    .join("\n");
  return {
    url: `${cfg.url.replace(/\/+$/, "")}${HEC_EVENT_PATH}`,
    headers: {
      Authorization: `Splunk ${cfg.token}`,
      "content-type": "application/json",
    },
    body,
  };
}
