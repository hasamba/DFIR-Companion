import type { AuditEvent, SyslogConfig } from "../../analysis/auditExport.js";

// RFC 5424 syslog lines for the audit-log export (#929) — the third wire format, and the one #929
// got most wrong. Its step 3 said the exporter "POSTs them to the configured endpoint" for all
// three targets, but syslog is a message format carried over a socket to a host and port; there is
// no HTTP request here at all. See syslogTransport.ts for the send half.

/**
 * Facility 13 is `log audit` in RFC 5424's table — the facility that exists for records of this
 * kind. Severity 6 is informational and 4 is warning, so a failed action outranks a successful one
 * and a SIEM rule can select failures from the priority alone, without parsing the message.
 */
const FACILITY_LOG_AUDIT = 13;
const SEVERITY_INFO = 6;
const SEVERITY_WARNING = 4;

const DEFAULT_APP_NAME = "dfir-companion";
const NIL = "-";

/**
 * RFC 5424 §6.1 requires a receiver to accept at least 2048 octets and permits it to discard the
 * rest. A record longer than that would be cut wherever the limit fell — mid-field, mid-escape — so
 * the line is trimmed here, at a field boundary, with an ellipsis that says it happened. Silent
 * truncation of an audit record is worse than a visibly shortened one.
 */
const MAX_LINE = 2048;

/**
 * A CR or LF is a syslog record separator. Left in the message, one activity entry whose detail
 * contains a newline arrives as TWO records, and the second one is entirely caller-chosen text — a
 * forged audit line assembled out of evidence text. The other C0 controls and the Unicode line
 * separators go the same way, because a receiver or a downstream parser may treat them as breaks
 * too. They collapse to a space rather than vanishing, so the text stays readable.
 */
const CONTROL_CHARS = /[\u0000-\u001f\u007f\u0085\u2028\u2029]+/g;

function stripControls(value: string): string {
  return String(value).replace(CONTROL_CHARS, " ");
}

/**
 * Escape a structured-data param value per RFC 5424 §6.3.3: `"`, `\` and `]` must be backslashed.
 *
 * This is not cosmetic. Evidence text reaches `detail` and `targetId`, so an unescaped `]` closes
 * the structured-data element early and everything after it is read as new fields.
 */
function escapeSdValue(value: string): string {
  return stripControls(value).replace(/([\\\]"])/g, "\\$1");
}

function structuredData(event: AuditEvent): string {
  const params: Array<[string, string]> = [
    ["entryId", event.id],
    ["caseId", event.caseId],
    ["category", event.category],
    ["action", event.action],
    ["actor", event.actor],
    ["actorVerified", String(event.actorVerified)],
    ["outcome", event.outcome],
  ];
  if (event.actorId) params.push(["actorId", event.actorId]);
  if (event.actorKind) params.push(["actorKind", event.actorKind]);
  if (event.targetType) params.push(["targetType", event.targetType]);
  if (event.targetId) params.push(["targetId", event.targetId]);
  // "dfir@0" is a private enterprise SD-ID. RFC 5424 reserves the `@0` form for a sender with no
  // registered IANA enterprise number, which is the honest label here.
  return `[dfir@0 ${params.map(([k, v]) => `${k}="${escapeSdValue(v)}"`).join(" ")}]`;
}

/**
 * One RFC 5424 line per record. `hostname` is the machine this companion runs on, passed in so this
 * module stays free of I/O and testable without a real host.
 */
export function formatSyslog(events: readonly AuditEvent[], cfg: SyslogConfig, hostname: string): string[] {
  // APP-NAME is a single PRINTUSASCII token — a space in it would shift every later field.
  const appName =
    stripControls(cfg.appName ?? "")
      .trim()
      .replace(/\s+/g, "-") || DEFAULT_APP_NAME;
  const host = stripControls(hostname).trim().replace(/\s+/g, "-") || NIL;
  return events.map((event) => {
    const severity = event.outcome === "error" ? SEVERITY_WARNING : SEVERITY_INFO;
    const pri = FACILITY_LOG_AUDIT * 8 + severity;
    const header = `<${pri}>1 ${event.timestamp} ${host} ${appName} ${NIL} ${event.category}`;
    const prefix = `${header} ${structuredData(event)} `;
    const detail = stripControls(event.detail);
    if (prefix.length + detail.length <= MAX_LINE) return `${prefix}${detail}`;
    // Trim the free-text message only — never the structured fields a SIEM rule matches on.
    const room = MAX_LINE - prefix.length;
    return `${prefix}${room > 1 ? `${detail.slice(0, room - 1)}…` : "…"}`;
  });
}
