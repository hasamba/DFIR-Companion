// Import debug recording for the email importer (#1736): which header fed each event field and
// which path read the message. Header NAMES and code-authored slugs only, never a header value.

import type { ImportDebugRecorder } from "./importDebug.js";

interface ParsedForDebug {
  format: string;
  date: string;
  subject: string;
  from?: unknown;
  originatingIp: string;
  attachmentsNotRead: number;
  headers: Map<string, string[]>;
}

export function recordEmailParse(debug: ImportDebugRecorder | undefined, p: ParsedForDebug): void {
  if (!debug) return;
  debug.counts({ total: 1, kept: 1, dropped: 0 });
  if (p.format === "msg") debug.fallback("msg_transport_headers");
  if (p.date) debug.field("timestamp", "Date");
  else debug.observed("empty_timestamp");
  if (p.from) debug.field("user", "From");
  if (p.subject) debug.field("message", "Subject");
  if (p.originatingIp) {
    const xorig = (p.headers.get("x-originating-ip") ?? []).some((v) => v.includes(p.originatingIp));
    debug.field("source_ip", xorig ? "X-Originating-IP" : "Received");
  }
  if (p.attachmentsNotRead) debug.observed("attachment_not_read", p.attachmentsNotRead);
}

export function recordEmailUnrecoverable(debug: ImportDebugRecorder | undefined): void {
  debug?.skipped("not_recoverable_email");
  debug?.counts({ total: 0, kept: 0, dropped: 0 });
}
