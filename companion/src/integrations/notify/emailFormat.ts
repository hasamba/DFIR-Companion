import { createHash } from "node:crypto";
import type { NotificationEvent } from "../../analysis/notifications.js";

// Pure: a NotificationEvent → email content (subject + text + html), and a dependency-free RFC 5322
// MIME message builder (multipart/alternative, base64 bodies, UTF-8). Mirrors the project's
// hand-rolled email IMPORT (`parseMimeEmail`) — we hand-roll the SEND side too, no `nodemailer`.
// The SMTP client (smtpClient.ts) transmits the string this produces. No I/O — unit-tested.

export interface EmailContent {
  subject: string;
  text: string;
  html: string;
}

export function formatEmail(event: NotificationEvent): EmailContent {
  const subject = `[DFIR ${event.severity}] ${event.title}`;
  const text = [event.title, "", ...event.lines.filter(Boolean), "", `— DFIR Companion · ${event.at}`]
    .concat(event.url ? ["", event.url] : [])
    .join("\n");

  const bullets = event.lines.filter(Boolean).map((l) => `<li>${esc(l)}</li>`).join("");
  const link = event.url ? `<p><a href="${esc(event.url)}">Open case</a></p>` : "";
  const html =
    `<div style="font-family:system-ui,Segoe UI,Arial,sans-serif">` +
    `<h2 style="margin:0 0 8px">${esc(event.title)}</h2>` +
    `<p style="margin:0 0 6px"><strong>Severity:</strong> ${esc(event.severity)}</p>` +
    (bullets ? `<ul style="margin:6px 0">${bullets}</ul>` : "") +
    link +
    `<p style="color:#888;font-size:12px;margin-top:12px">DFIR Companion · ${esc(event.kind.replace(/_/g, " "))} · ${esc(event.at)}</p>` +
    `</div>`;

  return { subject, text, html };
}

export interface Rfc822Options {
  from: string;
  to: string[];
  subject: string;
  text: string;
  html: string;
  date: string;            // ISO timestamp
  messageId?: string;      // defaults to a deterministic id derived from the headers
  boundary?: string;       // defaults to a deterministic boundary (so tests are stable)
}

// Build a complete RFC 5322 message (headers + multipart/alternative body) ready for SMTP DATA.
// Line endings are CRLF. Bodies are base64-encoded (no line starts with "." → SMTP-safe), wrapped
// at 76 cols. Deterministic: same inputs → same bytes (boundary/message-id derive from a hash).
export function buildRfc822Message(opts: Rfc822Options): string {
  const fingerprint = createHash("sha256")
    .update(`${opts.from}|${opts.to.join(",")}|${opts.subject}|${opts.date}`)
    .digest("hex");
  const boundary = opts.boundary ?? `=_dfir_${fingerprint.slice(0, 24)}`;
  const messageId = opts.messageId ?? `<${fingerprint.slice(0, 32)}@dfir-companion>`;

  const headers = [
    `From: ${opts.from}`,
    `To: ${opts.to.join(", ")}`,
    `Subject: ${encodeHeaderWord(opts.subject)}`,
    `Date: ${formatRfc2822Date(opts.date)}`,
    `Message-ID: ${messageId}`,
    "MIME-Version: 1.0",
    `Content-Type: multipart/alternative; boundary="${boundary}"`,
  ];

  const parts = [
    `--${boundary}`,
    "Content-Type: text/plain; charset=utf-8",
    "Content-Transfer-Encoding: base64",
    "",
    b64wrap(opts.text),
    `--${boundary}`,
    "Content-Type: text/html; charset=utf-8",
    "Content-Transfer-Encoding: base64",
    "",
    b64wrap(opts.html),
    `--${boundary}--`,
    "",
  ];

  return [...headers, "", ...parts].join("\r\n");
}

// RFC 2047 encoded-word for a non-ASCII subject; raw when it's plain ASCII.
function encodeHeaderWord(s: string): string {
  // eslint-disable-next-line no-control-regex
  if (/^[\x20-\x7e]*$/.test(s)) return s;
  return `=?UTF-8?B?${Buffer.from(s, "utf8").toString("base64")}?=`;
}

function b64wrap(s: string): string {
  const b64 = Buffer.from(s, "utf8").toString("base64");
  return (b64.match(/.{1,76}/g) ?? [b64]).join("\r\n");
}

const DAYS = ["Sun", "Mon", "Tue", "Wed", "Thu", "Fri", "Sat"];
const MONTHS = ["Jan", "Feb", "Mar", "Apr", "May", "Jun", "Jul", "Aug", "Sep", "Oct", "Nov", "Dec"];

// RFC 2822 date in UTC, e.g. "Fri, 12 Jun 2026 10:00:00 +0000". Falls back to the supplied string
// when it isn't a parseable date.
function formatRfc2822Date(iso: string): string {
  const d = new Date(iso);
  if (Number.isNaN(d.getTime())) return iso;
  const p = (n: number): string => String(n).padStart(2, "0");
  return (
    `${DAYS[d.getUTCDay()]}, ${p(d.getUTCDate())} ${MONTHS[d.getUTCMonth()]} ${d.getUTCFullYear()} ` +
    `${p(d.getUTCHours())}:${p(d.getUTCMinutes())}:${p(d.getUTCSeconds())} +0000`
  );
}

function esc(s: string): string {
  return String(s)
    .replace(/&/g, "&amp;")
    .replace(/</g, "&lt;")
    .replace(/>/g, "&gt;")
    .replace(/"/g, "&quot;");
}
