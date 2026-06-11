// Deterministic importer for email artifacts — `.eml` (RFC 2822 / MIME) and best-effort `.msg`
// (Outlook OLE compound files). The sixteenth deterministic ingest path; no AI call.
//
// Phishing and BEC are the #1 initial-access vector (ATT&CK T1566), but the rest of the tool had
// no way to pull an email onto the timeline. This module parses ONE email into ONE forensic event
// dated at the message's own `Date:` header, with the sender / reply-to / originating IP /
// authentication results in the description, and harvests every link + domain + originating IP +
// attachment name/hash as IOCs. Like the KAPE / Chainsaw importers it is fully deterministic —
// the email's headers ARE the verdict; we read them, we don't ask a model to.
//
// Severity is DERIVED from the email's own signals (no maliciousness call):
//   • SPF / DKIM / DMARC authentication FAILURE        → High  (spoofed / forged sender)
//   • suspicious sender (From vs different-org Reply-To, → Medium
//     or a display-name that spoofs another domain)
//   • clean / nothing notable                          → Info  (evidence row; synthesis + the
//                                                         high-severity backfill still escalate it
//                                                         if it lines up with a real detection)
//
// `.eml` is plain text and parses fully. `.msg` is an OLE/CFB BINARY container; the import pipeline
// is text-only (the dashboard reads files with `File.text()`), so `.msg` support is BEST-EFFORT:
// we recover the embedded RFC 822 transport-headers stream (which carries From/To/Subject/Date/
// auth/Received — exactly what we need) and scan the decoded bytes for URLs. For full fidelity,
// export the message as `.eml`.

import type { Severity } from "./stateTypes.js";
import { addIoc, cleanIp, type SiemEvent, type SiemIoc } from "./siemImport.js";

export interface EmailImportOptions {
  minSeverity?: Severity;
  maxEvents?: number;
  maxIocs?: number;
}

export interface EmailAddress {
  name: string;
  address: string;
  domain: string;
}

export interface EmailAttachment {
  filename: string;
  contentType: string;
  sha256?: string;
  md5?: string;
}

export interface EmailAuth {
  spf?: string;
  dkim?: string;
  dmarc?: string;
}

export interface ParsedEmail {
  format: "eml" | "msg";
  date: string;            // normalized to UTC ISO ("" if unparseable / absent)
  rawDate: string;         // the original Date: header
  subject: string;
  messageId: string;
  from?: EmailAddress;
  replyTo?: EmailAddress;
  returnPath?: EmailAddress;
  to: EmailAddress[];
  originatingIp: string;   // X-Originating-IP / earliest external Received hop
  auth: EmailAuth;
  urls: string[];
  attachments: EmailAttachment[];
  hashes: string[];        // MD5 / SHA-1 / SHA-256 seen in headers or body
  headers: Map<string, string[]>;
}

export interface EmailParseResult {
  events: SiemEvent[];
  iocs: SiemIoc[];
  total: number;   // messages parsed (1 for a single .eml/.msg, 0 if nothing recoverable)
  kept: number;    // events emitted
  dropped: number; // messages not represented
  groups: number;  // = kept (parity with the other importers)
  format: string;  // "eml" | "msg" | "empty"
  subject: string; // best-effort, for the import banner
  sender: string;
}

const IPV4_G = /\b\d{1,3}(?:\.\d{1,3}){3}\b/g;
const HEX_HASH = /\b(?:[a-f0-9]{32}|[a-f0-9]{40}|[a-f0-9]{64})\b/gi;
// http(s) and the common defanged form hxxp(s); stop at whitespace/quotes/closing brackets.
const URL_RE = /\b(?:h[x]{2}ps?|https?):\/\/[^\s"'<>)\]}]+/gi;

// ───────────────────────────── byte / charset decoding (dependency-free) ─────────────────────────────

function decodeBuffer(buf: Buffer, charset: string): string {
  const cs = charset.toLowerCase();
  if (/utf-?8/.test(cs)) return buf.toString("utf8");
  if (/ucs-?2|utf-?16/.test(cs)) return buf.toString("ucs2");
  return buf.toString("latin1"); // iso-8859-1 / windows-1252 / us-ascii approximation
}

// Decode an RFC 2047 Q-encoded chunk ("=XX" bytes, "_" → space) to raw bytes.
function qWordToBytes(s: string): Buffer {
  const out: number[] = [];
  for (let i = 0; i < s.length; i++) {
    const c = s[i];
    if (c === "_") out.push(0x20);
    else if (c === "=" && /^[0-9a-f]{2}$/i.test(s.slice(i + 1, i + 3))) {
      out.push(parseInt(s.slice(i + 1, i + 3), 16));
      i += 2;
    } else out.push(s.charCodeAt(i) & 0xff);
  }
  return Buffer.from(out);
}

// Decode RFC 2047 encoded-words ("=?utf-8?B?...?=" / "=?utf-8?Q?...?=") in a header value.
function decodeEncodedWords(s: string): string {
  if (!s.includes("=?")) return s;
  // Whitespace BETWEEN two adjacent encoded-words is not significant — collapse it first.
  const joined = s.replace(/\?=\s+=\?/g, "?==?");
  return joined.replace(/=\?([^?]+)\?([BQ])\?([^?]*)\?=/gi, (_m, charset, enc, data) => {
    try {
      const buf = /^B$/i.test(enc) ? Buffer.from(data, "base64") : qWordToBytes(data);
      return decodeBuffer(buf, String(charset));
    } catch {
      return _m;
    }
  });
}

// Decode a quoted-printable BODY part (soft line breaks removed, "=XX" → byte). Not header Q —
// no "_" → space here.
function qpBodyDecode(s: string): string {
  const noSoft = s.replace(/=\r?\n/g, "");
  const out: number[] = [];
  for (let i = 0; i < noSoft.length; i++) {
    if (noSoft[i] === "=" && /^[0-9a-f]{2}$/i.test(noSoft.slice(i + 1, i + 3))) {
      out.push(parseInt(noSoft.slice(i + 1, i + 3), 16));
      i += 2;
    } else out.push(noSoft.charCodeAt(i) & 0xff);
  }
  return Buffer.from(out).toString("utf8");
}

function decodeBody(body: string, encoding: string): string {
  const enc = encoding.trim().toLowerCase();
  if (enc === "base64") {
    try {
      return Buffer.from(body.replace(/\s+/g, ""), "base64").toString("utf8");
    } catch {
      return body;
    }
  }
  if (enc === "quoted-printable") return qpBodyDecode(body);
  return body; // 7bit / 8bit / binary / none
}

// ───────────────────────────── header parsing ─────────────────────────────

function splitHeadersBody(raw: string): { headerText: string; body: string } {
  const norm = raw.replace(/\r\n/g, "\n");
  const idx = norm.indexOf("\n\n");
  if (idx === -1) return { headerText: norm, body: "" };
  return { headerText: norm.slice(0, idx), body: norm.slice(idx + 2) };
}

// Parse a header block into a name(lowercased) → values[] map, unfolding continuation lines.
function parseHeaders(headerText: string): Map<string, string[]> {
  const map = new Map<string, string[]>();
  const folded: string[] = [];
  for (const line of headerText.split("\n")) {
    if (/^[ \t]/.test(line) && folded.length) folded[folded.length - 1] += " " + line.trim();
    else folded.push(line);
  }
  for (const entry of folded) {
    const ci = entry.indexOf(":");
    if (ci <= 0) continue;
    const name = entry.slice(0, ci).trim().toLowerCase();
    if (!/^[\x21-\x39\x3b-\x7e]+$/.test(name)) continue; // a real header name (printable, no spaces)
    const value = entry.slice(ci + 1).trim();
    const arr = map.get(name) ?? [];
    arr.push(value);
    map.set(name, arr);
  }
  return map;
}

function firstHeader(headers: Map<string, string[]>, name: string): string {
  return headers.get(name.toLowerCase())?.[0] ?? "";
}

// Pull a `name="value"` (or `name=value`) parameter out of a structured header (Content-Type, …).
function headerParam(value: string, param: string): string {
  const re = new RegExp(`${param}\\s*=\\s*("([^"]*)"|[^;\\s]+)`, "i");
  const m = re.exec(value);
  if (!m) return "";
  return (m[2] ?? m[1] ?? "").trim();
}

// ───────────────────────────── addresses ─────────────────────────────

const ADDR_RE = /([A-Za-z0-9._%+\-]+@[A-Za-z0-9.\-]+\.[A-Za-z]{2,})/;

function parseAddress(raw: string): EmailAddress | undefined {
  const s = decodeEncodedWords(raw).trim();
  if (!s) return undefined;
  const angle = /<([^>]+)>/.exec(s);
  const addrPart = (angle ? angle[1] : s).trim();
  const m = ADDR_RE.exec(addrPart) ?? ADDR_RE.exec(s);
  const address = m ? m[1].toLowerCase() : "";
  if (!address) return undefined;
  let name = angle ? s.slice(0, angle.index).trim() : "";
  name = name.replace(/^"(.*)"$/, "$1").trim();
  const domain = address.split("@").pop() ?? "";
  return { name, address, domain };
}

function parseAddressList(raw: string): EmailAddress[] {
  if (!raw.trim()) return [];
  // Split on commas that are NOT inside an angle-addr (rough but adequate for header lists).
  return decodeEncodedWords(raw)
    .split(/,(?![^<]*>)/)
    .map((p) => parseAddress(p))
    .filter((a): a is EmailAddress => !!a);
}

// ───────────────────────────── authentication results ─────────────────────────────

function parseAuth(headers: Map<string, string[]>): EmailAuth {
  const ar = (headers.get("authentication-results") ?? []).join(" ; ").toLowerCase();
  const recvSpf = (headers.get("received-spf") ?? []).join(" ").toLowerCase();
  const pick = (re: RegExp, hay: string): string | undefined => {
    const m = re.exec(hay);
    return m ? m[1] : undefined;
  };
  const spf = pick(/\bspf=(\w+)/, ar) ?? pick(/\b(pass|fail|softfail|neutral|none|permerror|temperror)\b/, recvSpf);
  const dkim = pick(/\bdkim=(\w+)/, ar);
  const dmarc = pick(/\bdmarc=(\w+)/, ar);
  return {
    ...(spf ? { spf } : {}),
    ...(dkim ? { dkim } : {}),
    ...(dmarc ? { dmarc } : {}),
  };
}

const AUTH_FAIL = new Set(["fail", "softfail", "hardfail", "permerror"]);
function isAuthFail(v?: string): boolean {
  return !!v && AUTH_FAIL.has(v);
}

// ───────────────────────────── sender heuristics ─────────────────────────────

// Registrable-ish domain: last two labels (good enough — we are comparing, not validating; this
// is deliberately not an eTLD list, so "co.uk" pairs compare by their last two labels too).
function registrable(domain: string): string {
  const parts = domain.toLowerCase().split(".").filter(Boolean);
  return parts.slice(-2).join(".");
}

function suspiciousSender(p: ParsedEmail): boolean {
  const fromDom = p.from?.domain ?? "";
  // From-domain vs Reply-To-domain across different orgs is a classic BEC reply-redirect.
  if (fromDom && p.replyTo?.domain && registrable(fromDom) !== registrable(p.replyTo.domain)) return true;
  // Return-Path (envelope sender) across a different org from the header From is spoof-shaped.
  if (fromDom && p.returnPath?.domain && registrable(fromDom) !== registrable(p.returnPath.domain)) return true;
  // A display name that itself contains an email/domain different from the actual sending domain
  // (e.g. From: "support@paypal.com <attacker@evil.ru>").
  const dnAddr = p.from?.name ? ADDR_RE.exec(p.from.name)?.[1] : undefined;
  if (dnAddr && fromDom) {
    const dnDom = dnAddr.split("@").pop() ?? "";
    if (registrable(dnDom) !== registrable(fromDom)) return true;
  }
  return false;
}

// ───────────────────────────── MIME body walk (URLs + attachments) ─────────────────────────────

interface BodyScan {
  text: string[];          // decoded text/html bodies, for URL + hash scanning
  attachments: EmailAttachment[];
}

// Recursively walk a (possibly multipart) MIME entity, collecting decoded text bodies and
// attachment descriptors. `headers`/`body` are this entity's own headers + raw body.
function walkMime(headers: Map<string, string[]>, body: string, sink: BodyScan, depth: number): void {
  if (depth > 20) return; // pathological nesting guard
  const ctype = firstHeader(headers, "content-type");
  const cte = firstHeader(headers, "content-transfer-encoding");
  const disp = firstHeader(headers, "content-disposition");
  const mediaType = ctype.split(";")[0].trim().toLowerCase();

  if (mediaType.startsWith("multipart/")) {
    const boundary = headerParam(ctype, "boundary");
    if (!boundary) return;
    const parts = splitMultipart(body, boundary);
    for (const part of parts) {
      const { headerText, body: partBody } = splitHeadersBody(part);
      walkMime(parseHeaders(headerText), partBody, sink, depth + 1);
    }
    return;
  }

  const filename = headerParam(disp, "filename") || headerParam(ctype, "name");
  const isAttachment = /^attachment/i.test(disp) || (!!filename && !mediaType.startsWith("text/"));
  if (isAttachment && filename) {
    sink.attachments.push({ filename: decodeEncodedWords(filename).slice(0, 260), contentType: mediaType });
    return; // don't decode attachment payloads (binary); names/hashes are what we want
  }

  if (mediaType === "text/plain" || mediaType === "text/html" || (!mediaType && depth === 0)) {
    sink.text.push(decodeBody(body, cte));
  }
}

// Split a multipart body on its `--boundary` delimiters into raw part strings.
function splitMultipart(body: string, boundary: string): string[] {
  const norm = body.replace(/\r\n/g, "\n");
  const delim = "--" + boundary;
  const out: string[] = [];
  const lines = norm.split("\n");
  let cur: string[] | null = null;
  for (const line of lines) {
    if (line === delim || line === delim + "--") {
      if (cur) out.push(cur.join("\n"));
      cur = line === delim + "--" ? null : []; // closing delimiter ends the sequence
      continue;
    }
    if (cur) cur.push(line);
  }
  if (cur && cur.length) out.push(cur.join("\n"));
  return out;
}

// ───────────────────────────── URL / domain helpers ─────────────────────────────

// Re-fang a defanged URL ("hxxp://" → "http://", "[.]" → ".") so its host parses; strip trailing
// punctuation. Note "hxxp" defangs BOTH t's, so the two x's restore to two t's ("htt" + p[s]).
function refang(url: string): string {
  return url
    .replace(/^hx{2}(ps?):\/\//i, "htt$1://")
    .replace(/\[\.\]/g, ".")
    .replace(/[).,;'"]+$/, "");
}

function urlHost(url: string): string {
  const m = /^[a-z]+:\/\/([^/?#]+)/i.exec(refang(url));
  if (!m) return "";
  return (m[1].split("@").pop() ?? "") // strip userinfo
    .replace(/:\d+$/, "")               // strip port
    .toLowerCase();
}

const DOMAIN_RE = /^(?=.{1,253}$)([a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,}$/i;
const IPV4 = /^\d{1,3}(?:\.\d{1,3}){3}$/;

// ───────────────────────────── .msg (OLE) best-effort recovery ─────────────────────────────

// A `.msg` file forced through UTF-8 text decoding keeps its MAPI stream-name markers as ASCII.
export function looksLikeMsg(raw: string): boolean {
  return raw.includes("__substg1.0_") || raw.includes("__properties_version1.0") ||
    raw.includes("__nameid_version1.0");
}

// Recover the RFC 822 transport-headers block embedded in a `.msg` (MAPI property 0x007D). The
// binary streams interleave NULs (UTF-16LE) and noise; drop NULs, then capture a run of
// header-shaped lines starting at the first recognizable header.
function recoverMsgHeaders(raw: string): string {
  const denull = raw.replace(/\x00/g, "");
  const start = /(?:Return-Path|Received|Authentication-Results|From|Date|Subject|Message-ID):/i.exec(denull);
  if (!start) return "";
  const tail = denull.slice(start.index).replace(/\r\n/g, "\n");
  const lines = tail.split("\n");
  const kept: string[] = [];
  let miss = 0;
  for (const line of lines) {
    if (/^[ \t]/.test(line) && kept.length) { kept.push(line); continue; } // folded continuation
    if (/^[\x21-\x39\x3b-\x7e]+:\s?/.test(line)) { kept.push(line); miss = 0; continue; }
    if (line.trim() === "") { if (kept.length) break; continue; }            // blank ends the block
    if (++miss > 2) break;                                                   // drifted into binary noise
  }
  return kept.join("\n");
}

// ───────────────────────────── top-level parse ─────────────────────────────

// Parse a raw email (`.eml` text or best-effort `.msg`) into a structured ParsedEmail. Pure; never
// throws — on malformed input it returns whatever could be recovered.
export function parseMimeEmail(raw: string): ParsedEmail {
  const isMsg = looksLikeMsg(raw);
  const headerSource = isMsg ? recoverMsgHeaders(raw) : splitHeadersBody(raw).headerText;
  const headers = parseHeaders(headerSource);

  const subject = decodeEncodedWords(firstHeader(headers, "subject")).slice(0, 400);
  const rawDate = firstHeader(headers, "date");
  const from = parseAddress(firstHeader(headers, "from"));
  const replyTo = parseAddress(firstHeader(headers, "reply-to"));
  const returnPath = parseAddress(firstHeader(headers, "return-path"));
  const to = parseAddressList(firstHeader(headers, "to"));
  const messageId = firstHeader(headers, "message-id").replace(/[<>]/g, "").slice(0, 200);
  const auth = parseAuth(headers);

  // Body walk for URLs + attachments. `.eml` parses MIME; `.msg` has no recoverable MIME tree, so
  // we scan the (de-NUL'd) decoded bytes directly for URLs.
  const scan: BodyScan = { text: [], attachments: [] };
  if (isMsg) {
    scan.text.push(raw.replace(/\x00/g, ""));
  } else {
    const { body } = splitHeadersBody(raw);
    walkMime(headers, body, scan, 0);
  }
  const haystack = headerSource + "\n" + scan.text.join("\n");

  // URLs (dedup, capped length) + their hosts as domains.
  const urlSet = new Set<string>();
  for (const m of haystack.matchAll(URL_RE)) {
    const u = refang(m[0]).slice(0, 400);
    if (u.length > 8) urlSet.add(u);
    if (urlSet.size >= 500) break;
  }
  const urls = [...urlSet];

  // Hashes seen anywhere in the headers/body (attachment digests are often carried in headers).
  const hashSet = new Set<string>();
  for (const m of haystack.matchAll(HEX_HASH)) hashSet.add(m[0].toLowerCase());

  // Originating IP: explicit X-Originating-IP, else the earliest (bottom-of-chain) external hop.
  const originatingIp = pickOriginatingIp(headers);

  return {
    format: isMsg ? "msg" : "eml",
    date: normalizeEmailDate(rawDate),
    rawDate,
    subject,
    messageId,
    ...(from ? { from } : {}),
    ...(replyTo ? { replyTo } : {}),
    ...(returnPath ? { returnPath } : {}),
    to,
    originatingIp,
    auth,
    urls,
    attachments: scan.attachments,
    hashes: [...hashSet],
    headers,
  };
}

// Email Date headers always carry an explicit zone (RFC 2822), so `new Date()` is unambiguous.
// Strip a trailing "(UTC)" style zone comment first, then normalize to UTC ISO.
function normalizeEmailDate(raw: string): string {
  const s = raw.replace(/\s*\([^)]*\)\s*$/, "").trim();
  if (!s) return "";
  const t = Date.parse(s);
  return Number.isNaN(t) ? "" : new Date(t).toISOString();
}

function pickOriginatingIp(headers: Map<string, string[]>): string {
  const xorig = firstHeader(headers, "x-originating-ip");
  if (xorig) {
    const m = IPV4_G.exec(xorig);
    IPV4_G.lastIndex = 0;
    if (m) { const ip = cleanIp(m[0]); if (ip) return ip; }
  }
  // Received headers are most-recent first; the LAST is the origin hop. Walk bottom-up for the
  // first public IPv4.
  const received = headers.get("received") ?? [];
  for (let i = received.length - 1; i >= 0; i--) {
    for (const m of received[i].matchAll(IPV4_G)) {
      const ip = cleanIp(m[0]);
      if (ip && !isPrivateIp(ip)) return ip;
    }
  }
  return "";
}

function isPrivateIp(ip: string): boolean {
  const o = ip.split(".").map(Number);
  if (o.length !== 4) return false;
  return o[0] === 10 ||
    (o[0] === 172 && o[1] >= 16 && o[1] <= 31) ||
    (o[0] === 192 && o[1] === 168) ||
    o[0] === 127 ||
    (o[0] === 169 && o[1] === 254);
}

// ───────────────────────────── event + IOC building ─────────────────────────────

function emailSeverity(p: ParsedEmail): Severity {
  if (isAuthFail(p.auth.spf) || isAuthFail(p.auth.dkim) || isAuthFail(p.auth.dmarc)) return "High";
  if (suspiciousSender(p)) return "Medium";
  return "Info";
}

function authSummary(a: EmailAuth): string {
  const parts: string[] = [];
  if (a.spf) parts.push(`spf=${a.spf}`);
  if (a.dkim) parts.push(`dkim=${a.dkim}`);
  if (a.dmarc) parts.push(`dmarc=${a.dmarc}`);
  return parts.join(" ");
}

function fromLabel(a: EmailAddress): string {
  return a.name ? `${a.name} <${a.address}>` : a.address;
}

function buildEvent(p: ParsedEmail, severity: Severity): SiemEvent {
  const mitre = ["T1566"];
  if (p.attachments.length) mitre.push("T1566.001");
  if (p.urls.length) mitre.push("T1566.002");

  let desc = `Email: "${p.subject || "(no subject)"}"`;
  if (p.from) desc += ` from ${fromLabel(p.from)}`;
  if (p.to.length) desc += ` to ${p.to.map((a) => a.address).join(", ")}`;
  if (p.replyTo && (!p.from || registrable(p.replyTo.domain) !== registrable(p.from.domain))) {
    desc += ` | reply-to ${p.replyTo.address}`;
  }
  const auth = authSummary(p.auth);
  if (auth) desc += ` | auth ${auth}`;
  if (p.originatingIp) desc += ` | origin IP ${p.originatingIp}`;
  if (p.attachments.length) {
    desc += ` | ${p.attachments.length} attachment(s): ${p.attachments.map((a) => a.filename).join(", ")}`;
  }
  if (p.urls.length) desc += ` | ${p.urls.length} URL(s)`;

  return {
    id: "",
    timestamp: p.date,
    description: desc.slice(0, 600),
    severity,
    mitreTechniques: mitre,
    sources: ["Email"],
  };
}

function collectIocs(p: ParsedEmail, maxIocs: number): SiemIoc[] {
  const sink = new Map<string, SiemIoc>();

  // URLs + their hosts.
  for (const u of p.urls) {
    addIoc(sink, "url", u);
    const host = urlHost(u);
    if (host && !IPV4.test(host) && DOMAIN_RE.test(host)) addIoc(sink, "domain", host);
    else if (host && IPV4.test(host)) { const ip = cleanIp(host); if (ip) addIoc(sink, "ip", ip); }
  }

  // Sender / reply-to / return-path domains are themselves indicators worth tracking.
  for (const a of [p.from, p.replyTo, p.returnPath]) {
    if (a?.domain && DOMAIN_RE.test(a.domain)) addIoc(sink, "domain", a.domain);
  }

  // Originating IP.
  if (p.originatingIp) addIoc(sink, "ip", p.originatingIp);

  // Attachment filenames + any hashes (header/body) + the attachments' own digests.
  for (const att of p.attachments) {
    if (att.filename) addIoc(sink, "file", att.filename);
    if (att.sha256) addIoc(sink, "hash", att.sha256.toLowerCase());
    if (att.md5) addIoc(sink, "hash", att.md5.toLowerCase());
  }
  for (const h of p.hashes) addIoc(sink, "hash", h);

  return [...sink.values()].slice(0, maxIocs);
}

// Parse a single email artifact into a forensic event + IOCs. Returns an empty result when the
// input is not recoverable as an email (no headers, no URLs, no subject/from).
export function parseEmail(text: string, opts: EmailImportOptions = {}): EmailParseResult {
  const maxIocs = opts.maxIocs ?? 5000;
  const parsed = parseMimeEmail(text);

  const recoverable = !!(parsed.subject || parsed.from || parsed.date || parsed.urls.length || parsed.messageId);
  if (!recoverable) {
    return { events: [], iocs: [], total: 0, kept: 0, dropped: 0, groups: 0, format: "empty", subject: "", sender: "" };
  }

  const severity = emailSeverity(parsed);
  const event = buildEvent(parsed, severity);
  const iocs = collectIocs(parsed, maxIocs);

  return {
    events: [event],
    iocs,
    total: 1,
    kept: 1,
    dropped: 0,
    groups: 1,
    format: parsed.format,
    subject: parsed.subject,
    sender: parsed.from?.address ?? "",
  };
}
