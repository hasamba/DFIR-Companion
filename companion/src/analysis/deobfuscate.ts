// Deterministic payload deobfuscation: detect → decode → extract IOCs from decoded text.
// No network, no I/O, no AI — safe to call anywhere, including in tests.
//
// Covers the most common attacker obfuscation patterns:
//   • PowerShell -enc / -EncodedCommand (UTF-16LE base64)
//   • [Convert]::FromBase64String('…') (UTF-8 base64)
//   • Generic base64 blocks when a suspicious execution marker is present
//
// The result is attached to the ForensicEvent as `event.deobfuscated` by applyDeobfuscation.ts.

import type { IOC } from "./stateTypes.js";

export type DeobfuscationMethod = "powershell-enc" | "base64";

export interface RawIoc {
  type: IOC["type"];
  value: string;
}

export interface DeobfuscationResult {
  decoded: string;
  method: DeobfuscationMethod;
  rawIocs: RawIoc[];
}

// ──────────────────────────── detection patterns ──────────────────────────────

// PowerShell -enc / -e / -EncodedCommand with a base64 payload (UTF-16LE)
const PS_ENC_RE = /(?:-enc(?:odedcommand)?|-e\b)\s+([A-Za-z0-9+/]{20,}={0,2})/i;
// [Convert]::FromBase64String('…') — UTF-8 payload
const FROM_B64_RE = /\[convert\]::frombase64string\(\s*["']([A-Za-z0-9+/]{20,}={0,2})["']\s*\)/i;
// Bare base64 block (≥40 chars) in quotes or after an equals sign
const BASE64_BLOCK_RE = /(?:["'`]|(?:=|:)\s*)([A-Za-z0-9+/]{40,}={0,2})(?:["'`]|\s|$)/;
// Presence of a suspicious execution marker that makes a generic base64 worth decoding
const EXEC_MARKER_RE = /iex\b|invoke-expression|certutil|frombase64string|downloadstring/i;

// ──────────────────────────── IOC extraction from decoded text ────────────────

const URL_RE = /\bhttps?:\/\/[^\s"'<>]{5,300}/gi;
// IPv4: each octet ≤ 255 (avoid matching version numbers like "1.2.3.4.5" or "10.0" port refs)
const IPV4_RE = /\b((?:(?:25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)\.){3}(?:25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d))\b/g;
const SHA256_RE = /\b([a-f0-9]{64})\b/gi;
// Domain: 2-63 chars per label, a common TLD, no leading digit in the rightmost label
const DOMAIN_RE = /\b([a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.(?:com|net|org|io|co|info|xyz|ru|cn|tk|top|pw|cc|biz|online|site|club|live|win|fun|space|tech|store|shop|link|click|download))\b/gi;

const NOISE_IPS = new Set(["127.0.0.1", "0.0.0.0", "255.255.255.255", "8.8.8.8", "8.8.4.4"]);

function extractIocsFromText(text: string): RawIoc[] {
  const out: RawIoc[] = [];
  const seen = new Set<string>();
  const add = (type: IOC["type"], value: string): void => {
    const k = `${type}:${value.toLowerCase()}`;
    if (!seen.has(k)) { seen.add(k); out.push({ type, value }); }
  };

  for (const m of text.matchAll(URL_RE)) {
    const url = m[0].replace(/[.,;:)'">]+$/, "").slice(0, 300);
    if (url.length > 10) add("url", url);
  }
  for (const m of text.matchAll(IPV4_RE)) {
    if (!NOISE_IPS.has(m[1])) add("ip", m[1]);
  }
  for (const m of text.matchAll(SHA256_RE)) {
    add("hash", m[0].toLowerCase());
  }
  for (const m of text.matchAll(DOMAIN_RE)) {
    const d = m[1].toLowerCase();
    if (!/^\d/.test(d)) add("domain", d);
  }
  return out;
}

// ──────────────────────────── decoding helpers ────────────────────────────────

// Decode a base64 string as UTF-16LE (PowerShell's internal string encoding) or UTF-8.
// Returns null when the payload looks like binary noise (no printable text).
function safeBase64Decode(s: string, encoding: BufferEncoding): string | null {
  try {
    const buf = Buffer.from(s.trim().replace(/\s/g, ""), "base64");
    if (buf.length < 4) return null;
    const text = buf.toString(encoding);
    // Require at least a few printable ASCII chars — rejects binary payloads
    const printable = (text.match(/[\x20-\x7e]/g) ?? []).length;
    if (printable < 4 || printable / text.length < 0.3) return null;
    return text.replace(/\0/g, "").trim(); // strip UTF-16LE null bytes that survive the decode
  } catch {
    return null;
  }
}

// ──────────────────────────── public API ─────────────────────────────────────

// Returns true when the text contains a pattern this module can attempt to decode.
export function isObfuscated(text: string): boolean {
  return PS_ENC_RE.test(text) || FROM_B64_RE.test(text) ||
    (BASE64_BLOCK_RE.test(text) && EXEC_MARKER_RE.test(text));
}

// Attempt to deobfuscate an event's description. Returns null when no decodable
// obfuscation is found or the decoded payload looks like binary noise.
export function deobfuscateText(text: string): DeobfuscationResult | null {
  // 1. PowerShell -enc / -EncodedCommand (UTF-16LE)
  const psMatch = PS_ENC_RE.exec(text);
  if (psMatch) {
    const decoded = safeBase64Decode(psMatch[1], "utf16le");
    if (decoded && decoded.length >= 5) {
      return { decoded, method: "powershell-enc", rawIocs: extractIocsFromText(decoded) };
    }
  }

  // 2. [Convert]::FromBase64String('…') — UTF-8
  const fbMatch = FROM_B64_RE.exec(text);
  if (fbMatch) {
    const decoded = safeBase64Decode(fbMatch[1], "utf8");
    if (decoded && decoded.length >= 5) {
      return { decoded, method: "base64", rawIocs: extractIocsFromText(decoded) };
    }
  }

  // 3. Generic base64 block — only when a suspicious execution marker is present
  if (EXEC_MARKER_RE.test(text)) {
    const b64Match = BASE64_BLOCK_RE.exec(text);
    if (b64Match) {
      // Try UTF-16LE first (common for PowerShell), then UTF-8
      const decoded =
        safeBase64Decode(b64Match[1], "utf16le") ??
        safeBase64Decode(b64Match[1], "utf8");
      if (decoded && decoded.length >= 5) {
        return { decoded, method: "base64", rawIocs: extractIocsFromText(decoded) };
      }
    }
  }

  return null;
}
