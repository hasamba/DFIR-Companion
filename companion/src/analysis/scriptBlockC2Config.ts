// C2 settings a logged PowerShell script block defines (#1959).
//
// A 4104 record can hold a whole beacon configuration: `$server='…'; $port=443; $uri='/submit.php';
// $watermark=123456`, or the hashtable form `@{domains=@(…);IPs=@(…);sleep=…;jitter=…;x86Get=…}`.
// The IOC extractor lifts the addresses into the IOC list, and destinationFacts.ts tags an ip:port
// or a URL — but a bare domain, an address with its port in a separate field, a scheme-less URI and a
// watermark reach the model as nothing. On INC-2026-001 the model then wrote a C2 finding that named
// none of the script's infrastructure.
//
// THE TRIGGER IS NARROW ON PURPOSE. The issue's "any two of server/port/uri/useragent/…" fires on
// Chocolatey's install script (`$url`, `$uri = [System.Uri]$url`, `$userAgent = 'chocolatey command
// line'`) in every case scanned. So a block qualifies only when it has:
//   (a) at least one BEACON key — a word no install or admin script needs (watermark, jitter,
//       spawnto, x86Get, …). url / uri / useragent / port never satisfy this;
//   (b) at least two config keys in total;
//   (c) at least one infrastructure value — a domain or a non-loopback IPv4 under an address key.
//
// Only LITERAL values count. `$uri = [System.Uri]$url` assigns a variable, not a setting.
//
// Every value is attacker text: angle brackets, control characters and leading formula characters
// are stripped, each value is capped, and URL secrets are redacted before anything leaves here.
//
// PURE — no I/O. Not a prompt constant: the eval change gate hashes only prompts/*.ts.

import { redactUrlSecrets } from "./destinationFacts.js";
import { isCollectorRow, isScriptRecord, scriptTextOf } from "./scriptBlockCommands.js";
import type { ForensicEvent } from "./stateTypes.js";

/** The whole tag — whole entries are dropped past this, never sliced. */
export const SCRIPT_C2_TAG_MAX = 200;
const TEXT_SCAN = 20000;
const VALUE_MAX = 60;
const RAW_VALUE_MAX = 400;
const MAX_ENTRIES = 16;
const MAX_INFRA = 8;

/** Keys only a beacon / implant configuration needs. */
const BEACON_KEYS = new Set([
  "watermark",
  "sleep",
  "jitter",
  "spawnto",
  "c2",
  "beacon",
  "callback",
  "lhost",
  "x86get",
  "x64get",
  "maxget",
]);
/** Keys whose value names where the implant talks to. */
const INFRA_KEYS = new Set(["server", "host", "c2", "domains", "ips", "urls", "lhost", "callback"]);
/** Keys that count toward "two config keys", but never as the beacon key. */
const OTHER_KEYS = ["port", "uri", "url", "useragent", "get", "post"];
const ALL_KEYS = [...new Set([...BEACON_KEYS, ...INFRA_KEYS, ...OTHER_KEYS])];

// `$key =` or a hashtable `key =`. Not `$obj.key =` (a property, often of a live object), not `==`.
const KEY_RE = new RegExp(`(?<![\\w.$-])\\$?(${ALL_KEYS.join("|")})\\s*=(?!=)\\s*`, "giu");
const IPV4_RE = /(?<![\w.])(\d{1,3}(?:\.\d{1,3}){3})(?![\w.])/gu;
const DOMAIN_RE = /(?<![\w.-])((?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,24})(?![\w-])/giu;
/** A dotted name ending like a file is a file, not a domain (`rundll32.exe`, `/visit.js`). */
const FILE_SUFFIX = /\.(?:exe|dll|ps1|psm1|bat|cmd|vbs|js|txt|xml|json|php|css|html?|log|dat|bin|tmp)$/iu;
const URL_IN_VALUE = /https?:\/\/[^\s'"<>,;)]+/giu;

export interface ScriptC2Entry {
  /** The key as the script spells it. */
  readonly key: string;
  /** The cleaned, capped, secret-redacted value. */
  readonly value: string;
}

export interface ScriptC2Config {
  readonly entries: readonly ScriptC2Entry[];
  /** Domains and non-loopback IPv4 addresses named under an address key, deduped, cleaned. */
  readonly infrastructure: readonly string[];
}

function clean(v: string): string {
  const s = redactUrlSecrets(v.replace(URL_IN_VALUE, (u) => redactUrlSecrets(u)))
    .replace(/[<>\u0000-\u001f\u007f]/gu, "")
    .replace(/\s+/gu, " ")
    .trim()
    .replace(/^[=+@\s]+/u, "");
  return s.length > VALUE_MAX ? s.slice(0, VALUE_MAX) + "…" : s;
}

/** The quoted items of `@('a','b')` / `@("a")`, or its comma-split bare words. */
function arrayItems(inner: string): string[] {
  const quoted = [...inner.matchAll(/'([^'\n]*)'|"([^"\n]*)"/gu)].map((m) => m[1] ?? m[2] ?? "");
  return quoted.length ? quoted : inner.split(",").map((s) => s.trim());
}

/** The literal items assigned at `at`, or null for a variable, a cast, an expression or nothing. */
function literalAt(text: string, at: number): string[] | null {
  const rest = text.slice(at, at + RAW_VALUE_MAX);
  const c = rest[0];
  if (c === "'" || c === '"') {
    const end = rest.indexOf(c, 1);
    const nl = rest.indexOf("\n", 1);
    if (end < 0 || (nl >= 0 && nl < end)) return null;
    return [rest.slice(1, end)];
  }
  if (rest.startsWith("@(")) {
    const end = rest.indexOf(")");
    return end < 0 ? null : arrayItems(rest.slice(2, end));
  }
  const bare = /^[\w./:-]+/u.exec(rest);
  return bare ? [bare[0]] : null;
}

function isLoopback(ip: string): boolean {
  return ip.startsWith("127.") || ip === "0.0.0.0";
}

function validIpv4(ip: string): boolean {
  return ip.split(".").every((o) => Number(o) <= 255);
}

/** Domains and non-loopback IPv4s named in one raw value. */
function infraIn(raw: string): string[] {
  const out: string[] = [];
  for (const m of raw.matchAll(IPV4_RE)) if (validIpv4(m[1]) && !isLoopback(m[1])) out.push(m[1]);
  for (const m of raw.matchAll(DOMAIN_RE)) {
    const d = m[1].toLowerCase();
    if (/^[\d.]+$/u.test(d) || FILE_SUFFIX.test(d) || d === "localhost") continue;
    out.push(d);
  }
  return out;
}

/** The C2 settings a script text defines, or null when it does not clear the trigger. */
export function scriptC2ConfigFromText(text: string): ScriptC2Config | null {
  const body = String(text ?? "").slice(0, TEXT_SCAN);
  const entries: ScriptC2Entry[] = [];
  const seen = new Set<string>();
  const infrastructure: string[] = [];
  for (const m of body.matchAll(KEY_RE)) {
    const lower = m[1].toLowerCase();
    if (seen.has(lower)) continue;
    const items = literalAt(body, (m.index ?? 0) + m[0].length);
    if (!items) continue;
    const value = items.map(clean).filter(Boolean).join(", ");
    if (!value || /^\$?(?:true|false|null)$/iu.test(value)) continue;
    seen.add(lower);
    entries.push({ key: m[1], value: value.length > VALUE_MAX ? value.slice(0, VALUE_MAX) + "…" : value });
    if (INFRA_KEYS.has(lower)) {
      for (const raw of items)
        for (const x of infraIn(raw)) if (!infrastructure.includes(x)) infrastructure.push(x);
    }
    if (entries.length >= MAX_ENTRIES) break;
  }
  const hasBeaconKey = entries.some((x) => BEACON_KEYS.has(x.key.toLowerCase()));
  if (!hasBeaconKey || entries.length < 2 || !infrastructure.length) return null;
  return { entries, infrastructure: infrastructure.slice(0, MAX_INFRA).map(clean) };
}

/** The C2 settings a row's script text defines — null for a non-script row or a collector row. */
export function scriptC2Config(e: ForensicEvent): ScriptC2Config | null {
  if (isCollectorRow(e) || !isScriptRecord(e)) return null;
  return scriptC2ConfigFromText(scriptTextOf(e));
}

/** Infrastructure keys first, then beacon keys, then the rest — the order the budget keeps them in. */
function priority(key: string): number {
  const k = key.toLowerCase();
  if (INFRA_KEYS.has(k)) return 0;
  if (BEACON_KEYS.has(k)) return 1;
  return 2;
}

/**
 * The prompt row's `<script-c2-config:key=value; …>` tag. Named for SCRIPT content, so the model does
 * not read it as a connection that happened. "" when the row defines no C2 settings.
 */
export function renderScriptC2Tag(e: ForensicEvent): string {
  const config = scriptC2Config(e);
  if (!config) return "";
  const ranked = config.entries
    .map((x, i) => ({ x, i }))
    .sort((a, b) => priority(a.x.key) - priority(b.x.key) || a.i - b.i);
  const kept = new Set<number>();
  let used = "<script-c2-config:>".length;
  for (const { x, i } of ranked) {
    const cost = x.key.length + 1 + x.value.length + (kept.size ? 2 : 0);
    if (used + cost > SCRIPT_C2_TAG_MAX) continue;
    kept.add(i);
    used += cost;
  }
  const shown = config.entries.filter((_, i) => kept.has(i)).map((x) => `${x.key}=${x.value}`);
  return shown.length ? `<script-c2-config:${shown.join("; ")}>` : "";
}
