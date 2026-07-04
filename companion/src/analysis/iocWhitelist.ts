// IOC whitelist — persistent, environment-level "known-good" patterns the analyst maintains
// (internal IP ranges as CIDR, known-good file hashes, regexes for internal domains). An IOC that
// matches a rule is auto-marked FALSE POSITIVE on import (and on demand), reusing the existing
// false-positive machinery so it's reversible and shows in the "False Positives" panel.
//
// Pure logic only (match + parse/serialize + validation) so it unit-tests without I/O. The store
// (iocWhitelistStore.ts) handles persistence; the auto-mark wiring lives in the /import route.
//
// CAUTION (DFIR): whitelisting is opt-in and never default — auto-marking internal IP ranges can
// hide lateral movement, so the analyst chooses every rule. "Missing a real threat is worse than
// leaving noise" (see CLAUDE.md): the whitelist starts empty.

import type { IOC } from "./stateTypes.js";
import { parseCsv } from "./csvImport.js";

export const WHITELIST_MATCH_MODES = ["cidr", "regex", "exact"] as const;
export type WhitelistMatchMode = (typeof WHITELIST_MATCH_MODES)[number];

const IOC_TYPES = ["ip", "domain", "hash", "file", "process", "url", "other"] as const;

export interface IocWhitelistRule {
  id: string;
  match: WhitelistMatchMode;     // how `pattern` is compared to the IOC value
  pattern: string;               // "10.0.0.0/8" | "^.*\\.corp\\.local$" | a sha256/md5 | an exact value
  iocType?: IOC["type"];         // optional: only apply to this IOC type (e.g. cidr → ip, hash list → hash)
  note?: string;                 // why it's known-good (e.g. "internal range", "Windows system binary")
  addedAt: string;               // ISO time the rule was added
}

// The validated core of a rule, before the store assigns an id + addedAt.
export type WhitelistRuleInput = Omit<IocWhitelistRule, "id" | "addedAt">;

// ── IPv4 CIDR containment ──────────────────────────────────────────────────────────────────────
// IPv4 only (the common "internal ranges" case). A bare IP is treated as /32. IPv6 / malformed
// input simply doesn't match (the rule is a no-op), so a cidr rule never throws on odd IOC values.
function ipv4ToInt(ip: string): number | null {
  const parts = ip.trim().split(".");
  if (parts.length !== 4) return null;
  let n = 0;
  for (const p of parts) {
    if (!/^\d{1,3}$/.test(p)) return null;
    const v = Number(p);
    if (v > 255) return null;
    n = (n << 8) | v;
  }
  return n >>> 0;
}

export function isValidCidr(cidr: string): boolean {
  const m = cidr.trim().match(/^(\d{1,3}(?:\.\d{1,3}){3})(?:\/(\d{1,2}))?$/);
  if (!m) return false;
  if (ipv4ToInt(m[1]) === null) return false;
  const bits = m[2] === undefined ? 32 : Number(m[2]);
  return bits >= 0 && bits <= 32;
}

export function ipInCidr(ip: string, cidr: string): boolean {
  const m = cidr.trim().match(/^(\d{1,3}(?:\.\d{1,3}){3})(?:\/(\d{1,2}))?$/);
  if (!m) return false;
  const base = ipv4ToInt(m[1]);
  const target = ipv4ToInt(ip);
  if (base === null || target === null) return false;
  const bits = m[2] === undefined ? 32 : Number(m[2]);
  if (bits < 0 || bits > 32) return false;
  if (bits === 0) return true;                                   // 0.0.0.0/0 matches everything
  const mask = (0xffffffff << (32 - bits)) >>> 0;
  return (base & mask) >>> 0 === (target & mask) >>> 0;
}

// ── matching ───────────────────────────────────────────────────────────────────────────────────
export function ruleMatchesIoc(rule: IocWhitelistRule | WhitelistRuleInput, ioc: { type: IOC["type"]; value: string }): boolean {
  if (rule.iocType && rule.iocType !== ioc.type) return false;
  const val = String(ioc.value ?? "").trim();
  if (!val) return false;
  switch (rule.match) {
    case "cidr":
      return ipInCidr(val, rule.pattern);
    case "exact":
      return val.toLowerCase() === rule.pattern.trim().toLowerCase();
    case "regex":
      try { return new RegExp(rule.pattern, "i").test(val); } catch { return false; }
    default:
      return false;
  }
}

// First rule that matches this IOC, or null.
export function matchIocToWhitelist(
  ioc: { type: IOC["type"]; value: string },
  rules: readonly IocWhitelistRule[],
): IocWhitelistRule | null {
  for (const r of rules) if (ruleMatchesIoc(r, ioc)) return r;
  return null;
}

// Every IOC that matches at least one rule, paired with the rule that caught it (for auto-marking).
export function whitelistMatches(
  iocs: readonly IOC[],
  rules: readonly IocWhitelistRule[],
): Array<{ ioc: IOC; rule: IocWhitelistRule }> {
  if (rules.length === 0) return [];
  const out: Array<{ ioc: IOC; rule: IocWhitelistRule }> = [];
  for (const ioc of iocs) {
    const rule = matchIocToWhitelist(ioc, rules);
    if (rule) out.push({ ioc, rule });
  }
  return out;
}

// ── validation ───────────────────────────────────────────────────────────────────────────────
// Coerce an untrusted object into a valid rule core, or null when it can't be (bad mode, empty
// pattern, invalid CIDR/regex). Keeps the store + routes from persisting garbage.
export function sanitizeRuleInput(raw: unknown): WhitelistRuleInput | null {
  if (!raw || typeof raw !== "object") return null;
  const r = raw as Record<string, unknown>;
  const mode = String(r.match ?? "").trim().toLowerCase();
  if (!WHITELIST_MATCH_MODES.includes(mode as WhitelistMatchMode)) return null;
  const match = mode as WhitelistMatchMode;
  const pattern = String(r.pattern ?? "").trim();
  if (!pattern || pattern.length > 500) return null;
  if (match === "cidr" && !isValidCidr(pattern)) return null;
  if (match === "regex") { try { new RegExp(pattern); } catch { return null; } }
  const rawType = String(r.iocType ?? "").trim().toLowerCase();
  const iocType = (IOC_TYPES as readonly string[]).includes(rawType) ? (rawType as IOC["type"]) : undefined;
  const note = r.note != null ? String(r.note).trim().slice(0, 500) : undefined;
  return { match, pattern, ...(iocType ? { iocType } : {}), ...(note ? { note } : {}) };
}

// ── CSV / JSON import-export ─────────────────────────────────────────────────────────────────
// Accepts either a JSON array (or {rules:[…]}) or a CSV with a header row (columns: match,pattern,
// type,note — aliases tolerated). Returns sanitized rule cores; malformed entries are dropped.
export function parseWhitelistText(text: string): WhitelistRuleInput[] {
  const t = (text ?? "").trim();
  if (!t) return [];
  if (t.startsWith("[") || t.startsWith("{")) {
    try {
      const data = JSON.parse(t) as unknown;
      const arr = Array.isArray(data)
        ? data
        : Array.isArray((data as { rules?: unknown }).rules)
          ? (data as { rules: unknown[] }).rules
          : [data];
      return arr.map(sanitizeRuleInput).filter((r): r is WhitelistRuleInput => r !== null);
    } catch {
      return [];
    }
  }
  const { headers, rows } = parseCsv(t);
  const idx = (names: string[]): number => headers.findIndex((h) => names.includes(h.trim().toLowerCase()));
  const mCol = idx(["match", "mode"]);
  const pCol = idx(["pattern", "value", "indicator", "cidr"]);
  const tCol = idx(["type", "ioctype", "kind"]);
  const nCol = idx(["note", "comment", "reason", "description"]);
  if (pCol === -1) return [];
  return rows
    .map((row) =>
      sanitizeRuleInput({
        match: mCol >= 0 ? row[mCol] : "exact",
        pattern: row[pCol],
        iocType: tCol >= 0 ? row[tCol] : undefined,
        note: nCol >= 0 ? row[nCol] : undefined,
      }),
    )
    .filter((r): r is WhitelistRuleInput => r !== null);
}

function csvField(v: string): string {
  return /[",\n\r]/.test(v) ? `"${v.replace(/"/g, '""')}"` : v;
}

export function toWhitelistCsv(rules: readonly IocWhitelistRule[]): string {
  const head = "match,pattern,type,note";
  const lines = rules.map((r) =>
    [r.match, r.pattern, r.iocType ?? "", r.note ?? ""].map((v) => csvField(String(v))).join(","),
  );
  return [head, ...lines].join("\n") + "\n";
}
