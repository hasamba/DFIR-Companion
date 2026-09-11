import { createHash } from "node:crypto";

// Small value helpers shared by the Exchange audit decoder and its inbox-rule reader.

type Row = Record<string, unknown>;

export const NAME_MAX = 40;
export const FOLDER_MAX = 30;
export const SUBJECT_MAX = 60;
export const LIST_SHOWN = 3;
export const VALUE_MAX = 4096;
export const CLIENT_MAX = 40;
export const SESSION_MAX = 16;
export const DIGEST_HEX = 16;

export const ACCESS_NOTE = "item access; whether a person read the content is not established";
export const SYNC_NOTE = "possible offline copy after sync";
export const THROTTLED_NOTE =
  "throttled — the item list is incomplete; whether further access to this mailbox went unlogged for up to 24 hours depends on the service behaviour at the time of the event";
export const SET_RULE_NOTE = "effective conditions and actions not in this record";
export const SET_FORWARD_NOTE = "effective forwarding state not in this record";
export const APP_USER_TYPES = new Set([5, 6]);

export const isObject = (v: unknown): v is Row => typeof v === "object" && v !== null && !Array.isArray(v);
export const str = (v: unknown): string =>
  typeof v === "string" ? v : typeof v === "number" || typeof v === "boolean" ? String(v) : "";
export const getCI = (row: Row, key: string): unknown => {
  if (key in row) return row[key];
  const lower = key.toLowerCase();
  for (const k of Object.keys(row)) if (k.toLowerCase() === lower) return row[k];
  return undefined;
};
export const digest = (s: string): string =>
  createHash("sha256").update(s).digest("hex").slice(0, DIGEST_HEX);
export const plural = (n: number, w: string): string => `${n} ${w}${n === 1 ? "" : "s"}`;
export const quote = (s: string, max: number): string => `"${s.slice(0, max)}${s.length > max ? "…" : ""}"`;
export const list = (v: string[]): string =>
  v.slice(0, LIST_SHOWN).join(", ") + (v.length > LIST_SHOWN ? ` (+${v.length - LIST_SHOWN} more)` : "");
export const truthy = (v: string): boolean => /^(true|\$true|1|yes)$/i.test(v.trim());
export const falsy = (v: string): boolean => /^(false|\$false|0|no)$/i.test(v.trim());

/** `{Name, Value}` pairs (Parameters, OperationProperties) → a case-insensitive map. */
export interface Pairs {
  /** name (lowercased) → value, bounded to VALUE_MAX for parsing and display. */
  map: Map<string, string>;
  /** Digest of every COMPLETE name and value, in order — the identity of what the record holds. */
  digest: string;
  /** True when a value was cut for parsing or entries were dropped: the scope is incomplete. */
  truncated: boolean;
}
export const PAIRS_MAX = 200;
export function pairs(v: unknown): Pairs {
  const map = new Map<string, string>();
  const all = Array.isArray(v) ? v : [];
  let truncated = all.length > PAIRS_MAX;
  const whole: string[] = [];
  for (const p of all.slice(0, PAIRS_MAX)) {
    if (!isObject(p)) continue;
    const name = str(getCI(p, "Name")).trim();
    if (!name) continue;
    const value = str(getCI(p, "Value"));
    whole.push(`${name}=${value}`);
    if (value.length > VALUE_MAX) truncated = true;
    map.set(name.toLowerCase(), value.slice(0, VALUE_MAX));
  }
  return { map, digest: digest(whole.join("\u0000")), truncated };
}
// A multi-valued cmdlet parameter is `a;b` (sometimes `{a, b}`); an SMTP proxy address is `smtp:x`.
export const values = (v: string): string[] =>
  v
    .replace(/^\{|\}$/g, "")
    .split(/[;,]/)
    .map((x) => x.trim().replace(/^smtp:/i, ""))
    .filter(Boolean);

// The address as the record carries it: `1.2.3.4`, `1.2.3.4:443`, `[2001:db8::1]:443`.
export const ipOf = (v: string): string => {
  const m4 = /(\d{1,3}(?:\.\d{1,3}){3})/.exec(v);
  if (m4) return m4[1];
  const m6 = /\[([0-9a-f:]+)\]/i.exec(v);
  return m6 ? m6[1] : v.trim();
};

export const domainOf = (addr: string): string => {
  const m = /@([^@\s>]+)$/.exec(addr.trim().replace(/>$/, ""));
  return m ? m[1].toLowerCase() : "";
};
/** `inside`/`outside the mailbox's domain`, or "" for a value that is not an SMTP address. */
export function domainClass(addr: string, ownerDomain: string): string {
  const d = domainOf(addr);
  if (!d || !ownerDomain) return "";
  return d === ownerDomain ? "inside the mailbox's domain" : "outside the mailbox's domain";
}
export const withClass = (addr: string, ownerDomain: string): string => {
  const c = domainClass(addr, ownerDomain);
  return c ? `${addr} (${c})` : addr;
};
