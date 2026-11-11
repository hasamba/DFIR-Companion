import { createHash } from "node:crypto";
import type { Severity } from "./stateTypes.js";

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
// `-WhatIf` and `-ValidateOnly` make no change: a successful record of either is a simulation.
export const isDryRun = (p: Map<string, string>): boolean =>
  ["whatif", "validateonly"].some((k) => p.has(k) && (truthy(p.get(k) ?? "") || p.get(k) === ""));
export const DRY_RUN_NOTE = "dry run (WhatIf/ValidateOnly) — no change was made";

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
/**
 * The domains an address is classed against (#2550). A UPN mailbox gives its own domain ("the
 * mailbox's domain"). A mailbox named by alias gives none, so the record's other proof of the
 * tenant is used ("the tenant domains this record names"): the organisation segment of an Exchange path
 * (`…/Microsoft Exchange Hosted Organizations/<domain>/<alias>`) and the acting person's UPN domain.
 * No proof → no domains → no class, the safe default.
 */
export interface OwnerDomains {
  domains: readonly string[];
  basis: "mailbox" | "tenant";
}

const HOSTED_ORG = /Hosted Organizations\/([^/\\]+)/i;
/** The tenant domain an Exchange organisation path names, or "". */
export const hostedOrgDomain = (v: string): string => {
  const d = HOSTED_ORG.exec(v)?.[1]?.trim().toLowerCase() ?? "";
  return d.includes(".") ? d : "";
};

// UserType 3 (DcAdmin) and 4 (System) are the service itself; NT AUTHORITY\ is Exchange's own host.
const SYSTEM_USER_TYPES = new Set([3, 4]);
const SYSTEM_ACTOR = /^(?:NT AUTHORITY\\|S-1-5-18\b)/i;
export const isSystemActor = (actor: string, userType: number): boolean =>
  SYSTEM_USER_TYPES.has(userType) || SYSTEM_ACTOR.test(actor.trim());

export function ownerDomainsOf(o: {
  mailbox: string;
  paths: readonly string[];
  actor: string;
  actorIsPerson: boolean;
}): OwnerDomains {
  if (o.mailbox.includes("@")) return { domains: [domainOf(o.mailbox)].filter(Boolean), basis: "mailbox" };
  const found = [
    ...o.paths.map(hostedOrgDomain),
    o.actorIsPerson && o.actor.includes("@") ? domainOf(o.actor) : "",
  ].filter(Boolean);
  return { domains: [...new Set(found)], basis: "tenant" };
}

const ownerOf = (owner: string | OwnerDomains): OwnerDomains =>
  typeof owner === "string" ? { domains: owner ? [owner] : [], basis: "mailbox" } : owner;

/** `inside`/`outside the mailbox's domain` (or `the tenant domains this record names`), or "" without a class. */
export function domainClass(addr: string, owner: string | OwnerDomains): string {
  const d = domainOf(addr);
  const o = ownerOf(owner);
  if (!d || !o.domains.length) return "";
  const where = o.basis === "mailbox" ? "the mailbox's domain" : "the tenant domains this record names";
  return o.domains.includes(d) ? `inside ${where}` : `outside ${where}`;
}
export const withClass = (addr: string, owner: string | OwnerDomains): string => {
  const c = domainClass(addr, owner);
  return c ? `${addr} (${c})` : addr;
};

/** `alias`, `alias@domain` or an Exchange path → the lowercased local name, for a self-grant test. */
export const localName = (v: string): string =>
  (v.split("/").filter(Boolean).pop() ?? "").trim().toLowerCase().replace(/@.*$/, "");

/** The last path segment, trimmed and lowercased. */
const lastSegment = (v: string): string => (v.split("/").filter(Boolean).pop() ?? "").trim().toLowerCase();

/**
 * Whether a grantee and a mailbox name one principal. Two full UPNs compare whole, so `alice@a` and
 * `alice@b` stay distinct accounts; an alias or an Exchange path has no domain, so it compares by
 * local name (#2550 review).
 */
export const samePrincipal = (a: string, b: string): boolean => {
  const x = lastSegment(a);
  const y = lastSegment(b);
  return x.includes("@") && y.includes("@") ? x === y : localName(x) === localName(y);
};

/**
 * A mailbox permission change's grade (#2550). Widening: FullAccess / SendAs to ANOTHER account by a
 * person is High (the importer table's own grade); the service provisioning its own mailboxes (a
 * system or application actor) is Low; a self-grant, a Deny entry and every other right stay Medium.
 * A narrowing change is Low.
 */
export function permissionSeverity(g: {
  widens: boolean;
  deny: boolean;
  rights: string;
  trustee: string;
  mailbox: string;
  byService: boolean;
}): Severity {
  if (!g.widens || g.byService) return "Low";
  const self = !g.trustee || samePrincipal(g.trustee, g.mailbox);
  return !g.deny && !self && /\b(fullaccess|sendas)\b/i.test(g.rights) ? "High" : "Medium";
}
