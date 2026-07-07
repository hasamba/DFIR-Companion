// IOC exclude list — per-case, PERMANENT removal of indicators the analyst never wants tracked
// (e.g. internal client hostnames like "*.lan"). Deliberately separate from the IOC whitelist
// (iocWhitelist.ts), which is global and reversible (auto-marks a match as a false positive but
// keeps the record — the whitelist is intentionally opt-in and non-destructive, see its header).
// An exclude rule instead deletes matching IOCs outright and prevents them from ever being
// re-created, so they can never reach enrichment (enrichIocs only ever sees state.iocs).
//
// Pure logic only (match + sanitize) so it unit-tests without I/O. Persistence lives directly on
// InvestigationState.iocExcludeRules (per-case, not a separate store — see stateTypes.ts); the
// purge-on-add wiring lives in the /cases/:id/ioc-exclude route, and the going-forward filter
// lives in stateMerge.ts's mergeDelta.

import type { IOC } from "./stateTypes.js";

export const EXCLUDE_MATCH_MODES = ["exact", "suffix", "regex"] as const;
export type ExcludeMatchMode = (typeof EXCLUDE_MATCH_MODES)[number];

const IOC_TYPES = ["ip", "domain", "hash", "file", "process", "url", "sid", "other"] as const;

export interface IocExcludeRule {
  id: string;
  match: ExcludeMatchMode;     // how `pattern` is compared to the IOC value
  pattern: string;             // "client01.lan" (exact) | "lan" (suffix — normalized to ".lan") | a regex
  iocType?: IOC["type"];       // optional: only apply to this IOC type; unset = any type
  note?: string;               // why it's excluded (e.g. "client's internal AD domain")
  addedAt: string;             // ISO time the rule was added
}

// The validated core of a rule, before the caller assigns an id + addedAt.
export type ExcludeRuleInput = Omit<IocExcludeRule, "id" | "addedAt">;

// Normalize a suffix pattern to always carry a leading "." so "lan" and ".lan" behave identically —
// matching is on whole DNS labels, not an arbitrary substring.
export function normalizeSuffixPattern(pattern: string): string {
  const p = pattern.trim();
  return p.startsWith(".") ? p : `.${p}`;
}

// ── matching ───────────────────────────────────────────────────────────────────────────────────
export function ruleMatchesIoc(rule: IocExcludeRule | ExcludeRuleInput, ioc: { type: IOC["type"]; value: string }): boolean {
  if (rule.iocType && rule.iocType !== ioc.type) return false;
  const raw = String(ioc.value ?? "").trim();
  if (!raw) return false;
  const val = raw.toLowerCase();
  switch (rule.match) {
    case "exact":
      return val === rule.pattern.trim().toLowerCase();
    case "suffix": {
      const suffix = normalizeSuffixPattern(rule.pattern).toLowerCase();
      return val === suffix.slice(1) || val.endsWith(suffix);
    }
    case "regex":
      try { return new RegExp(rule.pattern, "i").test(raw); } catch { return false; }
    default:
      return false;
  }
}

// First rule that matches this IOC, or null.
export function matchIocToExclude(
  ioc: { type: IOC["type"]; value: string },
  rules: readonly IocExcludeRule[],
): IocExcludeRule | null {
  for (const r of rules) if (ruleMatchesIoc(r, ioc)) return r;
  return null;
}

// Every IOC (out of a case's current list) that matches at least one rule — used to purge on add.
export function excludeMatches(iocs: readonly IOC[], rules: readonly IocExcludeRule[]): IOC[] {
  if (rules.length === 0) return [];
  return iocs.filter((ioc) => matchIocToExclude(ioc, rules) !== null);
}

// ── validation ───────────────────────────────────────────────────────────────────────────────
// Coerce an untrusted object into a valid rule core, or null when it can't be (bad mode, empty
// pattern, invalid regex). Keeps the route from persisting garbage.
export function sanitizeExcludeRuleInput(raw: unknown): ExcludeRuleInput | null {
  if (!raw || typeof raw !== "object") return null;
  const r = raw as Record<string, unknown>;
  const mode = String(r.match ?? "").trim().toLowerCase();
  if (!EXCLUDE_MATCH_MODES.includes(mode as ExcludeMatchMode)) return null;
  const match = mode as ExcludeMatchMode;
  let pattern = String(r.pattern ?? "").trim();
  if (!pattern || pattern.length > 500) return null;
  if (match === "suffix") pattern = normalizeSuffixPattern(pattern);
  if (match === "regex") { try { new RegExp(pattern); } catch { return null; } }
  const rawType = String(r.iocType ?? "").trim().toLowerCase();
  const iocType = (IOC_TYPES as readonly string[]).includes(rawType) ? (rawType as IOC["type"]) : undefined;
  const note = r.note != null ? String(r.note).trim().slice(0, 500) : undefined;
  return { match, pattern, ...(iocType ? { iocType } : {}), ...(note ? { note } : {}) };
}
