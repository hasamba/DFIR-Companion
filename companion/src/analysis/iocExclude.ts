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

import { checkRegexSafety, EMPTY_MATCH_REASON, regexMatchesEmptyString } from "./regexSafety.js";
import type { IOC } from "./stateTypes.js";

export const EXCLUDE_MATCH_MODES = ["exact", "suffix", "regex"] as const;
export type ExcludeMatchMode = (typeof EXCLUDE_MATCH_MODES)[number];

const IOC_TYPES = ["ip", "domain", "hash", "file", "process", "url", "sid", "other"] as const;

export interface IocExcludeRule {
  id: string;
  match: ExcludeMatchMode; // how `pattern` is compared to the IOC value
  pattern: string; // "client01.lan" (exact) | "lan" (suffix — normalized to ".lan") | a regex
  iocType?: IOC["type"]; // optional: only apply to this IOC type; unset = any type
  note?: string; // why it's excluded (e.g. "client's internal AD domain")
  addedAt: string; // ISO time the rule was added
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
export function ruleMatchesIoc(
  rule: IocExcludeRule | ExcludeRuleInput,
  ioc: { type: IOC["type"]; value: string },
): boolean {
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
      try {
        const re = new RegExp(rule.pattern, "i");
        // A nullable pattern stored before #1900 would match every IOC — it matches nothing instead.
        return !re.test("") && re.test(raw);
      } catch {
        return false;
      }
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
export type ExcludeRuleValidation = { ok: true; rule: ExcludeRuleInput } | { ok: false; reason: string };

// Coerce an untrusted object into a valid rule core, or say why it can't be (bad mode, empty
// pattern, invalid/unsafe regex, a regex that matches the empty string). Keeps the route from
// persisting garbage, and gives the analyst a reason they can act on.
export function validateExcludeRuleInput(raw: unknown): ExcludeRuleValidation {
  if (!raw || typeof raw !== "object") return { ok: false, reason: "rule must be an object" };
  const r = raw as Record<string, unknown>;
  const mode = String(r.match ?? "")
    .trim()
    .toLowerCase();
  if (!EXCLUDE_MATCH_MODES.includes(mode as ExcludeMatchMode))
    return { ok: false, reason: `match must be one of ${EXCLUDE_MATCH_MODES.join("|")}` };
  const match = mode as ExcludeMatchMode;
  let pattern = String(r.pattern ?? "").trim();
  if (!pattern || pattern.length > 500) return { ok: false, reason: "pattern must be 1-500 characters" };
  if (match === "suffix") pattern = normalizeSuffixPattern(pattern);
  if (match === "regex") {
    // Same reasoning as the whitelist's sanitizeRuleInput: vet the pattern's COST, not just its
    // syntax, because it runs against adversary-controlled IOC values.
    // "i" because ruleMatchesIoc matches with it — see checkRegexSafety on why that matters.
    const safety = checkRegexSafety(pattern, "i");
    if (!safety.ok) return { ok: false, reason: `invalid regex: ${safety.reason ?? "rejected"}` };
    // #1900: a nullable regex (`x*`, `evil\.com|`) matches every IOC, and the add purges one-way.
    if (regexMatchesEmptyString(pattern, "i")) return { ok: false, reason: EMPTY_MATCH_REASON };
  }
  const rawType = String(r.iocType ?? "")
    .trim()
    .toLowerCase();
  const iocType = (IOC_TYPES as readonly string[]).includes(rawType) ? (rawType as IOC["type"]) : undefined;
  const note = r.note != null ? String(r.note).trim().slice(0, 500) : undefined;
  return { ok: true, rule: { match, pattern, ...(iocType ? { iocType } : {}), ...(note ? { note } : {}) } };
}

// The validated rule core, or null when it is invalid — validateExcludeRuleInput without the reason.
export function sanitizeExcludeRuleInput(raw: unknown): ExcludeRuleInput | null {
  const v = validateExcludeRuleInput(raw);
  return v.ok ? v.rule : null;
}
