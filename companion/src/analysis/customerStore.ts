import { readFile } from "node:fs/promises";
import { join } from "node:path";
import { atomicWrite } from "../storage/atomicWrite.js";
import type { CaseStore } from "../storage/caseStore.js";
import type { InvestigationState } from "./stateTypes.js";

// The CUSTOMER's own assets for the breach/leak check — deliberately separate from IOCs.
// `domains` are the victim org's domains (NEVER adversary/IOC domains); `emails` are specific
// customer addresses to check. Persisted per case in state/customer.json.
export interface CustomerTargets {
  domains: string[];
  emails: string[];
  // Which exposure providers to run, by name (like the enrichment per-source picker). Omitted or
  // empty = run all configured providers; a non-empty list restricts the check to those.
  providers?: string[];
}

export const NO_CUSTOMER: CustomerTargets = { domains: [], emails: [] };

const EMAIL_RE = /[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}/g;
const DOMAIN_RE = /^[A-Za-z0-9-]+(?:\.[A-Za-z0-9-]+)+$/;

export function normalizeEmail(s: string): string | null {
  const e = s.trim().toLowerCase();
  return /^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(e) ? e : null;
}

// Accept a bare domain, a URL, or a @domain — strip scheme / www / path and validate.
export function normalizeDomain(s: string): string | null {
  const d = s.trim().toLowerCase()
    .replace(/^https?:\/\//, "")
    .replace(/^@/, "")
    .replace(/^www\./, "")
    .replace(/[/?#].*$/, "");
  return DOMAIN_RE.test(d) ? d : null;
}

// Split a comma/newline/space/semicolon-delimited string (or pass through an array).
export function parseList(input: unknown): string[] {
  if (Array.isArray(input)) return input.map((x) => String(x));
  if (typeof input === "string") return input.split(/[\s,;]+/).filter(Boolean);
  return [];
}

export function sanitizeTargets(raw: unknown): CustomerTargets {
  const r = (raw ?? {}) as { domains?: unknown; emails?: unknown; providers?: unknown };
  const domains = [...new Set(parseList(r.domains).map(normalizeDomain).filter((x): x is string => Boolean(x)))];
  const emails = [...new Set(parseList(r.emails).map(normalizeEmail).filter((x): x is string => Boolean(x)))];
  const out: CustomerTargets = { domains, emails };
  // Only carry a provider selection when one was explicitly provided (so older files without it
  // keep defaulting to "all"). Names are kept as-is (the route intersects them with the configured
  // providers); empty after sanitising means "all".
  if (r.providers !== undefined) {
    out.providers = [...new Set(parseList(r.providers).map((s) => s.trim()).filter(Boolean))];
  }
  return out;
}

// Distinct emails that APPEAR in the case (event descriptions), EXCLUDING any that are themselves
// a case IOC — an adversary indicator. So an auto-pulled leak check stays on victim assets, not on
// a phishing-sender address that happens to be in the timeline. Pure + deterministic.
export function extractCaseEmails(state: InvestigationState): string[] {
  const iocVals = new Set(state.iocs.map((i) => i.value.toLowerCase()));
  const out = new Set<string>();
  for (const ev of state.forensicTimeline) {
    EMAIL_RE.lastIndex = 0;
    let m: RegExpExecArray | null;
    while ((m = EMAIL_RE.exec(ev.description))) {
      const e = m[0].toLowerCase();
      if (!iocVals.has(e)) out.add(e);
    }
  }
  return [...out];
}

export class CustomerStore {
  constructor(private readonly cases: CaseStore) {}

  private path(caseId: string): string {
    return join(this.cases.stateDir(caseId), "customer.json");
  }

  async load(caseId: string): Promise<CustomerTargets> {
    try {
      return sanitizeTargets(JSON.parse(await readFile(this.path(caseId), "utf8")));
    } catch (err) {
      if ((err as NodeJS.ErrnoException).code === "ENOENT") return { ...NO_CUSTOMER };
      throw err;
    }
  }

  async save(caseId: string, targets: CustomerTargets): Promise<void> {
    await atomicWrite(this.path(caseId), JSON.stringify(sanitizeTargets(targets), null, 2));
  }
}
