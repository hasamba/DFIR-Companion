import { readFile } from "node:fs/promises";
import { join } from "node:path";
import { atomicWrite } from "../storage/atomicWrite.js";
import type { CaseStore } from "../storage/caseStore.js";
import { isNoiseDomain } from "./anonymize.js";
import type { InvestigationState } from "./stateTypes.js";
import {
  extractCaseEmails,
  normalizeEmail,
  sanitizeTargets,
  type CustomerTargets,
} from "./customerStore.js";

export type ExposureTargetType = "domain" | "email";

export interface CustomerExposureResult {
  provider: string;
  targetType: ExposureTargetType;
  target: string;
  email?: string;
  username?: string;
  breach?: string;
  breachDate?: string;
  exposedData?: string[];
  sourceUrl?: string;
  secretPresent?: boolean;
  raw?: unknown;
}

export interface StoredCustomerExposureResult extends Omit<CustomerExposureResult, "raw"> {}

export interface CustomerExposureError {
  provider: string;
  targetType: ExposureTargetType;
  target: string;
  error: string;
}

export interface CustomerExposureSummary {
  checkedAt: string;
  providers: string[];
  targets: CustomerTargets;
  results: StoredCustomerExposureResult[];
  errors: CustomerExposureError[];
}

export interface CustomerExposureProvider {
  readonly name: string;
  lookupEmail(email: string): Promise<CustomerExposureResult[]>;
  lookupDomain(domain: string): Promise<CustomerExposureResult[]>;
}

export interface CustomerExposureOptions {
  now?: () => string;
  sleep?: (ms: number) => Promise<void>;
  delayMs?: number;
}

export const NO_EXPOSURE: CustomerExposureSummary = {
  checkedAt: "",
  providers: [],
  targets: { domains: [], emails: [] },
  results: [],
  errors: [],
};

function domainOfEmail(email: string): string {
  return email.slice(email.lastIndexOf("@") + 1).toLowerCase();
}

function errorMessage(err: unknown): string {
  return err instanceof Error ? err.message : String(err);
}

function uniqueSorted(values: Iterable<string>): string[] {
  return [...new Set([...values].map((v) => v.trim().toLowerCase()).filter(Boolean))].sort();
}

function safeResult(r: CustomerExposureResult): StoredCustomerExposureResult {
  const { raw: _raw, ...safe } = r;
  return {
    ...safe,
    exposedData: safe.exposedData ? uniqueSorted(safe.exposedData) : undefined,
  };
}

// A result is only worth surfacing when the provider actually FOUND something — a
// breach/exposed host, exposed data fields, or credential material. "Checked, clean" rows
// (no breach, no data) are dropped by the dashboard panel + report so the section shows
// findings only. Real providers never emit empty rows (every hit carries a `breach`), so
// this is a display guard; the stored summary still records that the check ran.
export function hasExposureFinding(
  r: Pick<StoredCustomerExposureResult, "breach" | "exposedData" | "secretPresent">,
): boolean {
  return Boolean((r.breach && r.breach.trim()) || (r.exposedData && r.exposedData.length) || r.secretPresent);
}

// Distinct victim domains implied by the case's known FQDN hosts (event.asset only — NOT
// accounts/UPNs mentioned in free text, which would also catch an attacker's own email domain).
// Excludes noise (registry hive / ATT&CK folder / generic word, via the same isNoiseDomain the
// anonymizer uses) and any domain that is itself a case IOC (an adversary domain, never a
// customer asset). Pure + deterministic.
export function extractCaseDomains(state: InvestigationState): string[] {
  const iocVals = new Set(state.iocs.map((i) => i.value.toLowerCase()));
  const domains = new Set<string>();
  for (const e of state.forensicTimeline) {
    const host = e.asset?.trim().toLowerCase();
    if (!host) continue;
    const dot = host.indexOf(".");
    if (dot <= 0) continue; // no dot (or leading dot) — not a FQDN, nothing to derive
    const domain = host.slice(dot + 1);
    if (isNoiseDomain(domain) || iocVals.has(domain)) continue;
    domains.add(domain);
  }
  return [...domains];
}

export function buildCustomerExposureTargets(
  state: InvestigationState,
  rawTargets: CustomerTargets,
): CustomerTargets {
  const targets = sanitizeTargets(rawTargets);
  const customerDomains = new Set(targets.domains);
  for (const domain of extractCaseDomains(state)) customerDomains.add(domain);
  const emails = new Set(targets.emails);

  for (const email of extractCaseEmails(state)) {
    const normalized = normalizeEmail(email);
    if (normalized && customerDomains.has(domainOfEmail(normalized))) emails.add(normalized);
  }

  return {
    domains: uniqueSorted(customerDomains),
    emails: uniqueSorted(emails),
  };
}

export async function summarizeExposure(
  state: InvestigationState,
  rawTargets: CustomerTargets,
  providers: readonly CustomerExposureProvider[],
  opts: CustomerExposureOptions = {},
): Promise<CustomerExposureSummary> {
  const now = opts.now ?? (() => new Date().toISOString());
  const sleep = opts.sleep ?? ((ms: number) => new Promise<void>((resolve) => setTimeout(resolve, ms)));
  const delayMs = opts.delayMs ?? 1500;
  const targets = buildCustomerExposureTargets(state, rawTargets);
  const results: StoredCustomerExposureResult[] = [];
  const errors: CustomerExposureError[] = [];
  let calls = 0;

  async function runOne(provider: CustomerExposureProvider, targetType: ExposureTargetType, target: string): Promise<void> {
    if (calls > 0) await sleep(delayMs);
    calls += 1;
    try {
      const found = targetType === "domain"
        ? await provider.lookupDomain(target)
        : await provider.lookupEmail(target);
      results.push(...found.map(safeResult));
    } catch (err) {
      errors.push({ provider: provider.name, targetType, target, error: errorMessage(err) });
    }
  }

  for (const provider of providers) {
    for (const domain of targets.domains) await runOne(provider, "domain", domain);
    for (const email of targets.emails) await runOne(provider, "email", email);
  }

  return {
    checkedAt: now(),
    providers: providers.map((p) => p.name),
    targets,
    results,
    errors,
  };
}

export class CustomerExposureStore {
  constructor(private readonly cases: CaseStore) {}

  private path(caseId: string): string {
    return join(this.cases.stateDir(caseId), "customer-exposure.json");
  }

  async load(caseId: string): Promise<CustomerExposureSummary> {
    try {
      const raw = JSON.parse(await readFile(this.path(caseId), "utf8")) as Partial<CustomerExposureSummary>;
      return {
        ...NO_EXPOSURE,
        ...raw,
        providers: Array.isArray(raw.providers) ? raw.providers.map(String) : [],
        targets: sanitizeTargets(raw.targets),
        results: Array.isArray(raw.results) ? raw.results.map((r) => safeResult(r as CustomerExposureResult)) : [],
        errors: Array.isArray(raw.errors) ? raw.errors.map((e) => ({
          provider: String((e as CustomerExposureError).provider ?? ""),
          targetType: (e as CustomerExposureError).targetType === "domain" ? "domain" : "email",
          target: String((e as CustomerExposureError).target ?? ""),
          error: String((e as CustomerExposureError).error ?? ""),
        })) : [],
      };
    } catch (err) {
      if ((err as NodeJS.ErrnoException).code === "ENOENT") return { ...NO_EXPOSURE };
      throw err;
    }
  }

  async save(caseId: string, summary: CustomerExposureSummary): Promise<void> {
    await atomicWrite(this.path(caseId), JSON.stringify({
      ...summary,
      targets: sanitizeTargets(summary.targets),
      results: summary.results.map((r) => safeResult(r)),
    }, null, 2));
  }
}
