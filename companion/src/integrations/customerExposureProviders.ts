import type { CustomerExposureProvider, CustomerExposureResult, ExposureTargetType } from "../analysis/customerExposure.js";
import type { FetchFn } from "../enrichment/provider.js";
import { LeakCheckClient, type LeakCheckRecord } from "./leakcheck/leakcheckClient.js";

function asArray(v: unknown): unknown[] { return Array.isArray(v) ? v : []; }
function isObject(v: unknown): v is Record<string, unknown> { return typeof v === "object" && v !== null; }
function str(v: unknown): string { return v === undefined || v === null ? "" : String(v); }
function unique(values: string[]): string[] { return [...new Set(values.map((v) => v.trim()).filter(Boolean))]; }

function secretPresent(record: Record<string, unknown>): boolean {
  return ["password", "passwords", "hash", "hashed_password", "credential", "credentials", "credential_status"]
    .some((k) => String(record[k] ?? "").trim().length > 0);
}

export interface LeakCheckExposureOptions {
  apiKey: string;
  fetchFn?: FetchFn;
  timeoutMs?: number;
  baseUrl?: string;
  domainLimit?: number;
}

export class LeakCheckExposureProvider implements CustomerExposureProvider {
  readonly name = "LeakCheck";
  private readonly client: LeakCheckClient;
  private readonly domainLimit: number;

  constructor(opts: LeakCheckExposureOptions) {
    this.client = new LeakCheckClient(opts);
    this.domainLimit = opts.domainLimit ?? 1000;
  }

  private map(targetType: ExposureTargetType, target: string, rows: LeakCheckRecord[]): CustomerExposureResult[] {
    return rows.map((row) => {
      const record = row as Record<string, unknown>;
      return {
        provider: this.name,
        targetType,
        target,
        email: str(row.email) || undefined,
        username: str(row.username) || undefined,
        breach: str(row.source?.name) || "LeakCheck result",
        breachDate: str(row.source?.breach_date) || undefined,
        exposedData: unique(asArray(row.fields).map(str)),
        secretPresent: secretPresent(record),
      };
    });
  }

  async lookupEmail(email: string): Promise<CustomerExposureResult[]> {
    const r = await this.client.queryEmail(email);
    return this.map("email", email, r.result);
  }

  async lookupDomain(domain: string): Promise<CustomerExposureResult[]> {
    const r = await this.client.queryDomain(domain, this.domainLimit);
    return this.map("domain", domain, r.result);
  }
}

export interface HaveIBeenPwnedOptions {
  apiKey: string;
  userAgent?: string;
  fetchFn?: FetchFn;
  timeoutMs?: number;
  baseUrl?: string;
}

export class HaveIBeenPwnedExposureProvider implements CustomerExposureProvider {
  readonly name = "Have I Been Pwned";
  private readonly fetchFn: FetchFn;
  private readonly base: string;
  private readonly timeoutMs: number;
  private readonly userAgent: string;

  constructor(private readonly opts: HaveIBeenPwnedOptions) {
    this.fetchFn = opts.fetchFn ?? fetch;
    this.base = (opts.baseUrl ?? "https://haveibeenpwned.com/api/v3").replace(/\/+$/, "");
    this.timeoutMs = opts.timeoutMs ?? 20_000;
    this.userAgent = opts.userAgent || "DFIR Companion";
  }

  private async get(path: string): Promise<unknown> {
    const res = await this.fetchFn(`${this.base}${path}`, {
      headers: {
        "hibp-api-key": this.opts.apiKey,
        "user-agent": this.userAgent,
        accept: "application/json",
      },
      signal: AbortSignal.timeout(this.timeoutMs),
    });
    if (res.status === 404) return [];
    if (res.status === 401 || res.status === 403) throw new Error("HIBP auth failed or domain is not verified for this account");
    if (res.status === 429) throw new Error("HIBP rate limit");
    if (!res.ok) throw new Error(`HIBP HTTP ${res.status}`);
    return res.json();
  }

  async lookupEmail(email: string): Promise<CustomerExposureResult[]> {
    const json = await this.get(`/breachedAccount/${encodeURIComponent(email)}?truncateResponse=false`);
    return asArray(json).filter(isObject).map((b) => {
      const dataClasses = asArray(b.DataClasses).map(str).filter(Boolean);
      return {
        provider: this.name,
        targetType: "email",
        target: email,
        email,
        breach: str(b.Name || b.Title) || "HIBP breach",
        breachDate: str(b.BreachDate) || undefined,
        exposedData: dataClasses,
        secretPresent: dataClasses.some((c) => /password|credential/i.test(c)),
      };
    });
  }

  async lookupDomain(domain: string): Promise<CustomerExposureResult[]> {
    const json = await this.get(`/breachedDomain/${encodeURIComponent(domain)}`);
    if (!isObject(json)) return [];
    const out: CustomerExposureResult[] = [];
    for (const [alias, breaches] of Object.entries(json)) {
      for (const breach of asArray(breaches).map(str).filter(Boolean)) {
        out.push({
          provider: this.name,
          targetType: "domain",
          target: domain,
          email: `${alias}@${domain}`,
          breach,
        });
      }
    }
    return out;
  }
}

export interface DeHashedOptions {
  apiKey: string;
  fetchFn?: FetchFn;
  timeoutMs?: number;
  baseUrl?: string;
}

export class DeHashedExposureProvider implements CustomerExposureProvider {
  readonly name = "DeHashed";
  private readonly fetchFn: FetchFn;
  private readonly base: string;
  private readonly timeoutMs: number;

  constructor(private readonly opts: DeHashedOptions) {
    this.fetchFn = opts.fetchFn ?? fetch;
    this.base = (opts.baseUrl ?? "https://api.dehashed.com/v2").replace(/\/+$/, "");
    this.timeoutMs = opts.timeoutMs ?? 20_000;
  }

  private async search(query: string, targetType: ExposureTargetType, target: string): Promise<CustomerExposureResult[]> {
    const res = await this.fetchFn(`${this.base}/search`, {
      method: "POST",
      headers: {
        "DeHashed-Api-Key": this.opts.apiKey,
        "content-type": "application/json",
        accept: "application/json",
      },
      body: JSON.stringify({ query, page: 1, size: 100, regex: false, wildcard: false, de_dupe: false }),
      signal: AbortSignal.timeout(this.timeoutMs),
    });
    if (res.status === 401 || res.status === 403) {
      const body = await res.text().catch(() => "");
      throw new Error(`DeHashed auth failed (${res.status})${body ? `: ${body.slice(0, 200)}` : ""} — check DFIR_DEHASHED_KEY (v2 API key, sent as the DeHashed-Api-Key header)`);
    }
    if (res.status === 429) throw new Error("DeHashed rate limit");
    if (res.status === 404) return [];
    if (!res.ok) throw new Error(`DeHashed HTTP ${res.status}`);
    const json = (await res.json()) as Record<string, unknown>;
    const rows = asArray(json.entries ?? json.data ?? json.results).filter(isObject);
    return rows.map((row) => {
      const data = unique(asArray(row.fields).map(str).concat(
        ["email", "username", "phone", "address", "ip_address", "password", "hash"]
          .filter((k) => row[k] !== undefined),
      ));
      return {
        provider: this.name,
        targetType,
        target,
        email: str(row.email) || undefined,
        username: str(row.username || row.name) || undefined,
        breach: str(row.database_name || row.source || row.breach || row.name) || "DeHashed result",
        breachDate: str(row.date || row.breach_date) || undefined,
        exposedData: data,
        sourceUrl: str(row.url) || undefined,
        secretPresent: secretPresent(row),
      };
    });
  }

  lookupEmail(email: string): Promise<CustomerExposureResult[]> {
    return this.search(`email:${email}`, "email", email);
  }

  lookupDomain(domain: string): Promise<CustomerExposureResult[]> {
    return this.search(`domain:${domain}`, "domain", domain);
  }
}

export interface CrowdStrikeReconOptions {
  clientId: string;
  clientSecret: string;
  cloud?: string;
  baseUrl?: string;
  fetchFn?: FetchFn;
  timeoutMs?: number;
}

const CS_BASE: Record<string, string> = {
  "us-1": "https://api.crowdstrike.com",
  "us-2": "https://api.us-2.crowdstrike.com",
  "eu-1": "https://api.eu-1.crowdstrike.com",
  "gov-us-1": "https://api.laggar.gcw.crowdstrike.com",
  "gov-us-2": "https://api.us-gov-2.crowdstrike.mil",
};
const CS_ALIAS: Record<string, string> = {
  us: "us-1", us1: "us-1", "us-1": "us-1",
  us2: "us-2", "us-2": "us-2",
  eu: "eu-1", eu1: "eu-1", "eu-1": "eu-1",
  gov: "gov-us-1", gov1: "gov-us-1", "gov-us-1": "gov-us-1",
  gov2: "gov-us-2", "gov-us-2": "gov-us-2",
};

function crowdStrikeBase(opts: CrowdStrikeReconOptions): string {
  if (opts.baseUrl) return opts.baseUrl.replace(/\/+$/, "");
  const cloud = CS_ALIAS[(opts.cloud ?? "us-1").toLowerCase()] ?? "us-1";
  return CS_BASE[cloud];
}

export class CrowdStrikeReconExposureProvider implements CustomerExposureProvider {
  readonly name = "CrowdStrike Recon";
  private readonly fetchFn: FetchFn;
  private readonly base: string;
  private readonly timeoutMs: number;
  private token = "";
  private tokenExpiresAt = 0;

  constructor(private readonly opts: CrowdStrikeReconOptions) {
    this.fetchFn = opts.fetchFn ?? fetch;
    this.base = crowdStrikeBase(opts);
    this.timeoutMs = opts.timeoutMs ?? 20_000;
  }

  private async ensureToken(force = false): Promise<string> {
    if (!force && this.token && Date.now() < this.tokenExpiresAt) return this.token;
    const body = new URLSearchParams({ client_id: this.opts.clientId, client_secret: this.opts.clientSecret });
    const res = await this.fetchFn(`${this.base}/oauth2/token`, {
      method: "POST",
      headers: { "content-type": "application/x-www-form-urlencoded", accept: "application/json" },
      body: body.toString(),
      signal: AbortSignal.timeout(this.timeoutMs),
    });
    if (res.status === 400 || res.status === 401 || res.status === 403) throw new Error("CrowdStrike Recon auth failed");
    if (!res.ok) throw new Error(`CrowdStrike Recon token HTTP ${res.status}`);
    const json = (await res.json()) as { access_token?: string; expires_in?: number };
    if (!json.access_token) throw new Error("CrowdStrike Recon token response missing access_token");
    this.token = json.access_token;
    this.tokenExpiresAt = Date.now() + Math.max(0, (json.expires_in ?? 1799) - 60) * 1000;
    return this.token;
  }

  private async get(path: string): Promise<Record<string, unknown>> {
    const call = async (token: string) => this.fetchFn(`${this.base}${path}`, {
      headers: { authorization: `Bearer ${token}`, accept: "application/json" },
      signal: AbortSignal.timeout(this.timeoutMs),
    });
    let res = await call(await this.ensureToken());
    if (res.status === 401) res = await call(await this.ensureToken(true));
    if (res.status === 403) throw new Error("CrowdStrike Recon 403 — add the 'Monitoring rules (Falcon Intelligence): Read' scope to your DFIR_CROWDSTRIKE_* API client");
    if (res.status === 429) throw new Error("CrowdStrike Recon rate limit");
    if (res.status === 404) return {};
    if (!res.ok) {
      // CrowdStrike returns { errors: [{ code, message }] } — surface the real message (a 400 is
      // usually an FQL filter CrowdStrike rejected, not a generic failure).
      const body = (await res.json().catch(() => ({}))) as { errors?: Array<{ message?: string }> };
      const msg = (body.errors ?? []).map((e) => e.message).filter(Boolean).join("; ");
      throw new Error(`CrowdStrike Recon HTTP ${res.status}${msg ? ` — ${msg}` : ""}`);
    }
    return (await res.json()) as Record<string, unknown>;
  }

  private async queryRecords(targetType: ExposureTargetType, target: string): Promise<CustomerExposureResult[]> {
    const filter = targetType === "email"
      ? `email:'${target}'`
      : `(domain:'${target}',credentials_domain:'${target}')`;
    const params = new URLSearchParams({ filter, q: target, limit: "100" });
    const idsJson = await this.get(`/recon/queries/notifications-exposed-data-records/v1?${params.toString()}`);
    const ids = asArray(idsJson.resources).map(str).filter(Boolean);
    if (!ids.length) return [];
    const entParams = new URLSearchParams({ ids: ids.slice(0, 100).join(",") });
    const entities = await this.get(`/recon/entities/notifications-exposed-data-records/v1?${entParams.toString()}`);
    return asArray(entities.resources).filter(isObject).map((row) => {
      const breach = str(row.site || row.source || row.domain || row.credentials_domain || row.url) || "CrowdStrike Recon exposure";
      const data = unique([
        str(row.credential_status) ? `credential_status: ${str(row.credential_status)}` : "",
        str(row.data_type),
        str(row.status),
      ]);
      return {
        provider: this.name,
        targetType,
        target,
        email: str(row.email) || undefined,
        username: str(row.username) || undefined,
        breach,
        breachDate: str(row.exposure_date || row.created_date || row.updated_date || row.found_date) || undefined,
        exposedData: data,
        sourceUrl: str(row.url) || undefined,
        secretPresent: secretPresent(row) || data.some((d) => /credential|password/i.test(d)),
      };
    });
  }

  lookupEmail(email: string): Promise<CustomerExposureResult[]> {
    return this.queryRecords("email", email);
  }

  lookupDomain(domain: string): Promise<CustomerExposureResult[]> {
    return this.queryRecords("domain", domain);
  }
}

export interface ShodanExposureOptions {
  apiKey: string;
  fetchFn?: FetchFn;
  timeoutMs?: number;
  baseUrl?: string;
  maxMatches?: number;
}

// Shodan — internet attack-surface exposure (NOT credential leaks). For a customer DOMAIN it
// returns the org's internet-exposed hosts/services (open ports, products, known CVEs) via
// `hostname:<domain>` search. Shodan has no email lookup, so lookupEmail is a no-op.
export class ShodanExposureProvider implements CustomerExposureProvider {
  readonly name = "Shodan";
  private readonly fetchFn: FetchFn;
  private readonly base: string;
  private readonly timeoutMs: number;
  private readonly maxMatches: number;

  constructor(private readonly opts: ShodanExposureOptions) {
    this.fetchFn = opts.fetchFn ?? fetch;
    this.base = (opts.baseUrl ?? "https://api.shodan.io").replace(/\/+$/, "");
    this.timeoutMs = opts.timeoutMs ?? 20_000;
    this.maxMatches = opts.maxMatches ?? 50;
  }

  async lookupEmail(): Promise<CustomerExposureResult[]> {
    return [];   // Shodan maps exposed hosts/services, not email breaches
  }

  async lookupDomain(domain: string): Promise<CustomerExposureResult[]> {
    const url = `${this.base}/shodan/host/search?key=${encodeURIComponent(this.opts.apiKey)}`
      + `&query=${encodeURIComponent(`hostname:${domain}`)}`;
    const res = await this.fetchFn(url, { headers: { accept: "application/json" }, signal: AbortSignal.timeout(this.timeoutMs) });
    if (res.status === 401 || res.status === 403) throw new Error("Shodan auth failed (check DFIR_SHODAN_KEY)");
    if (res.status === 429) throw new Error("Shodan rate limit / out of query credits");
    if (!res.ok) throw new Error(`Shodan HTTP ${res.status}`);
    const json = (await res.json()) as { matches?: unknown };
    return asArray(json.matches).filter(isObject).slice(0, this.maxMatches).map((m) => {
      const ip = str(m.ip_str);
      const port = str(m.port);
      const transport = str(m.transport) || "tcp";
      const service = [str(m.product), str(m.version)].filter(Boolean).join(" ") || str(m.transport) || "service";
      const vulns = isObject(m.vulns) ? Object.keys(m.vulns) : asArray(m.vulns).map(str).filter(Boolean);
      const exposedData = unique([
        port ? `${port}/${transport}` : "",
        str(m.product),
        str(m.org),
        ...vulns.map((v) => `vuln:${v}`),
      ]);
      return {
        provider: this.name,
        targetType: "domain" as ExposureTargetType,
        target: domain,
        breach: `${ip}:${port} ${service}`.trim(),
        breachDate: str(m.timestamp) || undefined,
        exposedData,
        sourceUrl: ip ? `https://www.shodan.io/host/${encodeURIComponent(ip)}` : undefined,
        secretPresent: false,   // exposed services/CVEs, not credentials (CVEs surface in exposedData)
      };
    });
  }
}
