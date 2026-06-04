import type { EnrichmentProvider, EnrichmentResult, FetchFn, IocKind, Verdict } from "./provider.js";

export interface YetiOptions {
  baseUrl: string;   // your YETI instance, e.g. https://yeti.example.org
  apiKey: string;    // YETI per-user API key (x-yeti-apikey)
  fetchFn?: FetchFn;
  timeoutMs?: number;
}

interface YetiTag { name?: string }
interface YetiObservable {
  id?: string;
  value?: string;
  type?: string;
  tags?: Record<string, unknown> | Array<string | YetiTag>;
  context?: Array<Record<string, unknown>>;
}

// Tag names that indicate the observable is known-bad (vs merely tracked).
const MALICIOUS_TAGS = /\b(malware|malicious|c2|c&c|botnet|trojan|ransom\w*|phishing|exploit|apt|backdoor|stealer)\b/i;

// YETI v2 returns tags as an array of objects ({ name, fresh, expires, … }); also tolerate a
// plain string[] or a { tagName: meta } dict. Extracting the names is what makes the malicious-tag
// check work (mapping objects with String() yields "[object Object]", which never matches).
function tagNames(tags: YetiObservable["tags"]): string[] {
  if (!tags) return [];
  if (Array.isArray(tags)) {
    return tags
      .map((t) => (typeof t === "string" ? t : t?.name ?? ""))
      .filter((n): n is string => n.length > 0);
  }
  return Object.keys(tags);
}

// YETI (Your Everyday Threat Intelligence) — self-hosted intel platform. Searches your
// instance's observables for the indicator; a hit means it's tracked threat intel.
// Auth is two-step: exchange the API key for a short-lived JWT, then Bearer it.
export class YetiProvider implements EnrichmentProvider {
  readonly name = "YETI";
  readonly scope = "local" as const;     // your own instance — OPSEC-safe
  private readonly fetchFn: FetchFn;
  private readonly base: string;
  private token?: string;
  constructor(private readonly opts: YetiOptions) {
    this.fetchFn = opts.fetchFn ?? fetch;
    this.base = opts.baseUrl.replace(/\/+$/, "");
  }

  supports(kind: IocKind): boolean { return kind !== "process"; } // hash/ip/domain/url observables

  private signal(): AbortSignal { return AbortSignal.timeout(this.opts.timeoutMs ?? 20_000); }

  // Exchange the API key for a JWT access token (cached until a 401 invalidates it).
  private async accessToken(): Promise<string> {
    if (this.token) return this.token;
    const res = await this.fetchFn(`${this.base}/api/v2/auth/api-token`, {
      method: "POST",
      headers: { "x-yeti-apikey": this.opts.apiKey },
      signal: this.signal(),
    });
    if (res.status === 401 || res.status === 403) throw new Error("YETI auth failed (check DFIR_YETI_KEY)");
    if (!res.ok) throw new Error(`YETI auth HTTP ${res.status}`);
    const token = (await res.json() as { access_token?: string }).access_token;
    if (!token) throw new Error("YETI auth returned no access_token");
    this.token = token;
    return token;
  }

  private async search(value: string, token: string): Promise<Response> {
    return this.fetchFn(`${this.base}/api/v2/observables/search`, {
      method: "POST",
      headers: { authorization: `Bearer ${token}`, "content-type": "application/json" },
      body: JSON.stringify({ query: { value }, count: 5, page: 0 }),
      signal: this.signal(),
    });
  }

  async lookup(_kind: IocKind, value: string): Promise<EnrichmentResult | null> {
    let res = await this.search(value, await this.accessToken());
    if (res.status === 401) { this.token = undefined; res = await this.search(value, await this.accessToken()); } // token expired → refresh once
    if (res.status === 403) throw new Error("YETI access denied");
    if (!res.ok) throw new Error(`YETI HTTP ${res.status}`);

    const json = (await res.json()) as { observables?: YetiObservable[]; total?: number };
    const obs = json.observables ?? [];
    if (obs.length === 0) return null;                          // not tracked in YETI

    const first = obs[0];
    const tags = tagNames(first.tags);
    const malicious = tags.some((t) => MALICIOUS_TAGS.test(t));
    const verdict: Verdict = malicious ? "malicious" : "suspicious"; // present in YETI = at least suspicious
    const contexts = (first.context ?? []).map((c) => String(c.source ?? "")).filter(Boolean);
    const total = json.total ?? obs.length;

    return {
      source: this.name,
      verdict,
      score: `tracked${total > 1 ? ` (${total} matches)` : ""}${contexts.length ? `, sources: ${[...new Set(contexts)].slice(0, 3).join(", ")}` : ""}`,
      tags: tags.slice(0, 6),
      link: first.id ? `${this.base}/observables/${encodeURIComponent(first.id)}` : `${this.base}/observables`,
    };
  }
}
