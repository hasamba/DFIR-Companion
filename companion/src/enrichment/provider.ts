// Threat-intel enrichment providers (VirusTotal, MalwareBazaar, AbuseIPDB…). Like the
// AI providers, each takes an injectable fetchFn so tests never hit the network, and is
// configured from env (DFIR_VT_KEY etc.). A provider looks up ONE indicator and returns
// a normalized verdict, or null when the indicator is unknown to that source.

export type IocKind = "hash" | "ip" | "domain" | "url" | "process";
export type Verdict = "malicious" | "suspicious" | "harmless" | "unknown";

export interface EnrichmentResult {
  source: string;
  verdict: Verdict;
  score?: string;
  detections?: number;
  total?: number;
  tags?: string[];
  link?: string;
  // Geo context (set only by GeoIpProvider, #133). Optional so other providers are unaffected;
  // carried onto the stored IocEnrichment by enrichService's spread, then read by the geo map.
  lat?: number;
  lon?: number;
  country?: string;
  city?: string;
}

// "local" = the analyst's OWN self-hosted instance (MISP / YETI) — querying it does NOT
// leak indicators off-box, so it's OPSEC-safe and enabled by default. "external" = a
// third-party SaaS (VirusTotal, MalwareBazaar, AbuseIPDB, RockyRaccoon) — sending an
// indicator there can tip off an adversary, so it's opt-in per case.
export type ProviderScope = "local" | "external";

export interface EnrichmentProvider {
  readonly name: string;
  readonly scope: ProviderScope;
  supports(kind: IocKind): boolean;
  // Resolve to a result, or null if the indicator isn't found / no data. Throws only on
  // hard errors (auth, rate limit) so the service can react (skip / back off). A provider
  // that fans out across several back-ends (e.g. Hunting.ch → MalwareBazaar/ThreatFox/URLhaus/
  // YARAify) may return an ARRAY of results — one per back-end that has a hit — and they show
  // as separate badges. An empty array means "checked, nothing found" (same as null).
  lookup(kind: IocKind, value: string): Promise<EnrichmentResult | EnrichmentResult[] | null>;
  // OPTIONAL reachability check: a cheap request that verifies the server is up and auth
  // works WITHOUT sending a real indicator. Resolves when reachable; throws (like lookup)
  // when the server is unreachable / auth is broken. Used to gate sending hundreds of IOCs
  // at a dead self-hosted instance (MISP / YETI). A provider that omits it is treated as
  // always up — so external SaaS keep their existing per-call error handling.
  probe?(): Promise<void>;
}

export type FetchFn = typeof fetch;

// Map our IOC.type union to an enrichable kind (or undefined when not enrichable —
// file paths, process names, "other" can't be looked up by value).
export function iocKind(type: string): IocKind | undefined {
  switch (type) {
    case "hash": return "hash";
    case "ip": return "ip";
    case "domain": return "domain";
    case "url": return "url";
    case "process": return "process";
    default: return undefined;
  }
}

// Thrown by a provider on HTTP 429 instead of a plain Error, so callers can distinguish
// "back off and retry" from a hard failure (auth, network) that should surface immediately.
// Carries the server's Retry-After (parsed to ms) when it sent one.
export class RateLimitError extends Error {
  readonly retryAfterMs?: number;
  constructor(message: string, retryAfterMs?: number) {
    super(message);
    this.name = "RateLimitError";
    this.retryAfterMs = retryAfterMs;
  }
}

// Retry-After is either a whole number of seconds, or an HTTP-date. Returns ms, or undefined
// when absent/unparseable (caller falls back to its own backoff schedule).
export function parseRetryAfterMs(header: string | null | undefined, nowMs = Date.now()): number | undefined {
  if (!header) return undefined;
  const seconds = Number(header);
  if (Number.isFinite(seconds)) return Math.max(0, seconds * 1000);
  const at = Date.parse(header);
  return Number.isNaN(at) ? undefined : Math.max(0, at - nowMs);
}

export interface RetryPolicy {
  retries?: number;       // additional attempts after the first (default 2)
  backoffMs?: number;     // base backoff before the first retry (default 1000, doubles each attempt)
  maxBackoffMs?: number;  // cap on the computed backoff, before jitter (default 30_000)
}

export interface RetryRunOptions extends RetryPolicy {
  sleep?: (ms: number) => Promise<void>;  // injectable delay (tests pass a no-op)
  random?: () => number;                  // injectable jitter source (default Math.random), returns [0, 1)
}

// Retries `fn` when it throws a RateLimitError, waiting the server's Retry-After if it gave
// one, else an exponential backoff — with a bit of jitter either way so parallel callers
// hitting the same limit don't all retry in lockstep. Any other error (auth, network, a
// provider's plain "not found") is NOT retried — it should surface to the caller immediately.
export async function withRateLimitRetry<T>(fn: () => Promise<T>, opts: RetryRunOptions = {}): Promise<T> {
  const retries = opts.retries ?? 2;
  const backoffMs = opts.backoffMs ?? 1000;
  const maxBackoffMs = opts.maxBackoffMs ?? 30_000;
  const sleep = opts.sleep ?? ((ms: number) => new Promise<void>((r) => setTimeout(r, ms)));
  const random = opts.random ?? Math.random;

  let attempt = 0;
  for (;;) {
    try {
      return await fn();
    } catch (err) {
      if (!(err instanceof RateLimitError) || attempt >= retries) throw err;
      const base = err.retryAfterMs ?? Math.min(maxBackoffMs, backoffMs * 2 ** attempt);
      const jitter = base * 0.2 * random();   // 0–20% extra, never below the requested wait
      await sleep(Math.round(base + jitter));
      attempt++;
    }
  }
}
