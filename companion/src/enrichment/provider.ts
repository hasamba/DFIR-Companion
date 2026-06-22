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
