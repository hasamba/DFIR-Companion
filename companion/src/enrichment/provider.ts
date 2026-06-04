// Threat-intel enrichment providers (VirusTotal, MalwareBazaar, AbuseIPDB…). Like the
// AI providers, each takes an injectable fetchFn so tests never hit the network, and is
// configured from env (DFIR_VT_KEY etc.). A provider looks up ONE indicator and returns
// a normalized verdict, or null when the indicator is unknown to that source.

export type IocKind = "hash" | "ip" | "domain" | "url";
export type Verdict = "malicious" | "suspicious" | "harmless" | "unknown";

export interface EnrichmentResult {
  source: string;
  verdict: Verdict;
  score?: string;
  detections?: number;
  total?: number;
  tags?: string[];
  link?: string;
}

export interface EnrichmentProvider {
  readonly name: string;
  supports(kind: IocKind): boolean;
  // Resolve to a result, or null if the indicator isn't found / no data. Throws only on
  // hard errors (auth, rate limit) so the service can react (skip / back off).
  lookup(kind: IocKind, value: string): Promise<EnrichmentResult | null>;
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
    default: return undefined;
  }
}
