import type { EnrichmentProvider, EnrichmentResult, FetchFn, IocKind, Verdict } from "./provider.js";

export interface OpenCtiOptions {
  baseUrl: string;          // your OpenCTI instance, e.g. https://opencti.example.org
  apiKey: string;           // OpenCTI API token (Settings → your profile)
  fetchFn?: FetchFn;
  timeoutMs?: number;
  maliciousScore?: number;  // x_opencti_score >= this → malicious (default 75)
}

interface OctiLabel { value?: string }
interface OctiObservable {
  id?: string;
  entity_type?: string;
  observable_value?: string;
  x_opencti_score?: number | null;
  objectLabel?: OctiLabel[];
  indicators?: { edges?: Array<{ node?: { id?: string } }> };
}
interface GraphQlResponse<T> {
  data?: T;
  errors?: Array<{ message?: string }>;
}

// Labels that mark an observable as known-bad (vs merely tracked). Mirrors YETI's check.
const MALICIOUS_LABELS = /\b(malware|malicious|c2|c&c|botnet|trojan|ransom\w*|phishing|exploit|apt|backdoor|stealer)\b/i;

const DEFAULT_MALICIOUS_SCORE = 75;

// One query: find observables matching the IOC value, with their score, labels, and the COUNT
// of linked detection indicators. `search` is OpenCTI's full-text match across observable types
// (IPv4-Addr / Domain-Name / Url / StixFile hashes).
const OBSERVABLE_QUERY = `query($search: String!) {
  stixCyberObservables(search: $search, first: 5) {
    edges { node {
      id
      entity_type
      observable_value
      x_opencti_score
      objectLabel { value }
      indicators { edges { node { id } } }
    } }
  }
}`;

// Cheap auth + reachability check that sends no indicator.
const PROBE_QUERY = `query { me { id name } }`;

// OpenCTI (open-source CTI platform) — self-hosted. Searches your instance's stix cyber
// observables for the indicator value; a hit means it's tracked threat intel on that instance.
// Auth is a static API token (Bearer); the transport is GraphQL (POST <base>/graphql), which
// returns 200-with-errors[] for query/permission failures — so we inspect BOTH the HTTP status
// AND the GraphQL errors array.
export class OpenCtiProvider implements EnrichmentProvider {
  readonly name = "OpenCTI";
  readonly scope = "local" as const;     // your own instance — OPSEC-safe
  private readonly fetchFn: FetchFn;
  private readonly base: string;
  private readonly maliciousScore: number;
  constructor(private readonly opts: OpenCtiOptions) {
    this.fetchFn = opts.fetchFn ?? fetch;
    this.base = opts.baseUrl.replace(/\/+$/, "");
    this.maliciousScore = opts.maliciousScore ?? DEFAULT_MALICIOUS_SCORE;
  }

  supports(kind: IocKind): boolean { return kind !== "process"; } // hash/ip/domain/url observables

  // Cheap reachability + auth check: `me { id name }` requires a valid token but sends no
  // indicator. Throws on unreachable / bad token, gating us from query-storming a dead instance.
  async probe(): Promise<void> {
    await this.graphql<{ me?: { id?: string } }>(PROBE_QUERY);
  }

  private async graphql<T>(query: string, variables?: Record<string, unknown>): Promise<T> {
    const res = await this.fetchFn(`${this.base}/graphql`, {
      method: "POST",
      headers: {
        authorization: `Bearer ${this.opts.apiKey}`,
        "content-type": "application/json",
        accept: "application/json",
      },
      body: JSON.stringify({ query, variables }),
      signal: AbortSignal.timeout(this.opts.timeoutMs ?? 20_000),
    });
    if (res.status === 401 || res.status === 403) throw new Error("OpenCTI auth failed (check DFIR_OPENCTI_KEY)");
    if (!res.ok) throw new Error(`OpenCTI HTTP ${res.status}`);
    const json = (await res.json()) as GraphQlResponse<T>;
    if (json.errors && json.errors.length > 0) {
      throw new Error(`OpenCTI GraphQL error: ${json.errors[0]?.message ?? "unknown"}`);
    }
    if (!json.data) throw new Error("OpenCTI returned no data");
    return json.data;
  }

  async lookup(_kind: IocKind, value: string): Promise<EnrichmentResult | null> {
    const data = await this.graphql<{ stixCyberObservables?: { edges?: Array<{ node?: OctiObservable }> } }>(
      OBSERVABLE_QUERY,
      { search: value },
    );
    const nodes = (data.stixCyberObservables?.edges ?? [])
      .map((e) => e.node)
      .filter((n): n is OctiObservable => !!n);
    if (nodes.length === 0) return null;                       // not tracked in OpenCTI

    // `search` is full-text and may return near matches — prefer an exact value match, else first.
    const lower = value.toLowerCase();
    const node = nodes.find((n) => (n.observable_value ?? "").toLowerCase() === lower) ?? nodes[0];

    const labels = (node.objectLabel ?? [])
      .map((l) => l.value ?? "")
      .filter((v) => v.length > 0);
    const indicatorCount = node.indicators?.edges?.length ?? 0;
    const score = typeof node.x_opencti_score === "number" ? node.x_opencti_score : undefined;
    const malicious =
      (score !== undefined && score >= this.maliciousScore) ||
      labels.some((l) => MALICIOUS_LABELS.test(l));
    const verdict: Verdict = malicious ? "malicious" : "suspicious"; // present in OpenCTI = at least suspicious

    const parts: string[] = [];
    parts.push(score !== undefined ? `score ${score}/100` : "known observable");
    if (labels.length > 0) parts.push(`${labels.length} label(s)`);
    if (indicatorCount > 0) parts.push(`${indicatorCount} linked indicator(s)`);

    return {
      source: this.name,
      verdict,
      score: parts.join(", "),
      detections: indicatorCount,
      tags: labels.slice(0, 6),
      link: node.id
        ? `${this.base}/dashboard/observations/observables/${encodeURIComponent(node.id)}`
        : `${this.base}/dashboard/observations/observables`,
    };
  }
}
