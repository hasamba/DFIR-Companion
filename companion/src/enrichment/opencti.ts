import type { DetailedLookup, EnrichmentProvider, EnrichmentResult, FetchFn, IocKind } from "./provider.js";
import { readBoundedJson, RESPONSE_SIZE_LIMITS } from "../providers/boundedResponse.js";
import { boundOrigins } from "../analysis/intelLineage.js";

export interface OpenCtiOptions {
  baseUrl: string; // your OpenCTI instance, e.g. https://opencti.example.org
  apiKey: string; // OpenCTI API token (Settings → your profile)
  fetchFn?: FetchFn;
  timeoutMs?: number;
  maliciousScore?: number; // x_opencti_score >= this → malicious (default 75)
}

interface OctiLabel {
  value?: string;
}
// A linked indicator (#1024): validity, revocation and score live HERE, not on the observable;
// several indicators can link one observable with different validity — one assertion each.
interface OctiIndicator {
  id?: string;
  name?: string;
  valid_from?: string | null;
  valid_until?: string | null;
  revoked?: boolean | null;
  x_opencti_score?: number | null;
  created?: string | null;
  pattern_type?: string | null;
}
interface OctiObservable {
  id?: string;
  entity_type?: string;
  observable_value?: string;
  x_opencti_score?: number | null;
  objectLabel?: OctiLabel[];
  indicators?: {
    edges?: Array<{ node?: OctiIndicator }>;
    pageInfo?: { endCursor?: string | null; hasNextPage?: boolean };
  };
  createdBy?: { name?: string } | null; // who created the object on this instance (#933 item 18)
}

// The observable's remaining indicator pages, by its id (#1024): read to a bound, merged by id.
const INDICATOR_PAGES_MAX = 8;
const INDICATORS_QUERY = `query($id: String!, $first: Int!, $after: ID) {
  stixCyberObservable(id: $id) {
    indicators(first: $first, after: $after) {
      edges { node { id name valid_from valid_until revoked x_opencti_score created pattern_type } }
      pageInfo { endCursor hasNextPage }
    }
  }
}`;
interface GraphQlResponse<T> {
  data?: T;
  errors?: Array<{ message?: string }>;
}

// Labels that mark an observable as known-bad (vs merely tracked). Mirrors YETI's check.
const MALICIOUS_LABELS =
  /\b(malware|malicious|c2|c&c|botnet|trojan|ransom\w*|phishing|exploit|apt|backdoor|stealer)\b/i;

const DEFAULT_MALICIOUS_SCORE = 75;

// One query: find observables matching the IOC value, with their score, labels, and the COUNT
// of linked detection indicators. `search` is OpenCTI's full-text match across observable types
// (IPv4-Addr / Domain-Name / Url / StixFile hashes).
// Paginated (#1024): the search is full-text and may rank near matches first, so the pages are
// read until the exact value is found or the bound is reached; a bound reached without the exact
// value is an INCOMPLETE search — never a miss. The indicators connection is read with its own
// bound and `hasNextPage` records whether it was cut.
const OBSERVABLE_PAGE = 50;
const OBSERVABLE_PAGES_MAX = 8;
const INDICATORS_MAX = 64;
const OBSERVABLE_QUERY = `query($search: String!, $first: Int!, $after: ID, $indicators: Int!) {
  stixCyberObservables(search: $search, first: $first, after: $after) {
    edges { node {
      id
      entity_type
      observable_value
      x_opencti_score
      objectLabel { value }
      indicators(first: $indicators) {
        edges { node { id name valid_from valid_until revoked x_opencti_score created pattern_type } }
        pageInfo { endCursor hasNextPage }
      }
      createdBy { name }
    } }
    pageInfo { endCursor hasNextPage }
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
  readonly scope = "local" as const; // your own instance — OPSEC-safe
  private readonly fetchFn: FetchFn;
  private readonly base: string;
  private readonly maliciousScore: number;
  constructor(private readonly opts: OpenCtiOptions) {
    this.fetchFn = opts.fetchFn ?? fetch;
    this.base = opts.baseUrl.replace(/\/+$/, "");
    this.maliciousScore = opts.maliciousScore ?? DEFAULT_MALICIOUS_SCORE;
  }

  supports(kind: IocKind): boolean {
    return kind !== "process";
  } // hash/ip/domain/url observables

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
    if (res.status === 401 || res.status === 403)
      throw new Error("OpenCTI auth failed (check DFIR_OPENCTI_KEY)");
    if (!res.ok) throw new Error(`OpenCTI HTTP ${res.status}`);
    const json = await readBoundedJson<GraphQlResponse<T>>(res, {
      maxBytes: RESPONSE_SIZE_LIMITS.json,
      context: "OpenCTI",
    });
    if (json.errors && json.errors.length > 0) {
      throw new Error(`OpenCTI GraphQL error: ${json.errors[0]?.message ?? "unknown"}`);
    }
    if (!json.data) throw new Error("OpenCTI returned no data");
    return json.data;
  }

  /** The exact observable, its indicators, and whether the search or the indicators were cut. */
  private async findObservable(
    value: string,
  ): Promise<{ node: OctiObservable | null; searchIncomplete: boolean }> {
    const lower = value.toLowerCase();
    let after: string | undefined;
    for (let page = 0; page < OBSERVABLE_PAGES_MAX; page += 1) {
      const data = await this.graphql<{
        stixCyberObservables?: {
          edges?: Array<{ node?: OctiObservable }>;
          pageInfo?: { endCursor?: string | null; hasNextPage?: boolean };
        };
      }>(OBSERVABLE_QUERY, { search: value, first: OBSERVABLE_PAGE, after, indicators: INDICATORS_MAX });
      const nodes = (data.stixCyberObservables?.edges ?? [])
        .map((e) => e.node)
        .filter((n): n is OctiObservable => !!n);
      // `search` is full-text and may return near matches. Only an exact value match is THIS
      // indicator's record; a near match's score, labels and creator belong to some other object
      // and must not be attached here (#933 item 18).
      const node = nodes.find((n) => (n.observable_value ?? "").toLowerCase() === lower);
      if (node) return { node, searchIncomplete: false };
      const info = data.stixCyberObservables?.pageInfo;
      if (!info?.hasNextPage || !info.endCursor || nodes.length === 0)
        return { node: null, searchIncomplete: false };
      after = info.endCursor;
    }
    return { node: null, searchIncomplete: true };
  }

  /** Every indicator linked to the observable, across pages up to the bound; `indicatorsCut` when the bound was reached first. */
  private async allIndicators(
    node: OctiObservable,
  ): Promise<{ indicators: OctiIndicator[]; indicatorsCut: boolean }> {
    const byId = new Map<string, OctiIndicator>();
    const add = (list: Array<{ node?: OctiIndicator }> | undefined) => {
      for (const e of list ?? []) if (e.node) byId.set(e.node.id ?? `#${byId.size}`, e.node);
    };
    add(node.indicators?.edges);
    let info = node.indicators?.pageInfo;
    let pages = 1;
    while (info?.hasNextPage && info.endCursor && node.id && pages < INDICATOR_PAGES_MAX) {
      const data = await this.graphql<{
        stixCyberObservable?: {
          indicators?: {
            edges?: Array<{ node?: OctiIndicator }>;
            pageInfo?: { endCursor?: string | null; hasNextPage?: boolean };
          };
        };
      }>(INDICATORS_QUERY, { id: node.id, first: INDICATORS_MAX, after: info.endCursor });
      add(data.stixCyberObservable?.indicators?.edges);
      info = data.stixCyberObservable?.indicators?.pageInfo;
      pages += 1;
    }
    return { indicators: [...byId.values()], indicatorsCut: info?.hasNextPage === true };
  }

  async lookup(kind: IocKind, value: string): Promise<EnrichmentResult[] | null> {
    const { results, backends } = await this.lookupDetailed(kind, value);
    if (backends[0]?.outcome === "error") throw new Error(backends[0].detail ?? "OpenCTI: incomplete search");
    return results.length ? results : null;
  }

  /**
   * One assertion per linked indicator (its own id, validity `[valid_from, valid_until)`,
   * `revoked`, score, `created` = object creation), plus the observable itself as a "known
   * observable" assertion when no indicator links it. A search cut by the bound before the exact
   * value was found is reported INCOMPLETE: no absence may be concluded from it (#1024).
   */
  async lookupDetailed(_kind: IocKind, value: string): Promise<DetailedLookup> {
    const { node, searchIncomplete } = await this.findObservable(value);
    if (!node)
      return searchIncomplete
        ? {
            results: [],
            backends: [
              {
                name: this.name,
                outcome: "error",
                detail: "OpenCTI: search bound reached before the exact value was found",
                incomplete: true,
              },
            ],
          }
        : { results: [], backends: [{ name: this.name, outcome: "miss" }] };

    const labels = (node.objectLabel ?? []).map((l) => l.value ?? "").filter((v) => v.length > 0);
    const { indicators, indicatorsCut } = await this.allIndicators(node);
    const observableScore = typeof node.x_opencti_score === "number" ? node.x_opencti_score : undefined;
    const labelMalicious = labels.some((l) => MALICIOUS_LABELS.test(l));
    const lineage = { originKind: "relay" as const, ...boundOrigins([node.createdBy?.name]) };
    const observableLink = node.id
      ? `${this.base}/dashboard/observations/observables/${encodeURIComponent(node.id)}`
      : `${this.base}/dashboard/observations/observables`;
    const results: EnrichmentResult[] = [];
    for (const ind of indicators) {
      const score = typeof ind.x_opencti_score === "number" ? ind.x_opencti_score : observableScore;
      const malicious = (score !== undefined && score >= this.maliciousScore) || labelMalicious;
      const validity = {
        ...(ind.valid_from ? { from: ind.valid_from } : {}),
        ...(ind.valid_until ? { until: ind.valid_until } : {}),
      };
      const parts = [
        score !== undefined ? `score ${score}/100` : "indicator",
        ind.name ? `"${ind.name.slice(0, 60)}"` : "",
        ind.valid_until ? `valid until ${ind.valid_until.slice(0, 10)}` : "no valid_until",
        ind.revoked ? "revoked" : "",
      ].filter(Boolean);
      results.push({
        source: this.name,
        ...lineage,
        verdict: malicious ? "malicious" : "suspicious",
        score: parts.join(", "),
        tags: labels.slice(0, 6),
        link: ind.id
          ? `${this.base}/dashboard/observations/indicators/${encodeURIComponent(ind.id)}`
          : observableLink,
        ...(ind.id ? { providerRecordId: ind.id } : {}),
        ...(Object.keys(validity).length ? { validity } : {}),
        ...(ind.revoked ? { revoked: true } : {}),
        ...(ind.created
          ? { temporal: { createdAt: ind.created, ...(indicatorsCut ? { truncated: true } : {}) } }
          : indicatorsCut
            ? { temporal: { truncated: true } }
            : {}),
      });
    }
    if (results.length === 0) {
      const malicious =
        (observableScore !== undefined && observableScore >= this.maliciousScore) || labelMalicious;
      results.push({
        source: this.name,
        ...lineage,
        verdict: malicious ? "malicious" : "suspicious",
        score: `${observableScore !== undefined ? `score ${observableScore}/100` : "known observable"}${labels.length ? `, ${labels.length} label(s)` : ""}, no linked indicator`,
        detections: 0,
        tags: labels.slice(0, 6),
        link: observableLink,
        ...(node.id ? { providerRecordId: node.id } : {}),
      });
    }
    return {
      results,
      backends: [
        {
          name: this.name,
          outcome: "hit",
          ...(indicatorsCut ? { incomplete: true, detail: `indicators cut at ${INDICATORS_MAX}` } : {}),
        },
      ],
    };
  }
}
