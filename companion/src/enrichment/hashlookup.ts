import type { EnrichmentProvider, EnrichmentResult, FetchFn, IocKind, Verdict } from "./provider.js";

// CIRCL hashlookup (https://www.circl.lu/services/hashlookup/) — a large, free, keyless
// KNOWN-FILE database (NSRL-derived corpus + Linux distro packages + more). For DFIR this is
// the *known-good* angle that complements VirusTotal / Hunting.ch: a hit confirms a hash
// belongs to a known, legitimate file, cutting false positives. (It is distinct from the bulk
// NSRL auto-legitimate feature: this is a per-IOC enrichment BADGE with file/source/trust.)
//
// API: GET https://hashlookup.circl.lu/lookup/{md5|sha1|sha256}/{hash}
//   200 → known (JSON record), 404 → unknown, 400 → bad hash format. No auth, best-effort.
// `external` scope: sending a hash to circl.lu reveals what you're investigating, so it's
// opt-in per case (default OFF) like the other keyless external providers. Injectable fetchFn
// so tests never hit the network; base URL overridable for a self-hosted / air-gapped mirror.
export interface HashlookupOptions {
  baseUrl?: string;        // default https://hashlookup.circl.lu
  fetchFn?: FetchFn;
  timeoutMs?: number;
  trustThreshold?: number; // hashlookup:trust >= this → harmless (default 50, the documented split)
}

const DEFAULT_BASE = "https://hashlookup.circl.lu";
const DEFAULT_TRUST_THRESHOLD = 50;

// hashlookup keys on md5 / sha1 / sha256, picked from the value's length. A value that isn't
// one of those (a path, a partial hash, "process" text) is not enrichable here → skip.
function hashType(value: string): "md5" | "sha1" | "sha256" | undefined {
  const h = value.trim().toLowerCase();
  if (!/^[0-9a-f]+$/.test(h)) return undefined;
  if (h.length === 32) return "md5";
  if (h.length === 40) return "sha1";
  if (h.length === 64) return "sha256";
  return undefined;
}

// Some hashlookup records (e.g. from a blocklist source) carry a KnownMalicious marker. Treat
// any truthy, non-"false" value as a malicious signal — defensive, since a "known" hash can
// still be malware in context.
function isKnownMalicious(v: unknown): boolean {
  if (v === true) return true;
  if (typeof v === "number") return v !== 0;
  if (typeof v === "string") {
    const s = v.trim().toLowerCase();
    return s !== "" && s !== "false" && s !== "0" && s !== "no";
  }
  return false;
}

export class HashlookupProvider implements EnrichmentProvider {
  readonly name = "Hashlookup";
  readonly scope = "external" as const;
  private readonly base: string;
  private readonly fetchFn: FetchFn;
  private readonly trustThreshold: number;
  constructor(private readonly opts: HashlookupOptions = {}) {
    this.base = (opts.baseUrl?.trim() || DEFAULT_BASE).replace(/\/+$/, "");
    this.fetchFn = opts.fetchFn ?? fetch;
    this.trustThreshold = opts.trustThreshold ?? DEFAULT_TRUST_THRESHOLD;
  }

  supports(kind: IocKind): boolean { return kind === "hash"; }

  async lookup(kind: IocKind, value: string): Promise<EnrichmentResult | null> {
    if (kind !== "hash") return null;
    const type = hashType(value);
    if (!type) return null;
    const hash = value.trim().toLowerCase();
    const url = `${this.base}/lookup/${type}/${hash}`;

    const res = await this.fetchFn(url, {
      headers: { Accept: "application/json", "User-Agent": "DFIR-Companion" },
      signal: AbortSignal.timeout(this.opts.timeoutMs ?? 20_000),
    });
    // Unknown hash (404) or malformed (400) → a clean miss, cached as "checked, nothing".
    if (res.status === 404 || res.status === 400) return null;
    if (res.status === 429) throw new Error("Hashlookup rate limit");
    if (!res.ok) throw new Error(`Hashlookup HTTP ${res.status}`);

    const json = (await res.json()) as Record<string, unknown>;
    if (!json || typeof json !== "object" || Array.isArray(json)) return null;

    const fileName = typeof json.FileName === "string" ? json.FileName.trim() : "";
    const source = typeof json.source === "string" ? json.source.trim()
      : typeof json.db === "string" ? (json.db as string).trim() : "";
    const trustRaw = json["hashlookup:trust"];
    const trust = typeof trustRaw === "number" ? trustRaw : Number(trustRaw);
    const hasTrust = Number.isFinite(trust);

    let verdict: Verdict;
    if (isKnownMalicious(json.KnownMalicious)) verdict = "malicious";
    else if (hasTrust && trust >= this.trustThreshold) verdict = "harmless";   // known good
    else verdict = "unknown";                                                  // known file, legitimacy not asserted

    const tags: string[] = [];
    if (source) tags.push(source);
    if (hasTrust) tags.push(`trust ${trust}`);

    const score = (verdict === "malicious" ? "known malicious" : "known file") + (fileName ? `: ${fileName}` : "");

    return { source: this.name, verdict, score, tags, link: url };
  }
}
