import type { EnrichmentProvider, EnrichmentResult, FetchFn, IocKind, Verdict } from "./provider.js";

export interface RockyRaccoonOptions {
  apiKey: string;    // et_live_… (Authorization: Bearer)
  fetchFn?: FetchFn;
  timeoutMs?: number;
  baseUrl?: string;
}

interface ProcessProfile {
  process_name?: string;
  classification?: { category?: string; publisher?: string; is_lolbin?: boolean; risk_level?: string; expected_parent?: string };
  intel?: { mitre_techniques?: string[]; suspicious_indicators?: string };
  executions?: { total?: number; confidence?: string };
}

// Result of a parent→child relationship check (Part B: process-chain validation).
export interface ParentChildResult {
  observed: boolean;
  percentage?: number;
  note: string;
  link?: string;
}

function fmtCount(n?: number): string {
  if (!n) return "0";
  if (n >= 1_000_000) return `${(n / 1_000_000).toFixed(1)}M`;
  if (n >= 1_000) return `${(n / 1_000).toFixed(0)}K`;
  return String(n);
}

// RockyRaccoon (echotrail) — Windows process behavioral intelligence over ~346M process
// execution events. Enriches PROCESS-name IOCs with prevalence, classification (LOLBIN /
// risk level / expected parent) and ATT&CK context. Also exposes a parent→child chain
// check used by the process-chain validation pass.
export class RockyRaccoonProvider implements EnrichmentProvider {
  readonly name = "RockyRaccoon";
  readonly scope = "external" as const;
  private readonly fetchFn: FetchFn;
  private readonly base: string;
  constructor(private readonly opts: RockyRaccoonOptions) {
    this.fetchFn = opts.fetchFn ?? fetch;
    this.base = (opts.baseUrl ?? "https://api.rockyraccoon.io").replace(/\/+$/, "");
  }

  supports(kind: IocKind): boolean { return kind === "process"; }

  private headers(): Record<string, string> {
    return { Authorization: `Bearer ${this.opts.apiKey}`, Accept: "application/json" };
  }

  async lookup(kind: IocKind, value: string): Promise<EnrichmentResult | null> {
    if (kind !== "process") return null;
    const name = value.trim().split(/[\\/]/).pop() || value;     // basename, in case a path slipped in
    const res = await this.fetchFn(`${this.base}/v1/process/${encodeURIComponent(name)}`, {
      headers: this.headers(),
      signal: AbortSignal.timeout(this.opts.timeoutMs ?? 20_000),
    });
    if (res.status === 404) {
      // Not in the dataset — uncommon. A real DFIR signal, but not an accusation.
      return { source: this.name, verdict: "unknown", score: "not seen in ~346M events (uncommon process)" };
    }
    if (res.status === 401 || res.status === 403) throw new Error("RockyRaccoon auth/tier error (check DFIR_ROCKYRACCOON_KEY / plan)");
    if (res.status === 429) throw new Error("RockyRaccoon rate/quota limit");
    if (!res.ok) throw new Error(`RockyRaccoon HTTP ${res.status}`);

    const p = (await res.json()) as ProcessProfile;
    const cls = p.classification ?? {};
    const risk = (cls.risk_level ?? "").toLowerCase();
    // A process PROFILE describes the process TYPE, not whether this instance is evil:
    // flag LOLBINs and higher-risk types for scrutiny, mark common low-risk ones benign.
    const verdict: Verdict = cls.is_lolbin || risk === "high" || risk === "medium" ? "suspicious"
      : risk === "low" ? "harmless" : "unknown";

    const tags = new Set<string>();
    if (cls.category) tags.add(cls.category);
    if (cls.is_lolbin) tags.add("LOLBIN");
    for (const t of (p.intel?.mitre_techniques ?? []).slice(0, 5)) tags.add(t);

    const bits: string[] = [];
    if (risk) bits.push(`risk: ${risk}`);
    if (p.executions?.total != null) bits.push(`${fmtCount(p.executions.total)} executions`);
    if (cls.expected_parent) bits.push(`expected parent ${cls.expected_parent}`);

    return {
      source: this.name,
      verdict,
      score: bits.join(", ") || undefined,
      detections: p.executions?.total,
      tags: [...tags],
    };
  }

  // GET /v1/parent-child — has this parent→child relationship been observed?
  async checkParentChild(parent: string, child: string): Promise<ParentChildResult | null> {
    const p = parent.trim().split(/[\\/]/).pop() || parent;
    const c = child.trim().split(/[\\/]/).pop() || child;
    if (!p || !c) return null;
    const url = `${this.base}/v1/parent-child?parent=${encodeURIComponent(p)}&child=${encodeURIComponent(c)}`;
    const res = await this.fetchFn(url, { headers: this.headers(), signal: AbortSignal.timeout(this.opts.timeoutMs ?? 20_000) });
    if (res.status === 404) return { observed: false, note: `${p} → ${c} not seen; child '${c}' is unknown to the dataset` };
    if (res.status === 401 || res.status === 403) throw new Error("RockyRaccoon auth/tier error");
    if (res.status === 429) throw new Error("RockyRaccoon rate/quota limit");
    if (!res.ok) throw new Error(`RockyRaccoon HTTP ${res.status}`);

    const j = (await res.json()) as { observed?: boolean; percentage?: number; common_parents?: Array<{ parent?: string; percentage?: number }> };
    if (j.observed) {
      return { observed: true, percentage: j.percentage, note: `${p} → ${c} observed (${(j.percentage ?? 0).toFixed(1)}% of ${c} executions)` };
    }
    const usual = (j.common_parents ?? []).slice(0, 2).map((x) => x.parent).filter(Boolean).join(", ");
    return { observed: false, note: `${p} → ${c} NOT observed${usual ? `; ${c} usually spawned by ${usual}` : ""}` };
  }
}
