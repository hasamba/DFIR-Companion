import type { EnrichmentProvider, EnrichmentResult, IocKind } from "./provider.js";
import { detectLookalike, type LookalikeKind } from "../analysis/lookalikeDomains.js";

// Offline lookalike / typosquat domain check (the deterministic counterpart to Timesketch's
// phishy_domains analyzer). Compares each domain IOC's registrable form against a bundled list of
// commonly-impersonated brands (+ DFIR_LOOKALIKE_EXTRA_DOMAINS) using homoglyph-skeleton, edit
// distance, and brand-token impersonation — see analysis/lookalikeDomains.ts.
//
// scope = "local": it runs entirely on-box (no network, nothing sent anywhere), so it is OPSEC-safe
// and enabled by DEFAULT — every case gets lookalike flagging with zero configuration. A hit is
// SUSPICIOUS (drives Medium), never malicious.
const TAG_FOR_KIND: Record<LookalikeKind, string> = {
  homoglyph: "Homoglyph domain",
  typosquat: "Typosquat domain",
  impersonation: "Brand impersonation",
};

export class LookalikeDomainProvider implements EnrichmentProvider {
  readonly name = "Lookalike Domain";
  readonly scope = "local" as const;

  supports(kind: IocKind): boolean {
    return kind === "domain";
  }

  // Synchronous logic wrapped in a Promise to satisfy the async provider contract. Returns a
  // suspicious verdict when the domain imitates a watched brand, else null ("checked, clean").
  async lookup(kind: IocKind, value: string): Promise<EnrichmentResult | null> {
    if (kind !== "domain") return null;
    const v = detectLookalike(value);
    if (!v) return null;
    return {
      source: this.name,
      verdict: "suspicious",
      score: v.note,
      tags: [TAG_FOR_KIND[v.kind], `similar to ${v.brand}`],
    };
  }
}
