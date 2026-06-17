import { promises as dnsPromises } from "node:dns";
import type { EnrichmentProvider, EnrichmentResult, IocKind } from "./provider.js";

// Reverse DNS (PTR) lookup for an IP IOC — resolves the address back to its hostname(s)
// (e.g. 8.8.8.8 → dns.google), which often unmasks the hosting provider / CDN behind an
// attacker IP. Pure infrastructure CONTEXT, not a reputation verdict, so the result is
// always `unknown`; the hostnames ride along in `score`/`tags`. Uses the system resolver
// (whatever the box is configured to use — NOT a hardcoded public one, to avoid leaking the
// queried IP to a third party the analyst didn't choose). Injectable for tests.
export type DnsReverseFn = (ip: string) => Promise<string[]>;

export interface ReverseDnsOptions {
  resolve?: DnsReverseFn;   // injected in tests; default = node:dns reverse()
  timeoutMs?: number;       // per-lookup ceiling (default 8s)
}

// Resolver error codes that mean "this IP simply has no PTR record" — a definitive MISS we
// want cached (so we don't re-query it), NOT a transient failure to retry.
const NO_RECORD_CODES = new Set(["ENOTFOUND", "ENODATA", "NOTFOUND", "NXDOMAIN", "SERVFAIL"]);

export class ReverseDnsProvider implements EnrichmentProvider {
  readonly name = "Reverse DNS";
  readonly scope = "external" as const;
  private readonly resolve: DnsReverseFn;
  private readonly timeoutMs: number;

  constructor(opts: ReverseDnsOptions = {}) {
    this.resolve = opts.resolve ?? ((ip) => dnsPromises.reverse(ip));
    this.timeoutMs = opts.timeoutMs ?? 8_000;
  }

  supports(kind: IocKind): boolean { return kind === "ip"; }

  async lookup(kind: IocKind, value: string): Promise<EnrichmentResult | null> {
    if (kind !== "ip") return null;
    let hosts: string[];
    try {
      hosts = await this.withTimeout(this.resolve(value));
    } catch (err) {
      // No PTR record → a real "checked, nothing" miss (return null, gets cached).
      // Anything else (timeout, network down) → throw so it isn't cached as checked and a
      // later run retries it.
      const code = (err as NodeJS.ErrnoException).code;
      if (code && NO_RECORD_CODES.has(code)) return null;
      throw err;
    }
    const clean = (hosts ?? []).map((h) => h.trim()).filter(Boolean);
    if (clean.length === 0) return null;
    return {
      source: this.name,
      verdict: "unknown",
      score: clean.length === 1 ? clean[0] : `${clean.length} hostnames`,
      tags: clean.slice(0, 5),
    };
  }

  private withTimeout<T>(p: Promise<T>): Promise<T> {
    return Promise.race([
      p,
      new Promise<T>((_, reject) =>
        setTimeout(() => reject(new Error(`Reverse DNS timed out after ${this.timeoutMs}ms`)), this.timeoutMs),
      ),
    ]);
  }
}
