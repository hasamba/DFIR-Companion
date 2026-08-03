/**
 * Threat-intel enrichment and customer-exposure provider factories, built from env (#416).
 *
 * Sibling to composition/integrationClients.ts and composition/aiProviders.ts, and the same kind of
 * code: presence of a key IS the opt-in, so each `if` here is a feature flag. Kept in its own file
 * rather than folded into aiProviders.ts because these are the OUTBOUND-lookup providers, a
 * different set of credentials and a different failure mode (a down self-hosted MISP is routine —
 * see the reachability gate in enrichment/providerHealth.ts).
 *
 * Called at startup AND at runtime: POST /settings/reload rebuilds the enrichment set through
 * rebuildForPrefix so a just-saved key applies without the #1-gotcha restart.
 */
import type { EnrichmentProvider } from "../enrichment/provider.js";
import { VirusTotalProvider } from "../enrichment/virustotal.js";
import { HuntingChProvider } from "../enrichment/huntingch.js";
import { CrowdStrikeProvider } from "../enrichment/crowdstrike.js";
import { AbuseIpdbProvider } from "../enrichment/abuseipdb.js";
import { MispProvider } from "../enrichment/misp.js";
import { RockyRaccoonProvider } from "../enrichment/rockyraccoon.js";
import { YetiProvider } from "../enrichment/yeti.js";
import { OpenCtiProvider } from "../enrichment/opencti.js";
import { ReverseDnsProvider } from "../enrichment/reverseDns.js";
import { LookalikeDomainProvider } from "../enrichment/lookalikeDomain.js";
import { RdapProvider } from "../enrichment/rdap.js";
import { GeoIpProvider } from "../enrichment/geoip.js";
import { ShodanProvider } from "../enrichment/shodan.js";
import { HashlookupProvider } from "../enrichment/hashlookup.js";
import type { CustomerExposureProvider } from "../analysis/customerExposure.js";
import {
  DeHashedExposureProvider,
  HaveIBeenPwnedExposureProvider,
  LeakCheckExposureProvider,
  ShodanExposureProvider,
} from "../integrations/customerExposureProviders.js";
import { tlsFetchFor } from "./tlsFetch.js";

// Build the threat-intel enrichment providers from env. Each is added only when its key is present
// (MalwareBazaar needs DFIR_MB_KEY for its API). Empty array → enrichment off. Per-provider TLS
// trust for a self-hosted intel host comes from composition/tlsFetch.ts.
export function buildEnrichmentProviders(): EnrichmentProvider[] {
  const providers: EnrichmentProvider[] = [];
  if (process.env.DFIR_VT_KEY) providers.push(new VirusTotalProvider({ apiKey: process.env.DFIR_VT_KEY }));
  // Hunting.ch — the abuse.ch unified hunt (MalwareBazaar + ThreatFox + URLhaus + YARAify).
  // There's no separate MalwareBazaar source anymore: MalwareBazaar is one of its back-ends.
  // Uses the ONE abuse.ch Auth-Key; DFIR_MB_KEY (the legacy name for that key) still works.
  const abuseChKey = process.env.DFIR_HUNTINGCH_KEY || process.env.DFIR_MB_KEY;
  if (abuseChKey) providers.push(new HuntingChProvider({ apiKey: abuseChKey }));
  // CrowdStrike Falcon — Threat Intelligence only (Falcon Intelligence Indicators + MalQuery).
  if (process.env.DFIR_CROWDSTRIKE_CLIENT_ID && process.env.DFIR_CROWDSTRIKE_CLIENT_SECRET) {
    providers.push(
      new CrowdStrikeProvider({
        clientId: process.env.DFIR_CROWDSTRIKE_CLIENT_ID,
        clientSecret: process.env.DFIR_CROWDSTRIKE_CLIENT_SECRET,
        cloud: process.env.DFIR_CROWDSTRIKE_CLOUD,
        baseUrl: process.env.DFIR_CROWDSTRIKE_BASE_URL,
      }),
    );
  }
  if (process.env.DFIR_ABUSEIPDB_KEY)
    providers.push(new AbuseIpdbProvider({ apiKey: process.env.DFIR_ABUSEIPDB_KEY }));
  if (process.env.DFIR_MISP_URL && process.env.DFIR_MISP_KEY)
    providers.push(
      new MispProvider({
        baseUrl: process.env.DFIR_MISP_URL,
        apiKey: process.env.DFIR_MISP_KEY,
        fetchFn: tlsFetchFor("MISP"),
      }),
    );
  if (process.env.DFIR_ROCKYRACCOON_KEY)
    providers.push(new RockyRaccoonProvider({ apiKey: process.env.DFIR_ROCKYRACCOON_KEY }));
  if (process.env.DFIR_YETI_URL && process.env.DFIR_YETI_KEY)
    providers.push(
      new YetiProvider({
        baseUrl: process.env.DFIR_YETI_URL,
        apiKey: process.env.DFIR_YETI_KEY,
        fetchFn: tlsFetchFor("YETI"),
      }),
    );
  if (process.env.DFIR_OPENCTI_URL && process.env.DFIR_OPENCTI_KEY) {
    const octiScore = Number(process.env.DFIR_OPENCTI_MALICIOUS_SCORE);
    providers.push(
      new OpenCtiProvider({
        baseUrl: process.env.DFIR_OPENCTI_URL,
        apiKey: process.env.DFIR_OPENCTI_KEY,
        fetchFn: tlsFetchFor("OPENCTI"),
        maliciousScore: Number.isFinite(octiScore) && octiScore > 0 ? octiScore : undefined,
      }),
    );
  }
  // CIRCL hashlookup (#154): free, keyless KNOWN-FILE lookup for hash IOCs — the known-good
  // angle that complements VirusTotal / Hunting.ch (a hit confirms a known, legitimate file).
  // Always available; `external` scope → opt-in per case. Base URL overridable for a self-hosted
  // / air-gapped mirror via DFIR_HASHLOOKUP_URL.
  providers.push(new HashlookupProvider({ baseUrl: process.env.DFIR_HASHLOOKUP_URL }));
  // IP-infrastructure context providers (#134): reverse DNS, WHOIS-over-RDAP, and GeoIP need
  // NO API key, so they're always available — but, like all `external` providers, they're
  // opt-in per case (default OFF), so nothing is looked up off-box without analyst approval.
  // Base/endpoint overridable via env for self-hosted/paid backends or an air-gapped mirror.
  providers.push(new ReverseDnsProvider());
  // Offline lookalike / typosquat domain check — local scope (nothing leaves the box), so it is
  // enabled by default and flags domain IOCs that imitate a bundled brand list (+ env extras).
  providers.push(new LookalikeDomainProvider());
  providers.push(new RdapProvider({ baseUrl: process.env.DFIR_RDAP_URL }));
  providers.push(
    new GeoIpProvider({ baseUrl: process.env.DFIR_GEOIP_URL, apiKey: process.env.DFIR_GEOIP_KEY }),
  );
  // Shodan host lookup (hosted domains / open ports / services / CVEs) reuses the existing
  // DFIR_SHODAN_KEY (also used by the customer-exposure attack-surface check).
  if (process.env.DFIR_SHODAN_KEY)
    providers.push(new ShodanProvider({ apiKey: process.env.DFIR_SHODAN_KEY }));
  return providers;
}

// Build a per-provider delay map from `DFIR_ENRICH_DELAY_MS_<PROVIDER>` env vars.
// Keys must match the `provider.name` strings used in enrichService.
export function buildEnrichProviderDelayMap(): Record<string, number> | undefined {
  const entries: Array<[string, string]> = [
    ["VIRUSTOTAL", "VirusTotal"],
    ["ABUSEIPDB", "AbuseIPDB"],
    ["HUNTINGCH", "Hunting.ch"],
    ["CROWDSTRIKE", "CrowdStrike"],
    ["ROCKYRACCOON", "RockyRaccoon"],
    ["MISP", "MISP"],
    ["YETI", "YETI"],
    ["OPENCTI", "OpenCTI"],
    ["REVERSE_DNS", "Reverse DNS"],
    ["WHOIS", "WHOIS"],
    ["GEOIP", "GeoIP"],
    ["SHODAN", "Shodan"],
    ["HASHLOOKUP", "Hashlookup"],
  ];
  const map: Record<string, number> = {};
  for (const [suffix, name] of entries) {
    const v = Number(process.env[`DFIR_ENRICH_DELAY_MS_${suffix}`]);
    if (v > 0) map[name] = v;
  }
  return Object.keys(map).length > 0 ? map : undefined;
}

export function buildCustomerExposureProviders(): CustomerExposureProvider[] {
  const providers: CustomerExposureProvider[] = [];
  if (process.env.DFIR_LEAKCHECK_KEY) {
    providers.push(
      new LeakCheckExposureProvider({
        apiKey: process.env.DFIR_LEAKCHECK_KEY,
        domainLimit: Number(process.env.DFIR_LEAKCHECK_DOMAIN_LIMIT) || undefined,
      }),
    );
  }
  if (process.env.DFIR_DEHASHED_KEY) {
    providers.push(
      new DeHashedExposureProvider({
        apiKey: process.env.DFIR_DEHASHED_KEY,
        baseUrl: process.env.DFIR_DEHASHED_BASE_URL,
      }),
    );
  }
  if (process.env.DFIR_HIBP_KEY) {
    providers.push(
      new HaveIBeenPwnedExposureProvider({
        apiKey: process.env.DFIR_HIBP_KEY,
        userAgent: process.env.DFIR_HIBP_USER_AGENT || "DFIR Companion",
      }),
    );
  }
  if (process.env.DFIR_SHODAN_KEY) {
    providers.push(new ShodanExposureProvider({ apiKey: process.env.DFIR_SHODAN_KEY }));
  }
  return providers;
}
