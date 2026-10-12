// INVARIANT (#2148): an IOC value must never become a connection host. Every enrichment provider
// sends the IOC in the path, query or body of a request to a host that is either a hard-coded
// provider constant or an operator-configured base URL. That is why the enrichment SSRF guard
// (enrichService.ts, isInternalTarget) can stay literal-only and never resolve attacker domains
// (resolving them from the analyst's machine would leak the investigation to the attacker's
// nameserver). A provider that genuinely needs to connect to a host taken from an IOC value must
// route that request through `fetchOutbound` (routes/outboundFetchGuard.ts) — and this test, which
// fails the moment a provider requests a host derived from the IOC, is where that decision is made.
import { describe, it, expect } from "vitest";
import type { EnrichmentProvider, FetchFn, IocKind } from "../../src/enrichment/provider.js";
import { VirusTotalProvider } from "../../src/enrichment/virustotal.js";
import { AbuseIpdbProvider } from "../../src/enrichment/abuseipdb.js";
import { HuntingChProvider } from "../../src/enrichment/huntingch.js";
import { CrowdStrikeProvider } from "../../src/enrichment/crowdstrike.js";
import { HashlookupProvider } from "../../src/enrichment/hashlookup.js";
import { RdapProvider } from "../../src/enrichment/rdap.js";
import { ShodanProvider } from "../../src/enrichment/shodan.js";
import { GeoIpProvider } from "../../src/enrichment/geoip.js";
import { RockyRaccoonProvider } from "../../src/enrichment/rockyraccoon.js";
import { MispProvider } from "../../src/enrichment/misp.js";
import { YetiProvider } from "../../src/enrichment/yeti.js";
import { OpenCtiProvider } from "../../src/enrichment/opencti.js";

const CONFIGURED_BASE = "https://intel.test";
const CONFIGURED_HOST = "intel.test";
const SENTINEL_HOST = "ssrf-sentinel.example";
const SENTINEL_IP = "1.2.3.4";

// One IOC value per kind, each naming a host an attacker would like the companion to connect to.
const SENTINELS: Record<IocKind, string> = {
  hash: "d41d8cd98f00b204e9800998ecf8427e",
  ip: SENTINEL_IP,
  domain: SENTINEL_HOST,
  url: `http://${SENTINEL_HOST}/payload`,
  process: `${SENTINEL_HOST}.exe`,
};
const KINDS = Object.keys(SENTINELS) as IocKind[];

// Records every requested URL and answers with a generic JSON body (enough for token exchanges to
// succeed so the lookup request itself is made); parsing failures after that are irrelevant here.
function recordingFetch(urls: string[]): FetchFn {
  return async (input: Parameters<FetchFn>[0]) => {
    const url = typeof input === "string" ? input : input instanceof URL ? input.href : input.url;
    urls.push(url);
    const body = JSON.stringify({ access_token: "t", expires_in: 1799, data: {}, resources: [] });
    return new Response(body, { status: 200, headers: { "content-type": "application/json" } });
  };
}

interface Case {
  name: string;
  allowedHosts: string[];
  build: (fetchFn: FetchFn) => EnrichmentProvider;
}

const CASES: Case[] = [
  {
    name: "VirusTotal",
    allowedHosts: ["www.virustotal.com"],
    build: (fetchFn) => new VirusTotalProvider({ apiKey: "k", fetchFn }),
  },
  {
    name: "AbuseIPDB",
    allowedHosts: ["api.abuseipdb.com"],
    build: (fetchFn) => new AbuseIpdbProvider({ apiKey: "k", fetchFn }),
  },
  {
    name: "Hunting.ch",
    allowedHosts: [
      "mb-api.abuse.ch",
      "threatfox-api.abuse.ch",
      "urlhaus-api.abuse.ch",
      "yaraify-api.abuse.ch",
    ],
    build: (fetchFn) => new HuntingChProvider({ apiKey: "k", fetchFn }),
  },
  {
    name: "CrowdStrike",
    allowedHosts: ["api.crowdstrike.com"],
    build: (fetchFn) => new CrowdStrikeProvider({ clientId: "id", clientSecret: "s", fetchFn }),
  },
  {
    name: "Hashlookup",
    allowedHosts: ["hashlookup.circl.lu"],
    build: (fetchFn) => new HashlookupProvider({ fetchFn }),
  },
  { name: "RDAP", allowedHosts: ["rdap.org"], build: (fetchFn) => new RdapProvider({ fetchFn }) },
  {
    name: "Shodan",
    allowedHosts: ["api.shodan.io"],
    build: (fetchFn) => new ShodanProvider({ apiKey: "k", fetchFn }),
  },
  { name: "GeoIP", allowedHosts: ["ipinfo.io"], build: (fetchFn) => new GeoIpProvider({ fetchFn }) },
  {
    name: "RockyRaccoon",
    allowedHosts: ["api.rockyraccoon.io"],
    build: (fetchFn) => new RockyRaccoonProvider({ apiKey: "k", fetchFn }),
  },
  {
    name: "MISP",
    allowedHosts: [CONFIGURED_HOST],
    build: (fetchFn) => new MispProvider({ baseUrl: CONFIGURED_BASE, apiKey: "k", fetchFn }),
  },
  {
    name: "YETI",
    allowedHosts: [CONFIGURED_HOST],
    build: (fetchFn) => new YetiProvider({ baseUrl: CONFIGURED_BASE, apiKey: "k", fetchFn }),
  },
  {
    name: "OpenCTI",
    allowedHosts: [CONFIGURED_HOST],
    build: (fetchFn) => new OpenCtiProvider({ baseUrl: CONFIGURED_BASE, apiKey: "k", fetchFn }),
  },
];

async function lookupAll(provider: EnrichmentProvider): Promise<IocKind[]> {
  const exercised: IocKind[] = [];
  for (const kind of KINDS) {
    if (!provider.supports(kind)) continue;
    exercised.push(kind);
    try {
      if (provider.lookupDetailed) await provider.lookupDetailed(kind, SENTINELS[kind]);
      else await provider.lookup(kind, SENTINELS[kind]);
    } catch {
      // A canned body may not parse as this provider's real response — only the URLs matter here.
    }
  }
  return exercised;
}

describe("enrichment providers: an IOC value never becomes a connection host (#2148)", () => {
  for (const c of CASES) {
    it(`${c.name} only connects to its own constant or configured host`, async () => {
      const urls: string[] = [];
      const exercised = await lookupAll(c.build(recordingFetch(urls)));
      expect(exercised.length).toBeGreaterThan(0);
      expect(urls.length).toBeGreaterThan(0);
      for (const u of urls) {
        const host = new URL(u).hostname;
        expect(host).not.toContain("ssrf-sentinel");
        expect(host).not.toBe(SENTINEL_IP);
        expect(c.allowedHosts).toContain(host);
      }
    });
  }
});
