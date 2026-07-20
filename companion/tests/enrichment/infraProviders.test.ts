import { describe, it, expect, vi } from "vitest";
import { ReverseDnsProvider } from "../../src/enrichment/reverseDns.js";
import { RdapProvider } from "../../src/enrichment/rdap.js";
import { GeoIpProvider } from "../../src/enrichment/geoip.js";
import { ShodanProvider } from "../../src/enrichment/shodan.js";

function jsonResponse(body: unknown, status = 200): Response {
  return new Response(JSON.stringify(body), { status, headers: { "content-type": "application/json" } });
}

describe("ReverseDnsProvider", () => {
  it("resolves an IP to its PTR hostname(s) as an unknown-verdict context result", async () => {
    const rd = new ReverseDnsProvider({ resolve: async () => ["dns.google", "google-public-dns-a.google.com"] });
    const r = await rd.lookup("ip", "8.8.8.8");
    expect(r).toMatchObject({ source: "Reverse DNS", verdict: "unknown" });
    expect(r!.score).toBe("2 hostnames");
    expect(r!.tags).toEqual(["dns.google", "google-public-dns-a.google.com"]);
    expect(rd.supports("ip")).toBe(true);
    expect(rd.supports("hash")).toBe(false);
  });

  it("uses the single hostname as the score when there is exactly one", async () => {
    const rd = new ReverseDnsProvider({ resolve: async () => ["mail.evil.test"] });
    expect((await rd.lookup("ip", "1.2.3.4"))!.score).toBe("mail.evil.test");
  });

  it("returns null (a cached miss) when the IP has no PTR record", async () => {
    const noRecord = new ReverseDnsProvider({ resolve: async () => { throw Object.assign(new Error("getHostByAddr ENOTFOUND"), { code: "ENOTFOUND" }); } });
    expect(await noRecord.lookup("ip", "10.0.0.1")).toBeNull();
    const empty = new ReverseDnsProvider({ resolve: async () => [] });
    expect(await empty.lookup("ip", "10.0.0.2")).toBeNull();
  });

  it("re-throws a transient resolver failure (so it is retried, not cached)", async () => {
    const flaky = new ReverseDnsProvider({ resolve: async () => { throw Object.assign(new Error("queryPtr ETIMEOUT"), { code: "ETIMEOUT" }); } });
    await expect(flaky.lookup("ip", "9.9.9.9")).rejects.toThrow(/ETIMEOUT/);
  });

  it("does not look up non-IP kinds", async () => {
    const rd = new ReverseDnsProvider({ resolve: async () => { throw new Error("should not be called"); } });
    expect(await rd.lookup("domain", "evil.test")).toBeNull();
  });
});

describe("RdapProvider (WHOIS over RDAP)", () => {
  it("extracts net name, CIDR, country, ASN and the nested abuse contact", async () => {
    const fetchFn = vi.fn(async () => jsonResponse({
      name: "GOGL", handle: "NET-8-8-8-0-1", country: "US",
      startAddress: "8.8.8.0", endAddress: "8.8.8.255",
      cidr0_cidrs: [{ v4prefix: "8.8.8.0", length: 24 }],
      arin_originas0_originautnums: [15169],
      entities: [
        { handle: "GOGL", roles: ["registrant"], vcardArray: ["vcard", [["fn", {}, "text", "Google LLC"], ["org", {}, "text", "Google LLC"]]] },
        { handle: "ABUSE5250-ARIN", roles: ["technical"], entities: [
          { handle: "ABUSE5250-ARIN", roles: ["abuse"], vcardArray: ["vcard", [["fn", {}, "text", "Abuse"], ["email", {}, "text", "network-abuse@google.com"]]] },
        ] },
      ],
    }));
    const rdap = new RdapProvider({ fetchFn });
    const r = await rdap.lookup("ip", "8.8.8.8");
    expect(r).toMatchObject({ source: "WHOIS", verdict: "unknown" });
    expect(r!.score).toBe("AS15169 · Google LLC · US");
    expect(r!.tags).toEqual(expect.arrayContaining(["US", "AS15169", "GOGL", "8.8.8.0/24", "abuse: network-abuse@google.com"]));
    expect(r!.link).toContain("/ip/8.8.8.8");
    expect(fetchFn.mock.calls[0][0]).toBe("https://rdap.org/ip/8.8.8.8");
    expect(rdap.supports("ip")).toBe(true);
    expect(rdap.supports("domain")).toBe(false);
  });

  it("falls back to start–end range when no CIDR is given", async () => {
    const fetchFn = vi.fn(async () => jsonResponse({ name: "RIPE-BLOCK", country: "DE", startAddress: "203.0.113.0", endAddress: "203.0.113.127" }));
    const r = await new RdapProvider({ fetchFn }).lookup("ip", "203.0.113.5");
    expect(r!.tags).toContain("203.0.113.0 – 203.0.113.127");
  });

  it("honors a custom base URL", async () => {
    const fetchFn = vi.fn(async () => jsonResponse({ name: "X", country: "FR" }));
    await new RdapProvider({ baseUrl: "https://rdap.db.ripe.net/", fetchFn }).lookup("ip", "2.2.2.2");
    expect(fetchFn.mock.calls[0][0]).toBe("https://rdap.db.ripe.net/ip/2.2.2.2");
  });

  it("returns null on 404 (no allocation) and throws on 429 (rate limit)", async () => {
    const nf = new RdapProvider({ fetchFn: vi.fn(async () => new Response("", { status: 404 })) });
    expect(await nf.lookup("ip", "192.0.2.1")).toBeNull();
    const rl = new RdapProvider({ fetchFn: vi.fn(async () => new Response("", { status: 429 })) });
    await expect(rl.lookup("ip", "192.0.2.1")).rejects.toThrow(/rate limit/i);
  });

  it("returns null for an empty RDAP object (nothing to report)", async () => {
    const r = await new RdapProvider({ fetchFn: vi.fn(async () => jsonResponse({})) }).lookup("ip", "192.0.2.9");
    expect(r).toBeNull();
  });
});

describe("GeoIpProvider", () => {
  it("maps the default ipinfo.io shape (country code + 'AS… Org' org) and hits the /json template", async () => {
    const fetchFn = vi.fn(async () => jsonResponse({
      ip: "8.8.8.8", hostname: "dns.google", city: "Mountain View", region: "California",
      country: "US", org: "AS15169 Google LLC",
    }));
    const geo = new GeoIpProvider({ fetchFn });
    const r = await geo.lookup("ip", "8.8.8.8");
    expect(r).toMatchObject({ source: "GeoIP", verdict: "unknown" });
    expect(r!.score).toBe("US · AS15169 Google LLC");                   // code-only country, AS split out of org
    expect(r!.tags).toEqual(expect.arrayContaining(["US", "Mountain View", "AS15169", "Google LLC"]));
    expect(fetchFn.mock.calls[0][0]).toBe("https://ipinfo.io/8.8.8.8/json");
    const headers = (fetchFn.mock.calls[0][1] as RequestInit).headers as Record<string, string>;
    expect(headers["User-Agent"]).toBe("DFIR-Companion");               // many free GeoIPs 403 a UA-less request
  });

  it("tolerates the ipwho.is shape (full country name + numeric connection.asn)", async () => {
    const fetchFn = vi.fn(async () => jsonResponse({
      success: true, country: "United States", country_code: "US",
      region: "California", city: "Mountain View",
      connection: { asn: 15169, org: "Google LLC", isp: "Google LLC" },
    }));
    const r = await new GeoIpProvider({ baseUrl: "https://ipwho.is/{ip}", fetchFn }).lookup("ip", "8.8.8.8");
    expect(r!.score).toBe("United States (US) · AS15169 Google LLC");
    expect(r!.tags).toEqual(expect.arrayContaining(["US", "Mountain View", "AS15169", "Google LLC"]));
    expect(fetchFn.mock.calls[0][0]).toBe("https://ipwho.is/8.8.8.8");
  });

  it("tolerates the ip-api.com shape (countryCode / as string / regionName) and append-style base", async () => {
    const fetchFn = vi.fn(async () => jsonResponse({
      status: "success", country: "Germany", countryCode: "DE", regionName: "Hesse",
      city: "Frankfurt", as: "AS24940 Hetzner Online GmbH", isp: "Hetzner", org: "Hetzner Online GmbH",
    }));
    const r = await new GeoIpProvider({ baseUrl: "http://ip-api.com/json", fetchFn }).lookup("ip", "1.2.3.4");
    expect(r!.tags).toEqual(expect.arrayContaining(["DE", "AS24940", "Hetzner Online GmbH"]));
    expect(r!.score).toContain("Germany (DE)");
    expect(fetchFn.mock.calls[0][0]).toBe("http://ip-api.com/json/1.2.3.4");   // appended, no {ip} placeholder
  });

  it("returns null on a non-success/error body (reserved/invalid IP) and appends the optional key as ?token=", async () => {
    const miss = new GeoIpProvider({ fetchFn: vi.fn(async () => jsonResponse({ error: { title: "Wrong ip" } })) });
    expect(await miss.lookup("ip", "10.0.0.1")).toBeNull();
    const fetchFn = vi.fn(async () => jsonResponse({ country: "US", org: "AS15169 Google LLC" }));
    await new GeoIpProvider({ apiKey: "secret", fetchFn }).lookup("ip", "8.8.4.4");
    expect(fetchFn.mock.calls[0][0]).toBe("https://ipinfo.io/8.8.4.4/json?token=secret");
  });

  it("throws on auth / rate-limit statuses", async () => {
    const auth = new GeoIpProvider({ fetchFn: vi.fn(async () => new Response("", { status: 403 })) });
    await expect(auth.lookup("ip", "1.1.1.1")).rejects.toThrow(/auth failed/i);
    const rl = new GeoIpProvider({ fetchFn: vi.fn(async () => new Response("", { status: 429 })) });
    await expect(rl.lookup("ip", "1.1.1.1")).rejects.toThrow(/rate limit/i);
  });
});

describe("ShodanProvider (host lookup)", () => {
  it("summarizes hostnames, ports, products, ASN and CVEs as context", async () => {
    const fetchFn = vi.fn(async () => jsonResponse({
      ip_str: "1.2.3.4", hostnames: ["web.evil.test"], domains: ["evil.test"],
      ports: [22, 80, 443], org: "Evil Hosting", isp: "Evil Hosting", asn: "AS66666",
      country_name: "Russia", vulns: ["CVE-2021-44228"],
      data: [{ product: "nginx" }, { product: "OpenSSH" }],
    }));
    const sh = new ShodanProvider({ apiKey: "k", fetchFn });
    const r = await sh.lookup("ip", "1.2.3.4");
    expect(r).toMatchObject({ source: "Shodan", verdict: "unknown" });
    expect(r!.score).toContain("2 hostnames");
    expect(r!.score).toContain("3 ports");
    expect(r!.score).toContain("1 CVE");
    expect(r!.tags).toEqual(expect.arrayContaining(["Russia", "AS66666", "Evil Hosting", "web.evil.test", "ports 22,80,443", "CVE-2021-44228"]));
    expect(r!.link).toBe("https://www.shodan.io/host/1.2.3.4");
    const calledUrl = fetchFn.mock.calls[0][0] as string;
    expect(calledUrl).toContain("/shodan/host/1.2.3.4");
    expect(calledUrl).toContain("key=k");
  });

  it("returns null on 404 (IP not in Shodan) and throws on auth / rate-limit", async () => {
    const nf = new ShodanProvider({ apiKey: "k", fetchFn: vi.fn(async () => new Response("", { status: 404 })) });
    expect(await nf.lookup("ip", "203.0.113.7")).toBeNull();
    const auth = new ShodanProvider({ apiKey: "bad", fetchFn: vi.fn(async () => new Response("", { status: 401 })) });
    await expect(auth.lookup("ip", "1.2.3.4")).rejects.toThrow(/auth failed/i);
    const rl = new ShodanProvider({ apiKey: "k", fetchFn: vi.fn(async () => new Response("", { status: 429 })) });
    await expect(rl.lookup("ip", "1.2.3.4")).rejects.toThrow(/rate limit/i);
  });

  it("throws a RateLimitError carrying the parsed Retry-After on 429 (#78)", async () => {
    const rl = new ShodanProvider({
      apiKey: "k",
      fetchFn: vi.fn(async () => new Response("", { status: 429, headers: { "retry-after": "5" } })),
    });
    await expect(rl.lookup("ip", "1.2.3.4")).rejects.toMatchObject({ name: "RateLimitError", retryAfterMs: 5000 });
  });

  it("only supports IP IOCs", async () => {
    const sh = new ShodanProvider({ apiKey: "k", fetchFn: vi.fn(async () => jsonResponse({})) });
    expect(sh.supports("ip")).toBe(true);
    expect(sh.supports("domain")).toBe(false);
    expect(await sh.lookup("hash", "abcd")).toBeNull();
  });
});
