import { describe, it, expect, vi } from "vitest";
import {
  DeHashedExposureProvider,
  HaveIBeenPwnedExposureProvider,
  LeakCheckExposureProvider,
  ShodanExposureProvider,
} from "../../src/integrations/customerExposureProviders.js";

function jsonResponse(body: unknown, status = 200): Response {
  return new Response(JSON.stringify(body), { status, headers: { "content-type": "application/json" } });
}

describe("HaveIBeenPwnedExposureProvider", () => {
  it("maps breachedAccount results for an email and sends required headers", async () => {
    const fetchFn = vi.fn(async () => jsonResponse([
      { Name: "Adobe", BreachDate: "2013-10-04", DataClasses: ["Email addresses", "Passwords"] },
    ]));
    const hibp = new HaveIBeenPwnedExposureProvider({ apiKey: "00000000000000000000000000000000", userAgent: "dfir-test", fetchFn });

    const results = await hibp.lookupEmail("alice@example.com");

    expect(results).toEqual([{
      provider: "Have I Been Pwned",
      targetType: "email",
      target: "alice@example.com",
      email: "alice@example.com",
      breach: "Adobe",
      breachDate: "2013-10-04",
      exposedData: ["Email addresses", "Passwords"],
      secretPresent: true,
    }]);
    const init = fetchFn.mock.calls[0][1] as RequestInit;
    expect(init.headers).toMatchObject({ "hibp-api-key": "00000000000000000000000000000000", "user-agent": "dfir-test" });
    expect(fetchFn.mock.calls[0][0]).toContain("/breachedAccount/alice%40example.com");
  });

  it("maps breachedDomain aliases back to full customer emails", async () => {
    const fetchFn = vi.fn(async () => jsonResponse({ alice: ["Adobe"], bob: ["Gawker", "Stratfor"] }));
    const hibp = new HaveIBeenPwnedExposureProvider({ apiKey: "k", fetchFn });

    const results = await hibp.lookupDomain("example.com");

    expect(results.map((r) => `${r.email}:${r.breach}`).sort()).toEqual([
      "alice@example.com:Adobe",
      "bob@example.com:Gawker",
      "bob@example.com:Stratfor",
    ]);
    expect(fetchFn.mock.calls[0][0]).toContain("/breachedDomain/example.com");
  });

  it("treats a 404 as no exposure", async () => {
    const hibp = new HaveIBeenPwnedExposureProvider({ apiKey: "k", fetchFn: vi.fn(async () => new Response("", { status: 404 })) });
    expect(await hibp.lookupEmail("none@example.com")).toEqual([]);
  });
});

describe("LeakCheckExposureProvider", () => {
  it("maps domain and email results without storing returned passwords", async () => {
    const fetchFn = vi.fn(async (url: string, init?: RequestInit) => {
      expect((init!.headers as Record<string, string>)["X-API-Key"]).toBe("lc-key");
      expect(url).toContain("/query/example.com?type=domain");
      return jsonResponse({ success: true, found: 1, result: [
        { email: "alice@example.com", username: "alice", password: "secret", source: { name: "ComboList", breach_date: "2025-01-01" }, fields: ["email", "password"] },
      ] });
    });
    const lc = new LeakCheckExposureProvider({ apiKey: "lc-key", fetchFn });

    const results = await lc.lookupDomain("example.com");

    expect(results[0]).toMatchObject({
      provider: "LeakCheck",
      targetType: "domain",
      target: "example.com",
      email: "alice@example.com",
      username: "alice",
      breach: "ComboList",
      breachDate: "2025-01-01",
      secretPresent: true,
    });
    expect(JSON.stringify(results)).not.toContain('"secret"');
  });

  it("surfaces LeakCheck's own error text on a 403 (not a guessed plan-tier message)", async () => {
    const lc = new LeakCheckExposureProvider({
      apiKey: "lc-key",
      fetchFn: vi.fn(async () => jsonResponse({ success: false, error: "Limit reached" }, 403)),
    });
    await expect(lc.lookupEmail("alice@example.com")).rejects.toThrow(/Limit reached/);
  });
});

describe("DeHashedExposureProvider", () => {
  it("posts a v2 email query and marks passwords without storing their value", async () => {
    const fetchFn = vi.fn(async () => jsonResponse({
      entries: [{ email: "alice@example.com", database_name: "Example Leak", password: "secret", username: "alice" }],
    }));
    const dehashed = new DeHashedExposureProvider({ apiKey: "dh-key", fetchFn });

    const results = await dehashed.lookupEmail("alice@example.com");

    expect(results[0]).toMatchObject({
      provider: "DeHashed",
      targetType: "email",
      target: "alice@example.com",
      email: "alice@example.com",
      username: "alice",
      breach: "Example Leak",
      secretPresent: true,
    });
    expect(JSON.stringify(results)).not.toContain('"secret"');
    const init = fetchFn.mock.calls[0][1] as RequestInit;
    expect(init.method).toBe("POST");
    expect(init.headers).toMatchObject({ "DeHashed-Api-Key": "dh-key" });
    expect(JSON.parse(init.body as string)).toMatchObject({ query: "email:alice@example.com", page: 1, size: 100 });
  });

  it("builds a domain query for customer domains", async () => {
    const fetchFn = vi.fn(async () => jsonResponse({ entries: [{ email: "bob@example.com", database_name: "Breach" }] }));
    const dehashed = new DeHashedExposureProvider({ apiKey: "dh-key", fetchFn });

    const results = await dehashed.lookupDomain("example.com");

    expect(results[0]).toMatchObject({ targetType: "domain", target: "example.com", email: "bob@example.com" });
    expect(JSON.parse((fetchFn.mock.calls[0][1] as RequestInit).body as string).query).toBe("domain:example.com");
  });
});

describe("ShodanExposureProvider", () => {
  it("maps a domain's exposed hosts/services/CVEs and never reports credentials", async () => {
    const fetchFn = vi.fn(async () => jsonResponse({
      matches: [
        { ip_str: "203.0.113.10", port: 443, transport: "tcp", product: "nginx", version: "1.18.0",
          org: "Example Org", hostnames: ["www.example.com"], timestamp: "2026-06-01T00:00:00.000000",
          vulns: { "CVE-2021-23017": {}, "CVE-2019-9511": {} } },
      ],
    }));
    const shodan = new ShodanExposureProvider({ apiKey: "shodankey", fetchFn });

    const results = await shodan.lookupDomain("example.com");

    expect(results).toHaveLength(1);
    expect(results[0]).toMatchObject({
      provider: "Shodan",
      targetType: "domain",
      target: "example.com",
      breach: "203.0.113.10:443 nginx 1.18.0",
      sourceUrl: "https://www.shodan.io/host/203.0.113.10",
      secretPresent: false,
    });
    expect(results[0].exposedData).toEqual(expect.arrayContaining(["443/tcp", "nginx", "Example Org", "vuln:CVE-2021-23017", "vuln:CVE-2019-9511"]));
    // Searches by hostname filter with the key as a query param.
    const url = fetchFn.mock.calls[0][0] as string;
    expect(url).toContain("/shodan/host/search");
    expect(url).toContain("key=shodankey");
    expect(decodeURIComponent(url)).toContain("query=hostname:example.com");
  });

  it("has no email lookup (returns []) and surfaces auth errors", async () => {
    const shodan = new ShodanExposureProvider({ apiKey: "k", fetchFn: vi.fn(async () => jsonResponse({ matches: [] })) });
    expect(await shodan.lookupEmail("alice@example.com")).toEqual([]);

    const bad = new ShodanExposureProvider({ apiKey: "bad", fetchFn: vi.fn(async () => jsonResponse({ error: "Invalid API key" }, 401)) });
    await expect(bad.lookupDomain("example.com")).rejects.toThrow(/auth failed/i);
  });
});
