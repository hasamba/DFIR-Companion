import { describe, it, expect, vi } from "vitest";
import {
  DeHashedExposureProvider,
  HaveIBeenPwnedExposureProvider,
  CrowdStrikeReconExposureProvider,
  LeakCheckExposureProvider,
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

describe("CrowdStrikeReconExposureProvider", () => {
  function csFetch(): ReturnType<typeof vi.fn> {
    return vi.fn(async (url: string, init?: RequestInit) => {
      const u = new URL(url);
      if (u.pathname === "/oauth2/token") {
        expect((init!.headers as Record<string, string>)["content-type"]).toContain("x-www-form-urlencoded");
        return jsonResponse({ access_token: "tok", expires_in: 1799 }, 201);
      }
      expect((init!.headers as Record<string, string>).authorization).toBe("Bearer tok");
      if (u.pathname === "/recon/queries/notifications-exposed-data-records/v1") {
        expect(u.searchParams.get("filter")).toContain("email:'alice@example.com'");
        return jsonResponse({ resources: ["rec1"] });
      }
      if (u.pathname === "/recon/entities/notifications-exposed-data-records/v1") {
        expect(u.searchParams.get("ids")).toBe("rec1");
        return jsonResponse({ resources: [{
          id: "rec1",
          email: "alice@example.com",
          domain: "example.com",
          site: "forum.example",
          exposure_date: "2026-01-02T00:00:00Z",
          credential_status: "compromised",
        }] });
      }
      throw new Error(`unexpected path ${u.pathname}`);
    });
  }

  it("queries Recon exposed-data records and maps record entities", async () => {
    const fetchFn = csFetch();
    const cs = new CrowdStrikeReconExposureProvider({ clientId: "id", clientSecret: "sec", fetchFn });

    const results = await cs.lookupEmail("alice@example.com");

    expect(results).toEqual([{
      provider: "CrowdStrike Recon",
      targetType: "email",
      target: "alice@example.com",
      email: "alice@example.com",
      breach: "forum.example",
      breachDate: "2026-01-02T00:00:00Z",
      exposedData: ["credential_status: compromised"],
      secretPresent: true,
    }]);
  });
});
