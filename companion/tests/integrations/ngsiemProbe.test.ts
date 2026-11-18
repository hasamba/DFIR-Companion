import { describe, expect, it } from "vitest";
import { probeNgsiem } from "../../src/integrations/crowdstrike/ngsiemProbe.js";

// #2685: Settings → NG-SIEM → Test, against a scripted fake Falcon. No network.

const SECRET = "probe-secret-value";

interface Script {
  token?: number | "throw";
  start?: number | "throw";
  startBody?: unknown;
  poll?: number;
  pollBody?: unknown;
  del?: number;
}

function fake(s: Script = {}) {
  const calls: string[] = [];
  const fetchFn = (async (input: string | URL, init?: RequestInit) => {
    const url = new URL(String(input));
    const method = init?.method ?? "GET";
    calls.push(`${method} ${url.pathname}`);
    const boom = (code: string) => {
      throw new TypeError("fetch failed", { cause: Object.assign(new Error(code), { code }) });
    };
    if (url.pathname === "/oauth2/token") {
      if (s.token === "throw") boom("SELF_SIGNED_CERT_IN_CHAIN");
      if (typeof s.token === "number") return new Response("{}", { status: s.token });
      return Response.json({ access_token: "tok", expires_in: 1799 }, { status: 201 });
    }
    if (method === "POST") {
      if (s.start === "throw") boom("ECONNRESET");
      if (typeof s.start === "number")
        return Response.json({ errors: [{ message: "bad query" }] }, { status: s.start });
      return Response.json(s.startBody ?? { id: "job-1" });
    }
    if (method === "DELETE") return new Response(null, { status: s.del ?? 204 });
    if (s.poll) return new Response("{}", { status: s.poll });
    return Response.json(s.pollBody ?? { done: false, events: [] });
  }) as typeof fetch;
  return { fetchFn, calls };
}

const probe = (f: ReturnType<typeof fake>, extra: Record<string, unknown> = {}) =>
  probeNgsiem({
    clientId: "id",
    clientSecret: SECRET,
    baseUrl: "https://falcon.test",
    repository: "search-all",
    fetchFn: f.fetchFn,
    peerIssuer: async () => "O=Proxy, CN=Inspect CA",
    ...extra,
  });

describe("probeNgsiem", () => {
  it("all steps pass: reached, signed in, Write (job started), Read (job polled), and the job is cancelled", async () => {
    const f = fake();
    const r = await probe(f);
    expect(r.ok).toBe(true);
    expect(r.steps.map((s) => [s.id, s.ok])).toEqual([
      ["reach", true],
      ["signin", true],
      ["write", true],
      ["read", true],
    ]);
    expect(r.host).toBe("falcon.test");
    expect(f.calls).toEqual([
      "POST /oauth2/token",
      "POST /humio/api/v1/repositories/search-all/queryjobs",
      "GET /humio/api/v1/repositories/search-all/queryjobs/job-1",
      "DELETE /humio/api/v1/repositories/search-all/queryjobs/job-1",
    ]);
    expect(r.warnings).toEqual([]);
  });

  it("a rejected sign-in: reached OK, sign-in failed, no search started", async () => {
    const f = fake({ token: 401 });
    const r = await probe(f);
    expect(r.steps.map((s) => [s.id, s.ok])).toEqual([
      ["reach", true],
      ["signin", false],
    ]);
    expect(r.error).toMatch(/CLIENT_ID/);
    expect(f.calls).toEqual(["POST /oauth2/token"]);
  });

  it("a TLS failure stops at reach with the issuer and the CA setting", async () => {
    const r = await probe(fake({ token: "throw" }));
    expect(r.steps).toHaveLength(1);
    expect(r.steps[0]).toMatchObject({ id: "reach", ok: false });
    expect(r.error).toContain('issued by "O=Proxy, CN=Inspect CA"');
    expect(r.error).toContain("DFIR_CROWDSTRIKE_SIEM_CA");
  });

  it("a 403 on start names NGSIEM: Write; nothing to cancel", async () => {
    const f = fake({ start: 403 });
    const r = await probe(f);
    expect(r.steps.at(-1)).toMatchObject({ id: "write", ok: false });
    expect(r.error).toContain("NGSIEM: Write");
    expect(f.calls.some((c) => c.startsWith("DELETE"))).toBe(false);
  });

  it("a 404 on start names the repository setting", async () => {
    const r = await probe(fake({ start: 404 }));
    expect(r.error).toContain("DFIR_CROWDSTRIKE_SIEM_REPOSITORY");
    expect(r.error).toContain('"search-all"');
  });

  it("a refused query quotes Falcon", async () => {
    expect((await probe(fake({ start: 400 }))).error).toContain("bad query");
  });

  it("a 403 on poll names NGSIEM: Read and the job is still cancelled", async () => {
    const f = fake({ poll: 403 });
    const r = await probe(f);
    expect(r.steps.map((s) => [s.id, s.ok])).toEqual([
      ["reach", true],
      ["signin", true],
      ["write", true],
      ["read", false],
    ]);
    expect(r.error).toContain("NGSIEM: Read");
    expect(f.calls.at(-1)).toBe("DELETE /humio/api/v1/repositories/search-all/queryjobs/job-1");
  });

  it("a missing job id or a non-object poll answer is a failure, not a pass", async () => {
    expect((await probe(fake({ startBody: {} }))).error).toMatch(/job id/);
    expect((await probe(fake({ pollBody: [] }))).error).toMatch(/not a search status/);
  });

  it("an unconfirmed cancel is a warning", async () => {
    const r = await probe(fake({ del: 500 }));
    expect(r.ok).toBe(true);
    expect(r.warnings[0]).toContain("did not confirm the cancel");
  });

  it("a network failure on start is logged in full and never carries the secret", async () => {
    const logs: string[] = [];
    const r = await probe(fake({ start: "throw" }), { log: (l: string) => logs.push(l) });
    expect(r.error).toMatch(/firewall or proxy/);
    expect(logs.join("\n")).toContain("ECONNRESET");
    expect(JSON.stringify(r) + logs.join("")).not.toContain(SECRET);
  });

  it("a bad base URL or CA bundle fails the settings step before any request", async () => {
    const f = fake();
    const bad = await probe(f, { baseUrl: "http://falcon.test" });
    expect(bad.steps).toEqual([expect.objectContaining({ id: "settings", ok: false })]);
    const ca = await probeNgsiem({
      clientId: "id",
      clientSecret: SECRET,
      baseUrl: "https://falcon.test",
      repository: "search-all",
      ca: "/nonexistent/ca.pem",
    });
    expect(ca.error).toContain("DFIR_CROWDSTRIKE_SIEM_CA");
    expect(f.calls).toEqual([]);
  });
});
