import { describe, it, expect, beforeEach, afterEach, vi } from "vitest";
import { mkdtemp, readFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import request from "supertest";
import { CaseStore } from "../../src/storage/caseStore.js";
import { KevStore } from "../../src/analysis/kevStore.js";
import { createApp } from "../../src/server.js";

// The guard resolves every hostname before it connects, and refuses one it cannot resolve. These
// tests must not depend on the machine having DNS or on what a name really points at, so the
// lookup is stubbed to one public address. globalThis.fetch is stubbed per test as well, so the
// pinned dispatcher is built but never opens a socket.
vi.mock("node:dns/promises", () => ({
  lookup: async () => [{ address: "93.184.216.34", family: 4 }],
}));

// POST /kev/import-url fetches a caller-supplied URL server-side (issue #760). The route is
// global-admin gated, but an admin is still not an authorization to make the companion connect to
// the cloud metadata service and hand the reply back — and the reply used to come back two ways:
// through V8's JSON.parse message, which quotes the first bytes of whatever it failed to parse,
// and through the raw body being written to the catalog file, from which GET /kev reflects
// catalogVersion/dateReleased.
let app: ReturnType<typeof createApp>;
let catalogFile: string;
const originalFetch = globalThis.fetch;

const KEV_FEED = {
  catalogVersion: "2026.09.01",
  dateReleased: "2026-09-01T12:00:00.0000Z",
  vulnerabilities: [
    {
      cveID: "CVE-2021-44228",
      vendorProject: "Apache",
      product: "Log4j2",
      vulnerabilityName: "Apache Log4j2 Remote Code Execution Vulnerability",
      dateAdded: "2021-12-10",
      shortDescription: "RCE.",
      requiredAction: "Apply updates.",
      dueDate: "2021-12-24",
      knownRansomwareCampaignUse: "Known",
    },
  ],
};

beforeEach(async () => {
  const root = await mkdtemp(join(tmpdir(), "dfir-kevurl-"));
  catalogFile = join(root, "kev", "catalog.json");
  app = createApp(new CaseStore(join(root, "cases")), { kevStore: new KevStore(catalogFile) });
  delete process.env.DFIR_KEV_ALLOW_INTERNAL_URL;
});

afterEach(() => {
  globalThis.fetch = originalFetch;
  delete process.env.DFIR_KEV_ALLOW_INTERNAL_URL;
});

describe("POST /kev/import-url — SSRF guard", () => {
  it("refuses the cloud metadata address with 400, without fetching it", async () => {
    let called = false;
    globalThis.fetch = async () => {
      called = true;
      return new Response("ami-id\nami-launch-index\n", { status: 200 });
    };

    const res = await request(app)
      .post("/kev/import-url")
      .send({ url: "http://169.254.169.254/latest/meta-data/" });

    expect(res.status).toBe(400);
    expect(called, "the guard must reject BEFORE the request leaves the host").toBe(false);
  });

  it.each([
    "http://127.0.0.1:3000/api/keys",
    "http://localhost:9090/metrics",
    "https://10.0.0.5/internal.json",
    "file:///etc/passwd",
  ])("refuses %s with 400", async (url) => {
    globalThis.fetch = async () => new Response("{}", { status: 200 });
    const res = await request(app).post("/kev/import-url").send({ url });
    expect(res.status).toBe(400);
  });

  // The leak the issue missed. V8's SyntaxError quotes the input: `Unexpected token 'a',
  // "ami-id\nam"... is not valid JSON`. Echoing err.message turned the SSRF into a read primitive
  // against ANY endpoint, not only KEV-shaped ones.
  it("never echoes fetched response content back in an error message", async () => {
    globalThis.fetch = async () => new Response("SECRET-TOKEN-abc123 not json at all", { status: 200 });

    const res = await request(app).post("/kev/import-url").send({ url: "https://mirror.example/x.json" });

    expect(res.status).toBe(502);
    expect(JSON.stringify(res.body)).not.toContain("SECRET-TOKEN");
  });

  it("caps the response body instead of reading it all into memory", async () => {
    globalThis.fetch = async () =>
      new Response("x".repeat(64), {
        status: 200,
        headers: { "content-length": String(64 * 1024 * 1024) },
      });

    const res = await request(app).post("/kev/import-url").send({ url: "https://mirror.example/x.json" });

    expect(res.status).toBe(502);
    expect(res.body.error).toMatch(/limit/i);
  });

  it("imports a real KEV feed from a public https URL", async () => {
    globalThis.fetch = async () => new Response(JSON.stringify(KEV_FEED), { status: 200 });

    const res = await request(app)
      .post("/kev/import-url")
      .send({ url: "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json" });

    expect(res.status).toBe(200);
    expect(res.body.total).toBe(1);
  });

  it("defaults to the CISA feed when no url is given (what the dashboard sends)", async () => {
    let requested = "";
    globalThis.fetch = async (input: unknown) => {
      requested = String(input);
      return new Response(JSON.stringify(KEV_FEED), { status: 200 });
    };

    const res = await request(app).post("/kev/import-url").send({});

    expect(res.status).toBe(200);
    expect(requested).toContain("cisa.gov");
  });

  it.each(["1", "true", "yes", "on"])(
    "allows an internal mirror when the operator opts in with %s",
    async (flag) => {
      process.env.DFIR_KEV_ALLOW_INTERNAL_URL = flag;
      globalThis.fetch = async () => new Response(JSON.stringify(KEV_FEED), { status: 200 });

      const res = await request(app).post("/kev/import-url").send({ url: "http://10.0.0.5/kev.json" });

      expect(res.status).toBe(200);
      expect(res.body.total).toBe(1);
    },
  );

  // The Settings field is a text input, and Save writes an empty string when the analyst clears it.
  // A blank or "false" value has to mean OFF, or a security toggle turned on from the dashboard
  // could never be turned back off from there.
  it.each(["", "false", "0", "off"])("treats %s as off", async (flag) => {
    process.env.DFIR_KEV_ALLOW_INTERNAL_URL = flag;
    globalThis.fetch = async () => new Response(JSON.stringify(KEV_FEED), { status: 200 });

    const res = await request(app).post("/kev/import-url").send({ url: "http://10.0.0.5/kev.json" });

    expect(res.status).toBe(400);
  });
});

describe("POST /kev/import-url — catalog integrity", () => {
  // ingestRaw wrote the fetched body to disk BEFORE checking it was a KEV feed. GET /kev then read
  // catalogVersion and dateReleased straight back out of that file — a second read-back channel,
  // and a way to destroy a working catalog with one bad URL.
  it("does not overwrite the catalog with a body that is not a KEV feed", async () => {
    globalThis.fetch = async () => new Response(JSON.stringify(KEV_FEED), { status: 200 });
    await request(app).post("/kev/import-url").send({});

    globalThis.fetch = async () =>
      new Response(JSON.stringify({ catalogVersion: "LEAKED-INTERNAL-VALUE", tokens: ["s3cr3t"] }), {
        status: 200,
      });
    const res = await request(app).post("/kev/import-url").send({ url: "https://mirror.example/x.json" });

    expect(res.status).toBe(502);

    const stored = await readFile(catalogFile, "utf8").catch(() => "");
    expect(stored).not.toContain("LEAKED-INTERNAL-VALUE");

    const meta = await request(app).get("/kev");
    expect(meta.body.count).toBe(1);
    expect(meta.body.catalogVersion).toBe("2026.09.01");
  });
});
