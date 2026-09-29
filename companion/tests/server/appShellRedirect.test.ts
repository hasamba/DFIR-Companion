import { describe, it, expect } from "vitest";
import { mkdtemp } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import request from "supertest";
import { CaseStore } from "../../src/storage/caseStore.js";
import { createApp } from "../../src/server.js";

async function makeApp() {
  const root = await mkdtemp(join(tmpdir(), "dfir-appshell-"));
  return createApp(new CaseStore(root), {});
}

describe("GET / redirect (app shell)", () => {
  it("redirects a bare / to /dashboard", async () => {
    const res = await request(await makeApp()).get("/");
    expect(res.status).toBe(302);
    expect(res.headers.location).toBe("/dashboard");
  });

  it("keeps the query string, so /?caseId=demo opens the demo case", async () => {
    const res = await request(await makeApp()).get("/?caseId=demo");
    expect(res.status).toBe(302);
    expect(res.headers.location).toBe("/dashboard?caseId=demo");
  });

  it("never lets the query choose the redirect target (no open redirect)", async () => {
    const app = await makeApp();
    for (const q of ["?//evil.example.com", "?next=https://evil.example.com", "?/\\evil.example.com"]) {
      const res = await request(app).get(`/${q}`);
      expect(res.status).toBe(302);
      expect(res.headers.location.startsWith("/dashboard?")).toBe(true);
    }
  });

  it("does not redirect a protocol-relative path such as //evil", async () => {
    const res = await request(await makeApp()).get("//evil.example.com");
    expect(res.headers.location ?? "").not.toMatch(/evil/);
  });
});
