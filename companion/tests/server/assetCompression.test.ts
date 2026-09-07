import { describe, it, expect } from "vitest";
import { mkdtemp } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import request from "supertest";
import { CaseStore } from "../../src/storage/caseStore.js";
import { createApp } from "../../src/server.js";

// The dashboard document is ~507 KB and ships beside ~140 first-party JS files, none of which were
// compressed. Irrelevant on the loopback the tool is built for; it is the whole cost on the public
// demo, a VPN-hosted deployment, or an analyst on field connectivity. #882
async function app() {
  const root = await mkdtemp(join(tmpdir(), "dfir-compress-"));
  return createApp(new CaseStore(root), { appVersion: "0.36.0" });
}

describe("static asset compression", () => {
  it("gzips the dashboard document for a client that accepts it", async () => {
    const res = await request(await app())
      .get("/dashboard")
      .set("Accept-Encoding", "gzip");

    expect(res.status).toBe(200);
    expect(res.headers["content-encoding"]).toBe("gzip");
    // supertest decodes the body, so the assertion that it is still the real document holds.
    expect(res.text).toContain("<!doctype html>");
    expect(res.text).toContain('id="bootSplash"');
  });

  it("gzips a whitelisted script", async () => {
    const res = await request(await app())
      .get("/js/safe-dom.js")
      .set("Accept-Encoding", "gzip");

    expect(res.status).toBe(200);
    expect(res.headers["content-encoding"]).toBe("gzip");
  });

  it("sends identity bytes to a client that does not accept gzip", async () => {
    const res = await request(await app())
      .get("/dashboard")
      .set("Accept-Encoding", "identity");

    expect(res.status).toBe(200);
    expect(res.headers["content-encoding"]).toBeUndefined();
    expect(res.text).toContain("<!doctype html>");
  });

  it("varies on Accept-Encoding either way, so a shared cache cannot cross the two", async () => {
    const gz = await request(await app())
      .get("/dashboard")
      .set("Accept-Encoding", "gzip");
    const id = await request(await app())
      .get("/dashboard")
      .set("Accept-Encoding", "identity");

    expect(gz.headers["vary"]).toMatch(/Accept-Encoding/i);
    expect(id.headers["vary"]).toMatch(/Accept-Encoding/i);
  });
});
