import { describe, it, expect } from "vitest";
import express, { type Express } from "express";
import request from "supertest";
import { isOriginAllowed, parseAllowedOrigins, createOriginGuard } from "../../src/http/originGuard.js";

// A minimal app carrying the guard plus one route of each shape the real server exposes.
function guarded(allowedOrigins: string[] = []): Express {
  const app = express();
  app.use(createOriginGuard({ allowedOrigins }));
  app.use(express.json());
  app.get("/tools/custom", (_req, res) => res.status(200).json({ tools: [] }));
  app.post("/tools/custom", (_req, res) => res.status(201).json({ ok: true }));
  return app;
}

describe("isOriginAllowed", () => {
  it("allows a request with no Origin header at all (curl, scripts, Velociraptor pushes)", () => {
    // Non-browser clients never send Origin. They are not the threat this guard addresses —
    // any local process can already run code — and blocking them breaks every scripted push.
    expect(isOriginAllowed(undefined, [])).toBe(true);
  });

  it("allows the capture extension's chrome-extension:// origin", () => {
    // Unpacked installs get a random extension id, so the scheme is what we can rely on.
    expect(isOriginAllowed("chrome-extension://abcdefghijklmnopabcdefghijklmnop", [])).toBe(true);
    expect(isOriginAllowed("moz-extension://11112222-3333-4444-5555-666677778888", [])).toBe(true);
  });

  it("allows the dashboard on loopback, on any port", () => {
    expect(isOriginAllowed("http://127.0.0.1:4773", [])).toBe(true);
    expect(isOriginAllowed("http://localhost:9999", [])).toBe(true);
    expect(isOriginAllowed("http://[::1]:4773", [])).toBe(true);
  });

  it("trusts a hosted/reverse-proxied origin only when it is explicitly configured, never via the Host header", () => {
    // A public deployment (e.g. the Railway demo) serves the dashboard from a non-loopback https
    // origin. It is trusted by listing that origin in DFIR_ALLOWED_ORIGINS — NOT by matching the
    // request's own Host header, which is client-controlled and would open a DNS-rebinding hole.
    expect(isOriginAllowed("https://demo.example.app", [])).toBe(false);
    expect(isOriginAllowed("https://demo.example.app", ["https://demo.example.app"])).toBe(true);
  });

  it("rejects a rebound origin even though the attacker can make Origin and Host identical (CWE-346)", () => {
    // DNS-rebinding: evil.example resolves to 127.0.0.1, so the victim's browser sends
    // Origin: http://evil.example:4773 with a matching Host. The old Origin==Host branch trusted
    // this; trust must now come only from the origin's own value, so it is refused.
    expect(isOriginAllowed("http://evil.example:4773", [])).toBe(false);
  });

  it("allows an explicitly configured extra origin", () => {
    expect(isOriginAllowed("https://soc.example.com", ["https://soc.example.com"])).toBe(true);
  });

  it("rejects an arbitrary web page's origin", () => {
    expect(isOriginAllowed("https://evil.example", [])).toBe(false);
    expect(isOriginAllowed("http://evil.example", [])).toBe(false);
  });

  it("rejects an origin that merely embeds a trusted one as a substring", () => {
    expect(isOriginAllowed("https://127.0.0.1.evil.example", [])).toBe(false);
    expect(isOriginAllowed("https://localhost.evil.example", [])).toBe(false);
    expect(isOriginAllowed("https://evil.example/#http://localhost", [])).toBe(false);
  });

  it("rejects the literal null origin used by sandboxed iframes and data: URLs", () => {
    expect(isOriginAllowed("null", [])).toBe(false);
  });
});

describe("parseAllowedOrigins", () => {
  it("splits a comma-separated list and drops blanks and trailing slashes", () => {
    expect(parseAllowedOrigins(" https://a.example/ , ,https://b.example ")).toEqual([
      "https://a.example",
      "https://b.example",
    ]);
  });

  it("returns an empty list for undefined or blank config", () => {
    expect(parseAllowedOrigins(undefined)).toEqual([]);
    expect(parseAllowedOrigins("   ")).toEqual([]);
  });
});

describe("createOriginGuard", () => {
  it("blocks a cross-origin POST from a malicious page with 403 and never runs the route", async () => {
    const res = await request(guarded())
      .post("/tools/custom")
      .set("Origin", "https://evil.example")
      .send({ name: "pwn" });
    expect(res.status).toBe(403);
    expect(res.body.ok).toBeUndefined();
    expect(res.body.error).toMatch(/origin/i);
  });

  it("blocks a cross-origin GET too, so responses cannot be read back", async () => {
    const res = await request(guarded()).get("/tools/custom").set("Origin", "https://evil.example");
    expect(res.status).toBe(403);
  });

  it("fails the preflight for a disallowed origin without granting private-network access", async () => {
    const res = await request(guarded())
      .options("/tools/custom")
      .set("Origin", "https://evil.example")
      .set("Access-Control-Request-Method", "POST");
    expect(res.status).toBe(403);
    expect(res.headers["access-control-allow-origin"]).toBeUndefined();
    expect(res.headers["access-control-allow-private-network"]).toBeUndefined();
  });

  it("never answers with a wildcard Access-Control-Allow-Origin", async () => {
    const res = await request(guarded())
      .get("/tools/custom")
      .set("Origin", "chrome-extension://abcdefghijklmnopabcdefghijklmnop");
    expect(res.status).toBe(200);
    expect(res.headers["access-control-allow-origin"]).toBe("chrome-extension://abcdefghijklmnopabcdefghijklmnop");
    expect(res.headers.vary).toMatch(/Origin/);
  });

  it("still lets the extension through the preflight, with private-network access", async () => {
    const res = await request(guarded())
      .options("/tools/custom")
      .set("Origin", "chrome-extension://abcdefghijklmnopabcdefghijklmnop")
      .set("Access-Control-Request-Method", "POST");
    expect(res.status).toBe(204);
    expect(res.headers["access-control-allow-private-network"]).toBe("true");
    expect(res.headers["access-control-allow-methods"]).toMatch(/POST/);
  });

  it("lets a no-Origin request through untouched", async () => {
    const res = await request(guarded()).post("/tools/custom").send({ name: "ok" });
    expect(res.status).toBe(201);
    expect(res.headers["access-control-allow-origin"]).toBeUndefined();
  });
});
