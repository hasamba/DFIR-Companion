import { describe, it, expect } from "vitest";
import express, { type Express } from "express";
import request from "supertest";
import { CSP_POLICY, createSecurityHeaders } from "../../src/http/securityHeaders.js";

// A minimal app carrying the headers plus one route of each shape the real server exposes.
function withHeaders(): Express {
  const app = express();
  app.use(createSecurityHeaders());
  app.get("/dashboard", (_req, res) => res.type("html").send("<!doctype html><p>hi"));
  app.get("/cases/abc", (_req, res) => res.status(200).json({ id: "abc" }));
  return app;
}

/** Split the CSP header into `directive -> source list` for assertions that don't care about order. */
function directives(header: string): Record<string, string> {
  const out: Record<string, string> = {};
  for (const part of header.split(";")) {
    const [name, ...sources] = part.trim().split(/\s+/);
    if (name) out[name] = sources.join(" ");
  }
  return out;
}

describe("createSecurityHeaders — CSP on every response", () => {
  it("sends a Content-Security-Policy on the dashboard document", async () => {
    const res = await request(withHeaders()).get("/dashboard");
    expect(res.headers["content-security-policy"]).toBe(CSP_POLICY);
  });

  it("sends it on API responses too, so an injected script has no unguarded route to abuse", async () => {
    const res = await request(withHeaders()).get("/cases/abc");
    expect(res.headers["content-security-policy"]).toBe(CSP_POLICY);
  });
});

describe("CSP_POLICY — the directives, and deliberately nothing more", () => {
  const d = directives(CSP_POLICY);

  // Step 1 — free hardening. None of these interact with inline code, so nothing can break.
  it("forbids framing, plugins, <base> rewrites and form posts", () => {
    expect(d["frame-ancestors"]).toBe("'none'"); // clickjacking
    expect(d["object-src"]).toBe("'none'");       // <object>/<embed> script smuggling
    expect(d["base-uri"]).toBe("'none'");         // an injected <base> re-pointing every relative URL
    expect(d["form-action"]).toBe("'none'");      // all 5 dashboard forms are onsubmit="return false"
  });

  // Step 2 — the one that carries real weight while inline script is still allowed: an injected
  // script cannot beacon case data, provider API keys, or session state to an attacker host.
  it("confines network egress to this origin", () => {
    expect(d["connect-src"]).toBe("'self'");
  });

  // Step 3 — the dashboard inlines 27 data:image/svg icons, so data: must stay allowed for images.
  it("allows same-origin and data: images, nothing else", () => {
    expect(d["img-src"]).toBe("'self' data:");
  });

  // The guard rail on this PR's scope. The dashboard carries ~80 inline on*= handlers, 10 inline
  // <script> blocks and ~1157 style="" attributes. Constraining script/style — directly or via a
  // default-src fallback — would break all of them, so this policy must not mention them at all.
  // Removing inline script is a separate change that has to convert those handlers first.
  it("does not constrain scripts or styles, directly or by default-src fallback", () => {
    expect(d["default-src"]).toBeUndefined();
    expect(d["script-src"]).toBeUndefined();
    expect(d["style-src"]).toBeUndefined();
  });
});
