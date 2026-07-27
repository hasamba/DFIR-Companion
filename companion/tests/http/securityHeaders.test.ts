import { describe, it, expect } from "vitest";
import express, { type Express } from "express";
import request from "supertest";
import {
  CSP_POLICY,
  CSP_NONCE_PLACEHOLDER,
  cspWithNonce,
  withNonce,
  createSecurityHeaders,
} from "../../src/http/securityHeaders.js";

// A minimal app carrying the headers plus one route of each shape the real server exposes.
function withHeaders(): Express {
  const app = express();
  app.use(createSecurityHeaders());
  app.get("/dashboard", (_req, res) => res.type("html").send("<!doctype html><p>hi"));
  app.get("/cases/abc", (_req, res) => res.status(200).json({ id: "abc" }));
  app.get("/nonce-echo", (_req, res) => res.type("text").send(String(res.locals.cspNonce ?? "")));
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

/** Pull the nonce back out of a sent CSP header. */
function nonceOf(header: string): string | undefined {
  return /'nonce-([A-Za-z0-9+/=_-]+)'/.exec(header)?.[1];
}

describe("createSecurityHeaders — CSP on every response", () => {
  it("sends a Content-Security-Policy on the dashboard document", async () => {
    const res = await request(withHeaders()).get("/dashboard");
    expect(res.headers["content-security-policy"]).toContain(CSP_POLICY);
  });

  it("sends it on API responses too, so an injected script has no unguarded route to abuse", async () => {
    const res = await request(withHeaders()).get("/cases/abc");
    expect(res.headers["content-security-policy"]).toContain(CSP_POLICY);
  });

  it("carries script-src 'self' plus a per-response nonce", async () => {
    const res = await request(withHeaders()).get("/dashboard");
    const header = res.headers["content-security-policy"];
    expect(header).toContain("script-src 'self' 'nonce-");
    expect(nonceOf(header)).toBeTruthy();
  });

  // A nonce reused across responses is worth no more than 'unsafe-inline': an attacker who can read
  // one page can embed last request's nonce in the payload for the next.
  it("mints a fresh nonce per response", async () => {
    const app = withHeaders();
    const a = nonceOf((await request(app).get("/dashboard")).headers["content-security-policy"]);
    const b = nonceOf((await request(app).get("/dashboard")).headers["content-security-policy"]);
    expect(a).toBeTruthy();
    expect(a).not.toBe(b);
  });

  it("exposes the same nonce to the route via res.locals, so the HTML can match the header", async () => {
    const res = await request(withHeaders()).get("/nonce-echo");
    expect(res.text).toBe(nonceOf(res.headers["content-security-policy"]));
  });
});

describe("withNonce — stamping the served HTML", () => {
  it("replaces every placeholder occurrence, not just the first", () => {
    const html = `<script nonce="${CSP_NONCE_PLACEHOLDER}">a</script>`
      + `<script nonce="${CSP_NONCE_PLACEHOLDER}">b</script>`;
    const out = withNonce(html, "abc123");
    expect(out).toBe('<script nonce="abc123">a</script><script nonce="abc123">b</script>');
    expect(out).not.toContain(CSP_NONCE_PLACEHOLDER);
  });

  it("leaves HTML without the placeholder untouched", () => {
    expect(withNonce("<p>hi</p>", "abc123")).toBe("<p>hi</p>");
  });
});

describe("cspWithNonce", () => {
  it("keeps every base directive and adds script-src", () => {
    const policy = cspWithNonce("n0nce");
    for (const directive of CSP_POLICY.split("; ")) expect(policy).toContain(directive);
    expect(policy).toContain("script-src 'self' 'nonce-n0nce'");
  });

  // 'unsafe-inline' would silently undo the whole change: browsers ignore it when a nonce is
  // present in CSP3, but a CSP2-only client would honour it and run injected inline script.
  it("never emits 'unsafe-inline' for scripts", () => {
    expect(cspWithNonce("n0nce")).not.toContain("unsafe-inline");
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
