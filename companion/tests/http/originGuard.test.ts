import { describe, it, expect } from "vitest";
import express, { type Express } from "express";
import request from "supertest";
import {
  isOriginAllowed,
  isHostAllowed,
  isRequestAllowed,
  parseAllowedOrigins,
  parseAllowedHosts,
  parseAllowedHostSuffixes,
  createOriginGuard,
  type GuardConfig,
} from "../../src/http/originGuard.js";

// A minimal app carrying the guard plus one route of each shape the real server exposes.
function guarded(cfg: GuardConfig = {}): Express {
  const app = express();
  app.use(createOriginGuard(cfg));
  app.use(express.json());
  app.get("/tools/custom", (_req, res) => res.status(200).json({ tools: [] }));
  app.post("/tools/custom", (_req, res) => res.status(201).json({ ok: true }));
  app.get("/health", (_req, res) => res.status(200).json({ ok: true }));
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

describe("isHostAllowed", () => {
  it("allows loopback, on any port and in either IP family", () => {
    expect(isHostAllowed("127.0.0.1:4773", {})).toBe(true);
    expect(isHostAllowed("localhost:4773", {})).toBe(true);
    expect(isHostAllowed("[::1]:4773", {})).toBe(true);
    expect(isHostAllowed("localhost", {})).toBe(true);
  });

  it("allows a bare IP literal so investigators can reach the dashboard over the LAN with no config", () => {
    // This is the whole reason the Host gate can be strict without breaking anyone: a rebinding
    // attack always puts the attacker's DOMAIN NAME in Host, never a raw address. Serving on
    // 0.0.0.0 and browsing to http://192.168.1.50:4773 is therefore safe to allow outright.
    expect(isHostAllowed("192.168.1.50:4773", {})).toBe(true);
    expect(isHostAllowed("10.4.0.9", {})).toBe(true);
    expect(isHostAllowed("[fe80::1]:4773", {})).toBe(true);
  });

  it("rejects a hostname that is not configured — this is the DNS-rebinding stop (CWE-346)", () => {
    // evil.example rebinds to 127.0.0.1. The browser sends Host: evil.example:4773, and no
    // rebinding attack can avoid that, so refusing unknown names ends the attack outright.
    expect(isHostAllowed("evil.example:4773", {})).toBe(false);
    expect(isHostAllowed("dfir.example.com", {})).toBe(false);
  });

  it("allows a host listed in DFIR_ALLOWED_HOSTS, ignoring the port", () => {
    expect(isHostAllowed("dfir.example.com:8443", { allowedHosts: ["dfir.example.com"] })).toBe(true);
  });

  it("allows the host of a configured origin, so a deployment is named only once", () => {
    // Railway sets DFIR_ALLOWED_ORIGINS=https://demo.up.railway.app; requiring the operator to
    // repeat that host in a second variable would be a footgun with no security benefit.
    expect(isHostAllowed("demo.up.railway.app", { allowedOrigins: ["https://demo.up.railway.app"] })).toBe(true);
  });

  it("allows a configured suffix, for platforms that hand out a fresh hostname per session", () => {
    // Killercoda proxies port 4773 through a per-session hostname, so only the suffix is knowable.
    const cfg: GuardConfig = { allowedHostSuffixes: [".killercoda.com"] };
    expect(isHostAllowed("abc123-4773.environments.killercoda.com", cfg)).toBe(true);
    expect(isHostAllowed("killercoda.com", cfg)).toBe(true);
  });

  it("matches a suffix only on a label boundary, never as a bare string ending", () => {
    const cfg: GuardConfig = { allowedHostSuffixes: [".killercoda.com"] };
    expect(isHostAllowed("evilkillercoda.com", cfg)).toBe(false);
    expect(isHostAllowed("killercoda.com.evil.example", cfg)).toBe(false);
  });

  it("allows a request with no Host header at all", () => {
    // Only pre-HTTP/1.1 and hand-rolled clients omit Host; a browser always sends it, so there is
    // no rebinding vector here and refusing would break scripted callers for nothing.
    expect(isHostAllowed(undefined, {})).toBe(true);
  });

  it("rejects a malformed Host header rather than guessing", () => {
    expect(isHostAllowed("not a host", {})).toBe(false);
    expect(isHostAllowed("evil.example:notaport", {})).toBe(false);
  });

  it("is case-insensitive, since DNS names are", () => {
    expect(isHostAllowed("DFIR.Example.COM", { allowedHosts: ["dfir.example.com"] })).toBe(true);
    expect(isHostAllowed("LOCALHOST:4773", {})).toBe(true);
  });
});

describe("isRequestAllowed", () => {
  it("refuses a rebound request that carries no Origin, which the origin check alone lets through", () => {
    // The gap this closes: under rebinding the browser believes it is same-origin, so a GET carries
    // NO Origin header — the origin gate waves it through and the page reads back every response.
    // The Host check is what stops it.
    expect(isOriginAllowed(undefined, [])).toBe(true); // origin gate alone: allowed
    const decision = isRequestAllowed({ host: "evil.example:4773" }, {});
    expect(decision.ok).toBe(false);
  });

  it("refuses a rebound request that does carry an Origin", () => {
    expect(isRequestAllowed({ origin: "http://evil.example:4773", host: "evil.example:4773" }, {}).ok).toBe(false);
  });

  it("allows the dashboard served from a LAN address, including its writes and its WebSocket", () => {
    // Origin and Host match because the page really was served by this companion. That shortcut is
    // safe ONLY because the Host was validated first — which is the bug PR #280 found.
    const decision = isRequestAllowed({ origin: "http://192.168.1.50:4773", host: "192.168.1.50:4773" }, {});
    expect(decision.ok).toBe(true);
  });

  it("allows a hosted deployment once its origin is configured", () => {
    const cfg: GuardConfig = { allowedOrigins: ["https://demo.up.railway.app"] };
    expect(isRequestAllowed({ origin: "https://demo.up.railway.app", host: "demo.up.railway.app" }, cfg).ok).toBe(true);
  });

  it("allows the capture extension talking to loopback", () => {
    const req = { origin: "chrome-extension://abcdefghijklmnopabcdefghijklmnop", host: "127.0.0.1:4773" };
    expect(isRequestAllowed(req, {}).ok).toBe(true);
  });

  it("allows a scripted caller with neither header", () => {
    expect(isRequestAllowed({}, {}).ok).toBe(true);
  });

  it("still refuses a plain cross-origin page pointed at loopback", () => {
    // No rebinding: the Host is legitimately 127.0.0.1, but the page's own origin is not trusted.
    const decision = isRequestAllowed({ origin: "https://evil.example", host: "127.0.0.1:4773" }, {});
    expect(decision.ok).toBe(false);
  });

  it("does not let a page on one LAN address speak for another", () => {
    // The Origin==Host shortcut must be an equality check, not a family check: a rogue box at
    // 192.168.1.99 is a different origin from the companion at 192.168.1.50.
    const decision = isRequestAllowed({ origin: "http://192.168.1.99", host: "192.168.1.50:4773" }, {});
    expect(decision.ok).toBe(false);
  });

  it("says which gate refused, so the 403 body and the ws close reason can be specific", () => {
    const byHost = isRequestAllowed({ host: "evil.example" }, {});
    const byOrigin = isRequestAllowed({ origin: "https://evil.example", host: "127.0.0.1:4773" }, {});
    expect(byHost.ok === false && byHost.kind).toBe("host");
    expect(byOrigin.ok === false && byOrigin.kind).toBe("origin");
  });
});

describe("parseAllowedHosts", () => {
  it("splits a comma-separated list, lowercases, and drops blanks", () => {
    expect(parseAllowedHosts(" A.Example , ,b.example ")).toEqual(["a.example", "b.example"]);
  });

  it("tolerates a pasted origin or trailing slash and keeps only the host", () => {
    expect(parseAllowedHosts("https://a.example/, http://b.example:8443/")).toEqual(["a.example", "b.example"]);
  });

  it("returns an empty list for undefined or blank config", () => {
    expect(parseAllowedHosts(undefined)).toEqual([]);
    expect(parseAllowedHosts("   ")).toEqual([]);
  });
});

describe("parseAllowedHostSuffixes", () => {
  it("splits a comma-separated list, lowercases, and gives every entry a leading dot", () => {
    // A missing dot is the whole footgun this parser exists to remove: "acme.com" as a raw suffix
    // would also match "evilacme.com".
    expect(parseAllowedHostSuffixes("killercoda.com, .Example.COM")).toEqual([".killercoda.com", ".example.com"]);
  });

  it("returns an empty list for undefined or blank config", () => {
    expect(parseAllowedHostSuffixes(undefined)).toEqual([]);
    expect(parseAllowedHostSuffixes("  , ")).toEqual([]);
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

  it("blocks a rebound GET that carries no Origin, before the route can answer", async () => {
    // The end-to-end version of the gap: a rebound page issues what the browser considers a
    // same-origin GET (no Origin header) and reads the JSON straight out of the response.
    const res = await request(guarded()).get("/tools/custom").set("Host", "evil.example:4773");
    expect(res.status).toBe(403);
    expect(res.body.tools).toBeUndefined();
    expect(res.body.error).toMatch(/host/i);
  });

  it("blocks a rebound WebSocket-shaped upgrade the same way", async () => {
    const res = await request(guarded())
      .get("/tools/custom")
      .set("Host", "evil.example:4773")
      .set("Origin", "http://evil.example:4773");
    expect(res.status).toBe(403);
  });

  it("serves the dashboard to another investigator on the LAN, writes included", async () => {
    const res = await request(guarded())
      .post("/tools/custom")
      .set("Host", "192.168.1.50:4773")
      .set("Origin", "http://192.168.1.50:4773")
      .send({ name: "ok" });
    expect(res.status).toBe(201);
    expect(res.headers["access-control-allow-origin"]).toBe("http://192.168.1.50:4773");
  });

  it("answers the liveness probe whatever Host the platform's checker uses", async () => {
    // Railway, Kubernetes and friends probe /health from their own infrastructure and send a Host
    // of their choosing (Railway uses healthcheck.railway.app). Applying the host allow-list here
    // would fail every deploy. The route is a capability flag dump — no case data, no secrets.
    const res = await request(guarded()).get("/health").set("Host", "healthcheck.railway.app");
    expect(res.status).toBe(200);
    expect(res.body.ok).toBe(true);
  });

  it("does not extend the probe exemption to any other route", async () => {
    const res = await request(guarded()).get("/tools/custom").set("Host", "healthcheck.railway.app");
    expect(res.status).toBe(403);
  });

  it("still refuses a cross-origin page reading the probe", async () => {
    // The Host exemption is for infrastructure, which sends no Origin. A real page still has one,
    // and it is still judged.
    const res = await request(guarded())
      .get("/health")
      .set("Host", "127.0.0.1:4773")
      .set("Origin", "https://evil.example");
    expect(res.status).toBe(403);
  });

  it("serves a platform-proxied host once its suffix is configured", async () => {
    const cfg: GuardConfig = { allowedHostSuffixes: [".killercoda.com"] };
    const res = await request(guarded(cfg))
      .get("/tools/custom")
      .set("Host", "abc123-4773.environments.killercoda.com")
      .set("Origin", "https://abc123-4773.environments.killercoda.com");
    expect(res.status).toBe(200);
  });
});
