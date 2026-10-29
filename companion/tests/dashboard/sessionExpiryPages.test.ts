import { describe, it, expect } from "vitest";
import { readFileSync } from "node:fs";
import { runInNewContext } from "node:vm";

// The mobile and presentation pages under an expired team session, and the mobile service worker's
// offline shell (#2260). Neither page has a DOM harness, so the mobile fetch helper and the service
// worker are run for real in a vm with stubbed globals; present.html is pinned at source level.

const read = (rel: string): string => readFileSync(new URL(rel, import.meta.url), "utf8");

interface FakeResponse {
  ok: boolean;
  status: number;
  redirected: boolean;
  type: string;
  clone: () => FakeResponse;
  json: () => Promise<unknown>;
}

function response(over: Partial<FakeResponse> = {}): FakeResponse {
  const r: FakeResponse = {
    ok: true,
    status: 200,
    redirected: false,
    type: "basic",
    clone: () => r,
    json: async () => ({}),
    ...over,
  };
  return r;
}

describe("public/sw.js — the offline shell (#2260)", () => {
  async function navigate(res: FakeResponse): Promise<string[]> {
    const puts: string[] = [];
    const listeners: Record<string, (e: unknown) => void> = {};
    const cache = { put: async (url: string) => void puts.push(url), add: async () => undefined };
    const sandbox = {
      self: {
        addEventListener: (type: string, fn: (e: unknown) => void) => (listeners[type] = fn),
        skipWaiting: () => undefined,
        clients: { claim: () => undefined },
      },
      caches: {
        open: async () => cache,
        keys: async () => [],
        match: async () => undefined,
        delete: async () => true,
      },
      fetch: async () => res,
      Response: { error: () => null },
      Promise,
    };
    runInNewContext(read("../../../public/sw.js"), sandbox);
    let responded: Promise<unknown> = Promise.resolve();
    listeners.fetch({
      request: { method: "GET", mode: "navigate" },
      respondWith: (p: Promise<unknown>) => (responded = p),
    });
    await responded;
    await new Promise((r) => setTimeout(r, 0)); // let the fire-and-forget cache.put settle
    return puts;
  }

  it("caches a real 200 shell", async () => {
    expect(await navigate(response())).toEqual(["/mobile"]);
  });

  it("never caches the login page a redirected navigation lands on", async () => {
    expect(await navigate(response({ redirected: true }))).toEqual([]);
  });

  it("never caches an error page or an opaque response", async () => {
    expect(await navigate(response({ ok: false, status: 500 }))).toEqual([]);
    expect(await navigate(response({ type: "opaque" }))).toEqual([]);
  });
});

describe("public/mobile.html — getJson on an expired session (#2260)", () => {
  function loadGetJson(res: FakeResponse) {
    const html = read("../../../public/mobile.html");
    const start = html.indexOf("    function redirectToLogin()");
    const end = html.indexOf("    function setHeader(");
    expect(start, "redirectToLogin() must sit next to getJson()").toBeGreaterThan(-1);
    const assigned: string[] = [];
    const sandbox: Record<string, unknown> = {
      fetch: async () => res,
      location: {
        pathname: "/mobile",
        search: "",
        hash: "#/case/c1",
        assign: (u: string) => assigned.push(u),
      },
      encodeURIComponent,
      Error,
    };
    runInNewContext(html.slice(start, end) + "\nthis.getJson = getJson;", sandbox);
    return { getJson: sandbox.getJson as (u: string) => Promise<unknown>, assigned };
  }

  it("sends a 401 to /login with the page (hash route included) as returnTo", async () => {
    const { getJson, assigned } = loadGetJson(response({ ok: false, status: 401 }));
    await expect(getJson("/cases")).rejects.toMatchObject({ status: 401 });
    expect(assigned).toEqual(["/login?returnTo=" + encodeURIComponent("/mobile#/case/c1")]);
  });

  it("does not redirect on any other failure", async () => {
    const { getJson, assigned } = loadGetJson(response({ ok: false, status: 500 }));
    await expect(getJson("/cases")).rejects.toMatchObject({ status: 500 });
    expect(assigned).toEqual([]);
  });
});

describe("public/present.html — load() on an expired session (#2260)", () => {
  const html = read("../../../public/present.html");
  const load = html.slice(html.indexOf("  function load()"), html.indexOf("  // Auto-advance."));

  it("redirects a 401 to /login instead of asking whether the server is running", () => {
    expect(load).toMatch(/r\.status === 401/);
    expect(load).toContain(
      'location.assign("/login?returnTo=" + encodeURIComponent(location.pathname + location.search + location.hash))',
    );
  });

  it("keeps 'is the server running?' for server errors and network failures only", () => {
    expect(load).toMatch(
      /r\.status >= 500\) throw new Error\("HTTP " \+ r\.status \+ " — is the companion server running\?"\)/,
    );
    expect(load).toMatch(/if \(!r\.ok\) throw new Error\("HTTP " \+ r\.status\);/);
  });
});
