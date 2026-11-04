import { describe, it, expect, vi } from "vitest";
import { fetchOutbound, OutboundUrlBlockedError } from "../../src/routes/outboundFetchGuard.js";

// What a followed redirect RE-SENDS (#2269). The guard already checks WHERE each hop goes; these
// tests pin WHAT goes with it: 303 (and POST on 301/302) become a bodiless GET, 307/308 keep the
// request, and a hop to another origin is refused while the request still carries caller headers
// or a body — a custom API-key header is just as much a credential as Authorization.

const PUBLIC = async (): Promise<Array<{ address: string; family: number }>> => [
  { address: "93.184.216.34", family: 4 },
];

function redirect(status: number, location: string): Response {
  return new Response(null, { status, headers: { location } });
}

function ok(): Response {
  return new Response("{}", { status: 200 });
}

function twoHops(status: number, location: string) {
  return vi.fn().mockResolvedValueOnce(redirect(status, location)).mockResolvedValueOnce(ok());
}

type Init = RequestInit | undefined;

function hopInit(fetchImpl: ReturnType<typeof vi.fn>, index: number): RequestInit {
  return (fetchImpl.mock.calls[index] as [URL, Init])[1] ?? {};
}

async function follow(
  url: string,
  fetchImpl: ReturnType<typeof vi.fn>,
  request: Pick<RequestInit, "method" | "headers" | "body">,
): Promise<void> {
  const result = await fetchOutbound(url, { resolveHost: PUBLIC, fetchImpl, request });
  await result.dispose();
}

const POST_JSON = (): Pick<RequestInit, "method" | "headers" | "body"> => ({
  method: "POST",
  headers: { "content-type": "application/json", "content-length": "2", "x-trace": "1" },
  body: "{}",
});

describe("fetchOutbound — what a redirect re-sends", () => {
  it.each([303, 302, 301])("%i after a POST switches to a bodiless GET", async (status) => {
    const fetchImpl = twoHops(status, "https://a.example/next");
    await follow("https://a.example/start", fetchImpl, POST_JSON());

    const second = hopInit(fetchImpl, 1);
    const headers = new Headers(second.headers);
    expect(second.method).toBe("GET");
    expect(second.body).toBeUndefined();
    expect(headers.has("content-type")).toBe(false);
    expect(headers.has("content-length")).toBe(false);
    expect(headers.get("x-trace")).toBe("1");
  });

  it("303 after a PUT also switches to GET", async () => {
    const fetchImpl = twoHops(303, "https://a.example/next");
    await follow("https://a.example/start", fetchImpl, { ...POST_JSON(), method: "PUT" });
    expect(hopInit(fetchImpl, 1).method).toBe("GET");
    expect(hopInit(fetchImpl, 1).body).toBeUndefined();
  });

  it.each([307, 308])("%i keeps the method, body and body headers", async (status) => {
    const fetchImpl = twoHops(status, "https://a.example/next");
    await follow("https://a.example/start", fetchImpl, POST_JSON());

    const second = hopInit(fetchImpl, 1);
    expect(second.method).toBe("POST");
    expect(second.body).toBe("{}");
    expect(new Headers(second.headers).get("content-type")).toBe("application/json");
  });

  it.each([301, 302])("%i after a PUT keeps the method and body (only POST is rewritten)", async (status) => {
    const fetchImpl = twoHops(status, "https://a.example/next");
    await follow("https://a.example/start", fetchImpl, { ...POST_JSON(), method: "PUT" });

    const second = hopInit(fetchImpl, 1);
    expect(second.method).toBe("PUT");
    expect(second.body).toBe("{}");
  });

  it("builds each hop from the previous one: a GET from a 303 stays a GET through a later 307", async () => {
    const fetchImpl = vi
      .fn()
      .mockResolvedValueOnce(redirect(303, "https://a.example/two"))
      .mockResolvedValueOnce(redirect(307, "https://a.example/three"))
      .mockResolvedValueOnce(ok());
    await follow("https://a.example/one", fetchImpl, POST_JSON());

    const third = hopInit(fetchImpl, 2);
    expect(third.method).toBe("GET");
    expect(third.body).toBeUndefined();
    expect(new Headers(third.headers).has("content-type")).toBe(false);
  });

  it("never mutates the caller's request or its headers object", async () => {
    const headers = { "content-type": "application/json", "x-trace": "1" };
    const request = { method: "POST", headers, body: "{}" };
    const fetchImpl = twoHops(303, "https://a.example/next");
    await follow("https://a.example/start", fetchImpl, request);

    expect(request).toEqual({
      method: "POST",
      headers: { "content-type": "application/json", "x-trace": "1" },
      body: "{}",
    });
    expect(headers).toEqual({ "content-type": "application/json", "x-trace": "1" });
  });

  it("keeps Authorization on a same-origin redirect", async () => {
    const fetchImpl = twoHops(307, "https://a.example/y");
    await follow("https://a.example/x", fetchImpl, { headers: { authorization: "Bearer s3cret" } });
    expect(new Headers(hopInit(fetchImpl, 1).headers).get("authorization")).toBe("Bearer s3cret");
  });
});

describe("fetchOutbound — a redirect to another origin carries nothing of the caller's", () => {
  it.each([
    ["a custom API-key header", { headers: { "x-api-key": "k3y" } }],
    ["Authorization", { headers: { authorization: "Bearer s3cret" } }],
    ["Cookie", { headers: { cookie: "a=b" } }],
    ["a body", { method: "POST", body: '{"token":"t"}' }],
  ])("refuses a cross-origin 307 when the request carries %s", async (_label, request) => {
    const fetchImpl = twoHops(307, "https://b.example/next");
    await expect(follow("https://a.example/start", fetchImpl, request)).rejects.toBeInstanceOf(
      OutboundUrlBlockedError,
    );
    expect(fetchImpl).toHaveBeenCalledTimes(1);
  });

  it.each([
    ["the port", "https://a.example:8443/next"],
    ["the scheme", "http://a.example/next"],
  ])("treats a change of %s as another origin", async (_label, location) => {
    const fetchImpl = twoHops(307, location);
    const request = { headers: { "x-api-key": "k3y" } };
    const run = fetchOutbound("https://a.example/start", {
      resolveHost: PUBLIC,
      fetchImpl,
      request,
      policy: "lan",
    });
    await expect(run).rejects.toThrow(/origin/);
    expect(fetchImpl).toHaveBeenCalledTimes(1);
  });

  it("follows a cross-origin 303 once the body is gone and no caller header is left", async () => {
    const fetchImpl = twoHops(303, "https://b.example/next");
    await follow("https://a.example/start", fetchImpl, {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: "{}",
    });
    const second = hopInit(fetchImpl, 1);
    expect(second.method).toBe("GET");
    expect(second.body).toBeUndefined();
    expect([...new Headers(second.headers).keys()]).toEqual([]);
  });

  it("still follows a cross-origin redirect for a plain GET with no request (the feed callers)", async () => {
    const fetchImpl = twoHops(302, "https://mirror.example/feed.json");
    const result = await fetchOutbound("https://www.cisa.gov/feed.json", { resolveHost: PUBLIC, fetchImpl });
    expect(result.url.href).toBe("https://mirror.example/feed.json");
    await result.dispose();
  });
});
