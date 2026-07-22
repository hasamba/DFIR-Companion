import { describe, it, expect } from "vitest";
import { MispPushClient } from "../../src/integrations/misp/mispPushClient.js";

// These exercise the REAL HTTP layer with a stub fetch. The existing misp.test.ts mocks
// MispPushClientLike, so it never touched request/response handling — which is why three bugs
// survived to be found against a live MISP:
//   1. MISP answers some write failures with HTTP 200 + {"saved":false,"errors":"Invalid Tag."};
//      treating that as success meant tags silently no-opped while still being counted.
//   2. findEventByTag used GET /events/index?searchTag=&limit=, which a live MISP ignores (it
//      returned the whole 8800-event index) and which returns events FLAT, so [0].Event.id was
//      always undefined -> a prior event was never found -> every push duplicated the event.
//   3. A 403 was always reported as "the API key needs write access", even when MISP's body said
//      the value was malformed ("IP address has an invalid format.").

type Call = { url: string; method: string; body: unknown };

function stubFetch(handler: (call: Call) => { status?: number; json: unknown }) {
  const calls: Call[] = [];
  const fetchFn = (async (url: string, init?: RequestInit) => {
    const call: Call = {
      url: String(url),
      method: init?.method ?? "GET",
      body: init?.body ? JSON.parse(String(init.body)) : undefined,
    };
    calls.push(call);
    const { status = 200, json } = handler(call);
    return {
      ok: status >= 200 && status < 300,
      status,
      json: async () => json,
    } as Response;
  }) as unknown as typeof fetch;
  return { fetchFn, calls };
}

const client = (fetchFn: typeof fetch) =>
  new MispPushClient({ baseUrl: "https://misp.test", apiKey: "k", fetchFn: fetchFn as never });

describe("MispPushClient HTTP handling", () => {
  it("treats HTTP 200 with saved:false as a failure, not a success", async () => {
    // The exact shape a live MISP returns for an unknown tag.
    const { fetchFn } = stubFetch(() => ({ status: 200, json: { saved: false, errors: "Invalid Tag." } }));
    await expect(client(fetchFn).addTagToEvent("42", "dfir-companion:case:demo"))
      .rejects.toThrow(/Invalid Tag/);
  });

  it("flattens MISP's per-field error map into the thrown message", async () => {
    const { fetchFn } = stubFetch(() => ({
      status: 200,
      json: { saved: false, errors: { value: ["IP address has an invalid format."] } },
    }));
    await expect(client(fetchFn).addAttribute("42", { type: "ip-dst", value: "10.0.0.1 (DC01)", category: "Network activity", to_ids: false }))
      .rejects.toThrow(/value: IP address has an invalid format/);
  });

  it("creates the tag before attaching it, so an unknown tag name still lands", async () => {
    const { fetchFn, calls } = stubFetch((c) =>
      c.url.endsWith("/tags/add")
        ? { json: { Tag: { id: "1", name: "t" } } }
        : { json: { saved: true, success: "Tag added." } });
    await client(fetchFn).addTagToEvent("42", "dfir-companion:case:demo");
    expect(calls.map((c) => c.url.replace("https://misp.test", ""))).toEqual(["/tags/add", "/events/addTag"]);
    expect(calls[0].body).toEqual({ name: "dfir-companion:case:demo" });
  });

  it("still attaches when the tag already exists (tags/add failure is not fatal)", async () => {
    const { fetchFn, calls } = stubFetch((c) =>
      c.url.endsWith("/tags/add")
        ? { status: 403, json: { errors: "A similar tag already exists." } }
        : { json: { saved: true, success: "Tag added." } });
    await expect(client(fetchFn).addTagToEvent("42", "dupe")).resolves.toBeUndefined();
    expect(calls).toHaveLength(2);   // create attempted, attach still made
  });

  it("finds a prior event via POST /events/restSearch with a tag filter", async () => {
    const { fetchFn, calls } = stubFetch(() => ({ json: { response: [{ Event: { id: "8811" } }] } }));
    const id = await client(fetchFn).findEventByTag("dfir-companion:case:demo");
    expect(id).toBe("8811");
    expect(calls[0].method).toBe("POST");
    expect(calls[0].url).toBe("https://misp.test/events/restSearch");
    // The tag MUST be sent as a filter — /events/index silently ignored it and returned everything.
    expect(calls[0].body).toMatchObject({ tags: ["dfir-companion:case:demo"], limit: 1 });
  });

  it("tolerates a flat restSearch response shape as well as the wrapped one", async () => {
    const { fetchFn } = stubFetch(() => ({ json: { response: [{ id: "9001" }] } }));
    expect(await client(fetchFn).findEventByTag("t")).toBe("9001");
  });

  it("returns null (not a crash) when no prior event carries the tag", async () => {
    const { fetchFn } = stubFetch(() => ({ json: { response: [] } }));
    expect(await client(fetchFn).findEventByTag("t")).toBeNull();
  });

  it("quotes MISP's own reason on a 403 instead of blaming the API key", async () => {
    const { fetchFn } = stubFetch(() => ({
      status: 403,
      json: { saved: false, errors: { value: ["IP address has an invalid format."] } },
    }));
    const err = await client(fetchFn)
      .addAttribute("42", { type: "ip-dst", value: "10.0.0.1 (DC01)", category: "Network activity", to_ids: false })
      .catch((e: Error) => e);
    expect((err as Error).message).toMatch(/IP address has an invalid format/);
    expect((err as Error).message).not.toMatch(/needs write access/);
  });

  it("still gives the API-key hint on a 403 with no usable body", async () => {
    const { fetchFn } = stubFetch(() => ({ status: 403, json: {} }));
    await expect(client(fetchFn).createEvent({ info: "i", threat_level_id: "4", analysis: "0", distribution: "0" }))
      .rejects.toThrow(/needs write access/);
  });
});

// A fetch that fails at the transport layer the way undici really does: the message is ALWAYS
// the useless "fetch failed" and the actionable reason lives on `cause`.
function failingFetch(cause: unknown): typeof fetch {
  return (async () => {
    throw Object.assign(new TypeError("fetch failed"), { cause });
  }) as unknown as typeof fetch;
}

const netError = (code: string, message = code) => Object.assign(new Error(message), { code });

// The ping is the FIRST call a push makes, so a misconfigured DFIR_MISP_URL is the most likely
// error an operator ever meets — and it used to report only "MISP HTTP 400 on /servers/getVersion",
// naming neither the URL nor the setting at fault.
describe("MispPushClient ping diagnostics (issue #179)", () => {
  const PING_URL = "https://misp.test/servers/getVersion";

  it("names the URL and the likely wrong scheme when the ping answers 400", async () => {
    const { fetchFn } = stubFetch(() => ({ status: 400, json: {} }));
    const msg = await client(fetchFn).ping().catch((e: Error) => e.message);
    expect(msg).toContain(PING_URL);
    expect(msg).toMatch(/scheme/i);
    expect(msg).toMatch(/DFIR_MISP_URL/);
  });

  it("treats a 404 on the ping as a wrong base URL as well", async () => {
    const { fetchFn } = stubFetch(() => ({ status: 404, json: {} }));
    const msg = await client(fetchFn).ping().catch((e: Error) => e.message);
    expect(msg).toContain(PING_URL);
    expect(msg).toMatch(/DFIR_MISP_URL/);
  });

  it("does NOT blame the base URL for a 500 — the instance answered, so the URL reached MISP", async () => {
    const { fetchFn } = stubFetch(() => ({ status: 500, json: {} }));
    const msg = await client(fetchFn).ping().catch((e: Error) => e.message);
    expect(msg).toContain(PING_URL);          // still says WHERE it failed
    expect(msg).not.toMatch(/DFIR_MISP_URL/); // but does not send the operator editing the URL
  });

  it("still blames the API key, not the URL, when the ping answers 401", async () => {
    const { fetchFn } = stubFetch(() => ({ status: 401, json: {} }));
    const msg = await client(fetchFn).ping().catch((e: Error) => e.message);
    expect(msg).toMatch(/DFIR_MISP_KEY/);
    expect(msg).not.toMatch(/DFIR_MISP_URL/);
  });

  it("reports a refused connection as host/port, not as an opaque 'fetch failed'", async () => {
    const msg = await client(failingFetch(netError("ECONNREFUSED", "connect ECONNREFUSED 127.0.0.1:4430")))
      .ping().catch((e: Error) => e.message);
    expect(msg).toMatch(/refused/i);
    expect(msg).toContain(PING_URL);
    expect(msg).toMatch(/DFIR_MISP_URL/);
  });

  it("points at DFIR_MISP_CA / DFIR_MISP_INSECURE on a certificate failure", async () => {
    const msg = await client(failingFetch(netError("SELF_SIGNED_CERT_IN_CHAIN")))
      .ping().catch((e: Error) => e.message);
    expect(msg).toMatch(/certificate/i);
    expect(msg).toMatch(/DFIR_MISP_CA/);
    expect(msg).toMatch(/DFIR_MISP_INSECURE/);
  });

  it("calls out the opposite scheme mistake — https:// against a plain-HTTP port", async () => {
    const msg = await client(failingFetch(netError("EPROTO", "wrong version number")))
      .ping().catch((e: Error) => e.message);
    expect(msg).toMatch(/DFIR_MISP_URL/);
    expect(msg).toMatch(/http/i);
  });

  it("reports an unresolvable hostname as DNS, not as a down instance", async () => {
    const msg = await client(failingFetch(netError("ENOTFOUND", "getaddrinfo ENOTFOUND misp.internal")))
      .ping().catch((e: Error) => e.message);
    expect(msg).toMatch(/resolve/i);
    expect(msg).toMatch(/DFIR_MISP_URL/);
  });

  it("digs the reason out of a nested cause chain", async () => {
    const msg = await client(failingFetch({ cause: netError("ECONNREFUSED") }))
      .ping().catch((e: Error) => e.message);
    expect(msg).toMatch(/refused/i);
  });

  it("reports a timeout as a timeout (AbortSignal.timeout rejects with no error code)", async () => {
    // AbortSignal.timeout rejects with a DOMException whose name is TimeoutError and which has
    // NO `code` — so a code-only lookup would fall through to "fetch failed".
    const timeout = Object.assign(new Error("The operation was aborted due to timeout"), { name: "TimeoutError" });
    const fetchFn = (async () => { throw timeout; }) as unknown as typeof fetch;
    const msg = await client(fetchFn).ping().catch((e: Error) => e.message);
    expect(msg).toMatch(/timed out|timeout/i);
    expect(msg).toContain(PING_URL);
  });

  it("leaves non-ping failures alone — a 404 writing an attribute is not a base-URL problem", async () => {
    const { fetchFn } = stubFetch(() => ({ status: 404, json: {} }));
    const msg = await client(fetchFn)
      .addAttribute("42", { type: "ip-dst", value: "1.2.3.4", category: "Network activity", to_ids: false })
      .catch((e: Error) => e.message);
    expect(msg).toMatch(/MISP HTTP 404/);
    expect(msg).not.toMatch(/DFIR_MISP_URL/);
  });

  it("surfaces the underlying cause code on ANY path, so 'fetch failed' is never the whole story", async () => {
    const msg = await client(failingFetch(netError("ECONNRESET")))
      .addAttribute("42", { type: "ip-dst", value: "1.2.3.4", category: "Network activity", to_ids: false })
      .catch((e: Error) => e.message);
    expect(msg).toMatch(/ECONNRESET/);
  });

  it("diagnoses a 200 that isn't MISP JSON — the URL points at some other web app", async () => {
    // A reverse proxy or an unrelated app on that port answers 200 with an HTML page; parsing it
    // used to escape as a raw "Unexpected token '<'" with no hint that the URL was the problem.
    const fetchFn = (async () => ({
      ok: true,
      status: 200,
      json: async () => { throw new SyntaxError(`Unexpected token '<', "<!DOCTYPE "... is not valid JSON`); },
    })) as unknown as typeof fetch;
    const msg = await client(fetchFn).ping().catch((e: Error) => e.message);
    expect(msg).toContain(PING_URL);
    expect(msg).toMatch(/DFIR_MISP_URL/);
  });
});
