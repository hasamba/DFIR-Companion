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
