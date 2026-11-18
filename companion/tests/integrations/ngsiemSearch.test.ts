import { describe, expect, it } from "vitest";
import {
  NGSIEM_SCOPE_MESSAGE,
  NgsiemError,
  NgsiemSearchClient,
  pollDelayMs,
  queryJobsPath,
  type NgsiemRow,
} from "../../src/integrations/crowdstrike/ngsiemSearch.js";

// #2666: the NG-SIEM search client against a scripted fake Falcon. No test touches the network.

const SECRET = "s3cr3t-client-secret";
const ALLOWED = /^\/humio\/api\/v1\/repositories\/[^/]+\/queryjobs(\/[^/]+)?$/;

interface Status {
  done?: boolean;
  cancelled?: boolean;
  events?: NgsiemRow[];
  aggregate?: boolean;
  hasMore?: boolean;
  pollAfter?: number;
  http?: number;
  hang?: boolean;
}

interface Call {
  method: string;
  path: string;
  body?: Record<string, unknown>;
}

/** A fake Falcon: job N's polls return `jobs[N]` in order (the last one repeats). */
function fakeFalcon(
  jobs: Status[][],
  opts: {
    tokenStatus?: number;
    startStatus?: number;
    startBody?: string;
    first?: Array<{ status: number; headers?: Record<string, string> }>;
  } = {},
) {
  const calls: Call[] = [];
  let jobSeq = 0;
  const polls = new Map<string, number>();
  const first = [...(opts.first ?? [])];
  let tokens = 0;
  const fetchFn = (async (input: string | URL, init?: RequestInit) => {
    const url = new URL(String(input));
    const method = init?.method ?? "GET";
    if (url.pathname === "/oauth2/token") {
      tokens++;
      if (opts.tokenStatus) return new Response("{}", { status: opts.tokenStatus });
      return Response.json({ access_token: `tok${tokens}`, expires_in: 1799 }, { status: 201 });
    }
    const body =
      typeof init?.body === "string" ? (JSON.parse(init.body) as Record<string, unknown>) : undefined;
    calls.push({ method, path: url.pathname, ...(body ? { body } : {}) });
    const scripted = first.shift();
    if (scripted) return new Response("{}", { status: scripted.status, headers: scripted.headers });
    if (method === "POST") {
      if (opts.startStatus) return new Response(opts.startBody ?? "", { status: opts.startStatus });
      return Response.json({ id: `job${jobSeq++}`, hashedQueryOnView: "h" });
    }
    const id = decodeURIComponent(url.pathname.split("/").pop() ?? "");
    if (method === "DELETE") return new Response(null, { status: 204 });
    const n = Number(id.replace("job", ""));
    const script = jobs[n] ?? [{ done: true, events: [] }];
    const i = polls.get(id) ?? 0;
    polls.set(id, i + 1);
    const st = script[Math.min(i, script.length - 1)];
    if (st.hang) {
      return new Promise<Response>((_, reject) =>
        init?.signal?.addEventListener("abort", () => {
          const why: unknown = init.signal?.reason;
          reject(why instanceof Error ? why : new DOMException("aborted", "AbortError"));
        }),
      );
    }
    if (st.http) return new Response("{}", { status: st.http });
    return Response.json({
      done: st.done ?? false,
      cancelled: st.cancelled ?? false,
      events: st.events ?? [],
      metaData: {
        isAggregate: st.aggregate ?? false,
        pollAfter: st.pollAfter,
        extraData: { hasMoreEvents: st.hasMore ? "true" : "false" },
        processedEvents: 999_999,
      },
    });
  }) as typeof fetch;
  return { fetchFn, calls, tokenCount: () => tokens };
}

function client(fetchFn: typeof fetch, extra: { sleeps?: number[] } = {}) {
  let t = 1_000_000;
  const sleeps = extra.sleeps ?? [];
  return {
    c: new NgsiemSearchClient({
      clientId: "id",
      clientSecret: SECRET,
      baseUrl: "https://falcon.test",
      repository: "search-all",
      fetchFn,
      now: () => t,
      sleep: async (ms, signal) => {
        if (signal?.aborted) throw new DOMException("x", "AbortError");
        sleeps.push(ms);
        t += ms;
      },
    }),
    advance: (ms: number) => (t += ms),
    sleeps,
  };
}

const ev = (i: number, ts = 1_700_000_000_000 - i * 1000): NgsiemRow => ({
  "@id": `e${i}`,
  "@timestamp": ts,
  "#event_simpleName": "ProcessRollup2",
  ComputerName: "HOST-A",
});
const range = (n: number, from = 0) => Array.from({ length: n }, (_, i) => ev(from + i));
const run = (c: NgsiemSearchClient, over: Partial<Parameters<NgsiemSearchClient["run"]>[0]> = {}) =>
  c.run({
    query: "#event_simpleName=ProcessRollup2",
    startMs: 1,
    endMs: 2,
    maxRows: 10_000,
    timeoutMs: 300_000,
    ...over,
  });

describe("queryJobsPath / pollDelayMs", () => {
  it("builds only the queryjobs paths, encoding repo and id", () => {
    expect(queryJobsPath("search-all")).toBe("/humio/api/v1/repositories/search-all/queryjobs");
    expect(queryJobsPath("a/b", "x/../y")).toMatch(ALLOWED);
  });

  it("never waits more than 30 s between polls, whatever Falcon hints", () => {
    for (const hint of [undefined, null, "x", -5, 0, 10, 999, 60_000, 1e9]) {
      const d = pollDelayMs(hint);
      expect(d).toBeGreaterThan(0);
      expect(d).toBeLessThanOrEqual(30_000);
    }
  });
});

describe("NgsiemSearchClient.run", () => {
  it("starts, polls until done, reads the rows and cancels the job", async () => {
    const f = fakeFalcon([[{ done: false }, { done: true, events: range(3) }]]);
    const { c, sleeps } = client(f.fetchFn);
    const r = await run(c, { startMs: 111, endMs: 222 });
    expect(r.rows).toHaveLength(3);
    expect(r).toMatchObject({
      truncated: false,
      timedOut: false,
      aggregate: false,
      finished: true,
      pages: 1,
    });
    expect(f.calls.map((x) => x.method)).toEqual(["POST", "GET", "GET", "DELETE"]);
    expect(f.calls[0].body).toEqual({
      queryString: "#event_simpleName=ProcessRollup2",
      start: 111,
      end: 222,
      isLive: false,
    });
    for (const s of sleeps) expect(s).toBeLessThanOrEqual(30_000);
  });

  it("calls only start / poll / cancel queryjobs URLs", async () => {
    const f = fakeFalcon([
      [{ done: true, events: range(200), hasMore: true }],
      [{ done: true, events: range(50, 199) }],
    ]);
    const { c } = client(f.fetchFn);
    await run(c);
    expect(f.calls.length).toBeGreaterThan(3);
    for (const call of f.calls) {
      expect(call.path).toMatch(ALLOWED);
      expect(["POST", "GET", "DELETE"]).toContain(call.method);
    }
  });

  it("pages a filter query around the oldest event and dedupes by @id", async () => {
    const f = fakeFalcon([
      [{ done: true, events: range(200), hasMore: true }],
      [{ done: true, events: range(50, 199) }],
    ]);
    const { c } = client(f.fetchFn);
    const r = await run(c);
    expect(r.rows).toHaveLength(249);
    expect(r.pages).toBe(2);
    const second = f.calls.filter((x) => x.method === "POST")[1];
    expect(second.body?.around).toEqual({
      eventId: "e199",
      timestamp: ev(199)["@timestamp"],
      numberOfEventsBefore: 200,
      numberOfEventsAfter: 0,
    });
    expect(f.calls.filter((x) => x.method === "DELETE")).toHaveLength(2);
  });

  it("reads an aggregate in one job, without paging", async () => {
    const rows = [
      { ComputerName: "A", _count: 3 },
      { ComputerName: "B", _count: 1 },
    ];
    const f = fakeFalcon([[{ done: true, events: rows, aggregate: true, hasMore: false }]]);
    const { c } = client(f.fetchFn);
    const r = await run(c);
    expect(r).toMatchObject({ aggregate: true, finished: true, truncated: false, rows });
    expect(f.calls.filter((x) => x.method === "POST")).toHaveLength(1);
  });

  it("stops at the row cap and marks the result truncated, with no invented total", async () => {
    const f = fakeFalcon([[{ done: true, events: range(200), hasMore: true }]]);
    const { c } = client(f.fetchFn);
    const r = await run(c, { maxRows: 150 });
    expect(r.rows).toHaveLength(150);
    expect(r.truncated).toBe(true);
    expect(r).not.toHaveProperty("total");
  });

  it("marks a buffer it cannot page (no @id anchor) as truncated, not drained", async () => {
    const rows = [{ ComputerName: "A", "@timestamp": 5 }];
    const f = fakeFalcon([[{ done: true, events: rows, hasMore: true }]]);
    const { c } = client(f.fetchFn);
    const r = await run(c);
    expect(r).toMatchObject({ truncated: true, rows });
  });

  it("at the timeout cancels the job and returns the latest snapshot already read", async () => {
    const f = fakeFalcon([[{ done: false, events: range(2), pollAfter: 5000 }]]);
    const { c } = client(f.fetchFn);
    const r = await run(c, { timeoutMs: 12_000 });
    expect(r).toMatchObject({ timedOut: true, truncated: true });
    expect(r.rows).toHaveLength(2); // the snapshot, not 2 rows per poll
    expect(f.calls.at(-1)?.method).toBe("DELETE");
  });

  it("an unfinished aggregate at the timeout is returned as a provisional snapshot", async () => {
    const f = fakeFalcon([[{ done: false, aggregate: true, events: [{ n: 1 }], pollAfter: 5000 }]]);
    const { c } = client(f.fetchFn);
    const r = await run(c, { timeoutMs: 8_000 });
    expect(r).toMatchObject({ aggregate: true, finished: false, timedOut: true, truncated: true });
  });

  it("a hanging response is cut at the deadline and the job is still cancelled", async () => {
    const f = fakeFalcon([[{ hang: true }]]);
    const c = new NgsiemSearchClient({
      clientId: "id",
      clientSecret: SECRET,
      baseUrl: "https://falcon.test",
      repository: "search-all",
      fetchFn: f.fetchFn,
      requestTimeoutMs: 50,
    });
    await expect(run(c, { timeoutMs: 2_000 })).rejects.toThrow(/did not answer in time/);
    expect(f.calls.at(-1)?.method).toBe("DELETE");
  });

  it("an analyst abort cancels the job and throws AbortError", async () => {
    const ctrl = new AbortController();
    const f = fakeFalcon([[{ done: false }]]);
    const { c } = client(f.fetchFn);
    const p = run(c, { signal: ctrl.signal, onProgress: () => ctrl.abort() });
    ctrl.abort();
    await expect(p).rejects.toMatchObject({ name: "AbortError" });
    expect(f.calls.at(-1)?.method).toBe("DELETE");
  });

  it("refreshes the token once on a 401", async () => {
    const f = fakeFalcon([[{ done: true, events: range(1) }]], { first: [{ status: 401 }] });
    const { c } = client(f.fetchFn);
    const r = await run(c);
    expect(r.rows).toHaveLength(1);
    expect(f.tokenCount()).toBe(2);
  });

  it("a 403 says which NG-SIEM scopes are missing, never the secret", async () => {
    const f = fakeFalcon([], { first: [{ status: 403 }] });
    const { c } = client(f.fetchFn);
    const err = await run(c).then(
      () => new Error("expected a rejection"),
      (e: unknown) => e as Error,
    );
    expect(err).toBeInstanceOf(NgsiemError);
    expect(err.message).toBe(NGSIEM_SCOPE_MESSAGE);
    expect(err.message).toContain("NGSIEM: Write");
    expect(err.message).toContain("NGSIEM: Read");
    expect(err.message).not.toContain(SECRET);
  });

  it("a rejected sign-in names the SIEM settings, never the secret", async () => {
    const f = fakeFalcon([], { tokenStatus: 401 });
    const { c } = client(f.fetchFn);
    const err = await run(c).then(
      () => new Error("expected a rejection"),
      (e: unknown) => e as Error,
    );
    expect(err.message).toContain("DFIR_CROWDSTRIKE_SIEM_CLIENT_ID");
    expect(err.message).not.toContain(SECRET);
    expect(f.calls).toHaveLength(0);
  });

  it("waits Retry-After on a 429 and retries", async () => {
    const f = fakeFalcon([[{ done: true, events: range(1) }]], {
      first: [{ status: 429, headers: { "retry-after": "2" } }],
    });
    const { c, sleeps } = client(f.fetchFn);
    const r = await run(c);
    expect(r.rows).toHaveLength(1);
    expect(sleeps).toContain(2000);
  });

  it("a long Retry-After stops with the rate-limit sentence instead of sleeping past the job's life", async () => {
    const f = fakeFalcon([], { first: [{ status: 429, headers: { "retry-after": "120" } }] });
    const { c, sleeps } = client(f.fetchFn);
    await expect(run(c)).rejects.toThrow("CrowdStrike rate-limited the search. Try again in 120 seconds.");
    expect(sleeps.every((s) => s < 120_000)).toBe(true);
  });

  it("quotes Falcon's message when it refuses the query", async () => {
    const f = fakeFalcon([], {
      startStatus: 400,
      startBody: JSON.stringify({ errors: [{ message: "Unknown function: grupBy" }] }),
    });
    const { c } = client(f.fetchFn);
    await expect(run(c)).rejects.toThrow('Falcon refused the query: "Unknown function: grupBy"');
  });

  it("a failure after rows were read keeps them, marked truncated, with the error", async () => {
    const f = fakeFalcon([[{ done: true, events: range(200), hasMore: true }], [{ http: 404 }]]);
    const { c } = client(f.fetchFn);
    const r = await run(c);
    expect(r.rows).toHaveLength(200);
    expect(r).toMatchObject({
      truncated: true,
      error: "The search job expired on Falcon before its results were read.",
    });
  });

  it("records a cancel Falcon did not confirm as a warning", async () => {
    const base = fakeFalcon([[{ done: true, events: range(1) }]]);
    const fetchFn = (async (input: string | URL, init?: RequestInit) =>
      init?.method === "DELETE"
        ? new Response("{}", { status: 500 })
        : base.fetchFn(input, init)) as typeof fetch;
    const { c } = client(fetchFn);
    const r = await run(c);
    expect(r.warnings[0]).toContain("did not confirm the cancel");
  });
});

// #2685: a failure with no HTTP answer names what to check, is logged in full, never carries the secret.
describe("NgsiemSearchClient connection failures (#2685)", () => {
  const failing = (code: string) =>
    (async () => {
      throw new TypeError("fetch failed", {
        cause: Object.assign(new Error(`connect ${code} for ${SECRET}`), { code }),
      });
    }) as unknown as typeof fetch;
  const build = (fetchFn: typeof fetch, extra: Record<string, unknown> = {}) => {
    const logs: string[] = [];
    let t = 1_000_000;
    const c = new NgsiemSearchClient({
      clientId: "id",
      clientSecret: SECRET,
      baseUrl: "https://falcon.test",
      repository: "search-all",
      fetchFn,
      now: () => t,
      sleep: async (ms) => void (t += ms),
      log: (l) => logs.push(l),
      ...extra,
    });
    return { c, logs };
  };
  const reason = (c: NgsiemSearchClient) =>
    run(c).then(
      () => "no rejection",
      (e: unknown) => (e as Error).message,
    );

  it("a DNS failure says so, names the host, and the server log has the code", async () => {
    const { c, logs } = build(failing("ENOTFOUND"));
    const m = await reason(c);
    expect(m).toContain("could not resolve falcon.test");
    expect(m).not.toContain("Could not reach CrowdStrike NG-SIEM.");
    expect(logs.join("\n")).toContain("ENOTFOUND");
    expect(logs.join("\n")).not.toContain(SECRET);
    expect(m).not.toContain(SECRET);
  });

  it("a certificate-trust failure names the issuer a check connection saw and the CA setting", async () => {
    const seen: Array<[string, number]> = [];
    const { c } = build(failing("UNABLE_TO_GET_ISSUER_CERT_LOCALLY"), {
      peerIssuer: async (h: string, p: number) => {
        seen.push([h, p]);
        return "O=CrowdStrike, CN=Falcon ROOT CA Proxy";
      },
    });
    const m = await reason(c);
    expect(m).toContain('issued by "O=CrowdStrike, CN=Falcon ROOT CA Proxy"');
    expect(m).toContain("DFIR_CROWDSTRIKE_SIEM_CA");
    expect(seen).toEqual([["falcon.test", 443]]);
  });

  it("a non-certificate failure never opens the check connection", async () => {
    let asked = false;
    const { c } = build(failing("ECONNREFUSED"), {
      peerIssuer: async () => {
        asked = true;
        return "x";
      },
    });
    expect(await reason(c)).toMatch(/firewall or proxy/);
    expect(asked).toBe(false);
  });

  it("a bad base URL refuses at construction with the Settings sentence", () => {
    expect(
      () =>
        new NgsiemSearchClient({
          clientId: "id",
          clientSecret: SECRET,
          baseUrl: "https://falcon.crowdstrike.com",
          repository: "search-all",
          fetchFn: failing("X"),
        }),
    ).toThrow(/console/);
  });
});
