import { describe, it, expect, afterEach } from "vitest";
// The progress module lives outside companion/, next to command-palette.js. It guards its
// window/document access, so importing its pure named exports in node works — same arrangement as
// commandPalette.test.ts.
import {
  LOAD_STAGES,
  createLoadState,
  advanceStage,
  setDownloadBytes,
  setEventCount,
  progressOf,
  createPanelTally,
  settlePanel,
  failPanel,
  panelProgressOf,
  readBodyWithProgress,
  runPanelLoaders,
  afterPaint,
} from "../../../public/js/case-load-progress.js";

const MB = 1024 * 1024;

describe("load stages", () => {
  it("covers only the phases the overlay is actually up for", () => {
    // The lock-status fetch happens in connect(), BEFORE proceedConnect() shows the overlay, so it
    // is deliberately not a stage: a stage that is always already complete when the bar first
    // paints would pad the bar with progress the analyst never waited for.
    expect(LOAD_STAGES).toEqual(["query", "download", "parse", "render", "lifecycle"]);
  });
});

describe("progressOf", () => {
  it("starts at zero, naming the stage rather than inventing a percentage", () => {
    const p = progressOf(createLoadState());
    expect(p.fraction).toBe(0);
    expect(p.percent).toBe(0);
    expect(p.label).toContain("Querying");
    // No signal exists for server think time — say so with a shimmer, never a number.
    expect(p.shimmer).toBe(true);
  });

  it("advances one fifth per completed stage", () => {
    const s = createLoadState();
    advanceStage(s, "query");
    expect(progressOf(s).fraction).toBeCloseTo(0.2, 10);
    advanceStage(s, "download");
    expect(progressOf(s).fraction).toBeCloseTo(0.4, 10);
    advanceStage(s, "parse");
    expect(progressOf(s).fraction).toBeCloseTo(0.6, 10);
    advanceStage(s, "render");
    expect(progressOf(s).fraction).toBeCloseTo(0.8, 10);
    advanceStage(s, "lifecycle");
    expect(progressOf(s).fraction).toBe(1);
  });

  it("names the stage now running, not the one just finished", () => {
    const s = createLoadState();
    advanceStage(s, "query");
    expect(progressOf(s).label).toContain("Downloading");
    advanceStage(s, "download");
    expect(progressOf(s).label).toContain("Parsing");
    advanceStage(s, "parse");
    expect(progressOf(s).label).toContain("Rendering");
  });

  it("only claims a contiguous prefix of stages, so a parallel finish cannot jump the bar", () => {
    const s = createLoadState();
    // The lifecycle fetch (/cases) runs in parallel and routinely lands before render() finishes.
    // Counting it early would claim progress through stages that have not happened.
    advanceStage(s, "lifecycle");
    expect(progressOf(s).fraction).toBe(0);
    advanceStage(s, "query");
    expect(progressOf(s).fraction).toBeCloseTo(0.2, 10);
  });
});

describe("download stage", () => {
  it("reports a real fraction of the bytes actually received", () => {
    const s = createLoadState();
    advanceStage(s, "query");
    setDownloadBytes(s, 2.4 * MB, 4.8 * MB);
    // Half of the download stage's own fifth, on top of the completed query stage.
    expect(progressOf(s).fraction).toBeCloseTo(0.2 + 0.5 * 0.2, 10);
    expect(progressOf(s).shimmer).toBe(false);
  });

  it("puts both the received and total size in the label", () => {
    const s = createLoadState();
    advanceStage(s, "query");
    setDownloadBytes(s, 2.1 * MB, 4.8 * MB);
    expect(progressOf(s).label).toBe("Downloading 2.1 MB of 4.8 MB");
  });

  it("shimmers instead of inventing a denominator when Content-Length is absent", () => {
    // A proxy that chunks the response leaves no total. The bar keeps advancing by stage; it just
    // loses the sub-stage detail rather than making a number up.
    for (const total of [0, -1, Number.NaN, Number.POSITIVE_INFINITY]) {
      const s = createLoadState();
      advanceStage(s, "query");
      setDownloadBytes(s, 1 * MB, total);
      const p = progressOf(s);
      expect(p.shimmer).toBe(true);
      expect(p.fraction).toBeCloseTo(0.2, 10);
      expect(p.label).toBe("Downloading…");
    }
  });

  it("cannot overshoot its own stage when the body is longer than Content-Length claimed", () => {
    const s = createLoadState();
    advanceStage(s, "query");
    setDownloadBytes(s, 9 * MB, 4.8 * MB);
    expect(progressOf(s).fraction).toBeCloseTo(0.4, 10);
  });
});

describe("labels that depend on parsed data", () => {
  it("reports bytes while parsing, because no event count exists yet", () => {
    const s = createLoadState();
    advanceStage(s, "query");
    setDownloadBytes(s, 4.8 * MB, 4.8 * MB);
    advanceStage(s, "download");
    expect(progressOf(s).label).toBe("Parsing 4.8 MB…");
  });

  it("names the true event count once parsing has produced one", () => {
    const s = createLoadState();
    advanceStage(s, "query");
    advanceStage(s, "download");
    setEventCount(s, 9847);
    advanceStage(s, "parse");
    expect(progressOf(s).label).toBe("Rendering 9,847 events…");
  });

  it("stays vague rather than guessing when the count is unavailable", () => {
    const s = createLoadState();
    advanceStage(s, "query");
    advanceStage(s, "download");
    advanceStage(s, "parse");
    expect(progressOf(s).label).toBe("Rendering…");
  });
});

describe("monotonicity", () => {
  it("never moves backwards, whatever order events arrive in", () => {
    const s = createLoadState();
    let high = 0;
    const step = (fn: () => void) => {
      fn();
      const f = progressOf(s).fraction;
      expect(f).toBeGreaterThanOrEqual(high);
      high = f;
    };
    step(() => advanceStage(s, "query"));
    step(() => setDownloadBytes(s, 4 * MB, 5 * MB));
    // A retried/duplicated progress event reporting fewer bytes must not rewind the bar.
    step(() => setDownloadBytes(s, 1 * MB, 5 * MB));
    step(() => advanceStage(s, "download"));
    // A stage arriving twice, and one arriving out of order, are both no-ops.
    step(() => advanceStage(s, "download"));
    step(() => advanceStage(s, "query"));
    step(() => advanceStage(s, "parse"));
    step(() => advanceStage(s, "render"));
    step(() => advanceStage(s, "lifecycle"));
    expect(high).toBe(1);
  });

  it("shrugs off stage ids it does not recognise", () => {
    const s = createLoadState();
    advanceStage(s, "query");
    // A progress bar must never be able to break a case load.
    expect(() => advanceStage(s, "not-a-stage")).not.toThrow();
    expect(progressOf(s).fraction).toBeCloseTo(0.2, 10);
  });
});

describe("panel tally", () => {
  it("counts a panel once however many times it settles", () => {
    const t = createPanelTally(60);
    settlePanel(t, "geoMap");
    settlePanel(t, "geoMap");
    settlePanel(t, "hostRanking");
    expect(panelProgressOf(t).settled).toBe(2);
  });

  it("counts a failed panel as settled, so a 501-by-design route cannot stall the bar", () => {
    // Several routes 501 when their store is not configured. A fulfilled-only tally would sit
    // short of the total forever.
    const t = createPanelTally(3);
    settlePanel(t, "tags");
    failPanel(t, "mcpRun");
    const p = panelProgressOf(t);
    expect(p.settled).toBe(2);
    expect(p.failed).toBe(1);
  });

  it("reaches 1.0 when every panel fails", () => {
    const t = createPanelTally(2);
    failPanel(t, "a");
    failPanel(t, "b");
    const p = panelProgressOf(t);
    expect(p.fraction).toBe(1);
    expect(p.failed).toBe(2);
  });

  it("does not double-count a panel that fails and then settles", () => {
    const t = createPanelTally(2);
    failPanel(t, "a");
    settlePanel(t, "a");
    const p = panelProgressOf(t);
    expect(p.settled).toBe(1);
    expect(p.failed).toBe(1);
  });

  it("keeps the denominator fixed so the bar cannot run backwards", () => {
    const t = createPanelTally(60);
    settlePanel(t, "a");
    expect(panelProgressOf(t).total).toBe(60);
    expect(panelProgressOf(t).fraction).toBeCloseTo(1 / 60, 10);
  });

  it("is complete, not divided by zero, when there is nothing to load", () => {
    expect(panelProgressOf(createPanelTally(0)).fraction).toBe(1);
  });
});

describe("readBodyWithProgress", () => {
  function streamed(text: string, contentLength?: string) {
    const bytes = new TextEncoder().encode(text);
    const stream = new ReadableStream({
      start(controller) {
        // Two chunks, so the test observes progress mid-flight rather than only at the end.
        const half = Math.ceil(bytes.length / 2);
        controller.enqueue(bytes.slice(0, half));
        controller.enqueue(bytes.slice(half));
        controller.close();
      },
    });
    const headers: Record<string, string> = {};
    if (contentLength !== undefined) headers["Content-Length"] = contentLength;
    return new Response(stream, { headers });
  }

  it("returns the body exactly", async () => {
    const s = createLoadState();
    const body = JSON.stringify({ caseId: "INC-1", forensicTimelineTotal: 3 });
    await expect(readBodyWithProgress(s, streamed(body, String(body.length)))).resolves.toBe(body);
  });

  it("drives real byte progress while the body streams in", async () => {
    const s = createLoadState();
    advanceStage(s, "query");
    const seen: number[] = [];
    const body = "x".repeat(4096);
    await readBodyWithProgress(s, streamed(body, String(body.length)), () =>
      seen.push(progressOf(s).fraction),
    );
    // Progress was reported per chunk, and it climbed.
    expect(seen.length).toBeGreaterThanOrEqual(2);
    expect(seen[seen.length - 1]).toBeGreaterThan(seen[0]);
    // The download stage is complete: its whole fifth is claimed, and nothing beyond it.
    expect(progressOf(s).fraction).toBeCloseTo(0.4, 10);
  });

  it("shimmers rather than guessing when the response carries no Content-Length", async () => {
    const s = createLoadState();
    advanceStage(s, "query");
    const body = "y".repeat(1024);
    await expect(readBodyWithProgress(s, streamed(body))).resolves.toBe(body);
    expect(progressOf(s).shimmer).toBe(true);
  });

  it("falls back to text() when the body cannot be streamed", async () => {
    const s = createLoadState();
    // Some environments (and any polyfilled Response) expose no getReader.
    const fake = { headers: new Headers(), body: null, text: async () => "fallback" };
    await expect(readBodyWithProgress(s, fake as unknown as Response)).resolves.toBe("fallback");
  });
});

describe("runPanelLoaders", () => {
  const realFetch = globalThis.fetch;
  afterEach(() => {
    globalThis.fetch = realFetch;
  });

  /** A fetch stub whose promises the test resolves by hand. */
  function controllable() {
    const gates: { resolve: () => void; reject: () => void }[] = [];
    globalThis.fetch = () =>
      new Promise<Response>((res, rej) => {
        gates.push({ resolve: () => res(new Response("{}")), reject: () => rej(new Error("boom")) });
      });
    return gates;
  }

  it("settles a panel only once the fetch it started has resolved", async () => {
    const gates = controllable();
    const tally = runPanelLoaders([["geoMap", () => void fetch("/cases/x/geo-map")]]);
    expect(panelProgressOf(tally).settled).toBe(0);
    gates[0].resolve();
    await new Promise((r) => setTimeout(r, 0));
    expect(panelProgressOf(tally).settled).toBe(1);
  });

  it("counts a panel whose fetch rejects as settled and failed", async () => {
    const gates = controllable();
    const tally = runPanelLoaders([["mcpRun", () => void fetch("/mcp").catch(() => {})]]);
    gates[0].reject();
    await new Promise((r) => setTimeout(r, 0));
    const p = panelProgressOf(tally);
    expect(p.settled).toBe(1);
    expect(p.failed).toBe(1);
  });

  it("settles a loader that starts no fetch immediately", () => {
    controllable();
    const tally = runPanelLoaders([["noop", () => {}]]);
    expect(panelProgressOf(tally).fraction).toBe(1);
  });

  it("records a loader that throws as failed without stopping the ones after it", () => {
    controllable();
    const ran: string[] = [];
    const tally = runPanelLoaders([
      [
        "explodes",
        () => {
          throw new Error("bad loader");
        },
      ],
      ["after", () => void ran.push("after")],
    ]);
    expect(ran).toEqual(["after"]);
    expect(panelProgressOf(tally).failed).toBe(1);
  });

  it("restores the original fetch even when a loader throws", () => {
    const before = globalThis.fetch;
    runPanelLoaders([
      [
        "explodes",
        () => {
          throw new Error("bad loader");
        },
      ],
    ]);
    expect(globalThis.fetch).toBe(before);
  });

  it("attributes each fetch to the loader that started it", async () => {
    const gates = controllable();
    const tally = runPanelLoaders([
      ["a", () => void fetch("/a")],
      ["b", () => void fetch("/b")],
    ]);
    gates[1].resolve();
    await new Promise((r) => setTimeout(r, 0));
    // Only b's request has come back; a is still outstanding.
    expect(panelProgressOf(tally).settled).toBe(1);
    gates[0].resolve();
    await new Promise((r) => setTimeout(r, 0));
    expect(panelProgressOf(tally).fraction).toBe(1);
  });

  it("waits for every fetch a single loader started", async () => {
    const gates = controllable();
    const tally = runPanelLoaders([
      [
        "twoCalls",
        () => {
          void fetch("/one");
          void fetch("/two");
        },
      ],
    ]);
    gates[0].resolve();
    await new Promise((r) => setTimeout(r, 0));
    expect(panelProgressOf(tally).settled).toBe(0);
    gates[1].resolve();
    await new Promise((r) => setTimeout(r, 0));
    expect(panelProgressOf(tally).settled).toBe(1);
  });

  it("reports progress to its callback as panels come in", async () => {
    const gates = controllable();
    const seen: number[] = [];
    runPanelLoaders(
      [
        ["a", () => void fetch("/a")],
        ["b", () => void fetch("/b")],
      ],
      (t) => seen.push(panelProgressOf(t).settled),
    );
    gates[0].resolve();
    gates[1].resolve();
    await new Promise((r) => setTimeout(r, 0));
    expect(seen).toEqual([1, 2]);
  });

  // ── Abandonment ──────────────────────────────────────────────────────────────────────────────
  // The fan-out outliving its case is what made a big case's load unsurvivable: dismissing the
  // overlay aborted state and lifecycle only, and ~60 panel requests went on holding the browser's
  // six HTTP/1.1 connections on behalf of a case nobody was looking at any more.

  /** A fetch stub that records the init it was handed, so signal injection is observable. */
  function recording() {
    const calls: RequestInit[] = [];
    globalThis.fetch = ((_url: string, init?: RequestInit) => {
      calls.push(init ?? {});
      return new Promise<Response>(() => {}); // never settles; the signal is the only way out
    }) as typeof fetch;
    return calls;
  }

  it("passes the caller's abort signal to every panel request", () => {
    const calls = recording();
    const ac = new AbortController();
    runPanelLoaders([["geoMap", () => void fetch("/cases/x/geo-map")]], undefined, {
      signal: ac.signal,
    });
    expect(calls[0].signal).toBe(ac.signal);
  });

  it("hides an abort from the loader, so cancelling raises no false alarms", async () => {
    // These loaders almost all end in `.catch(() => somethingUnavailable())`, and ~73 of those
    // report a missing endpoint on the shared status line — several telling the analyst to restart
    // the companion server. An abort must not reach them: cancelling a case load would otherwise
    // accuse a perfectly healthy server and hand out actively wrong advice.
    const ac = new AbortController();
    globalThis.fetch = ((_url: string, init?: RequestInit) =>
      new Promise<Response>((_res, rej) => {
        init?.signal?.addEventListener("abort", () => rej(new Error("aborted")), { once: true });
      })) as typeof fetch;
    let caughtByLoader = false;
    const tally = runPanelLoaders(
      [["anonToggle", () => void fetch("/x").catch(() => (caughtByLoader = true))]],
      undefined,
      { signal: ac.signal },
    );
    ac.abort();
    await new Promise((r) => setTimeout(r, 0));
    expect(caughtByLoader).toBe(false);
    // The strip is not fooled by the silence — it still counts the panel as settled.
    expect(panelProgressOf(tally).fraction).toBe(1);
  });

  it("still delivers a genuine failure to the loader", async () => {
    // The flip side: suppressing aborts must not suppress real unavailability, or a 501-by-design
    // route would stop reporting itself.
    const ac = new AbortController();
    globalThis.fetch = () => Promise.reject(new Error("network down"));
    let caughtByLoader = false;
    runPanelLoaders([["geoMap", () => void fetch("/x").catch(() => (caughtByLoader = true))]], undefined, {
      signal: ac.signal,
    });
    await new Promise((r) => setTimeout(r, 0));
    expect(caughtByLoader).toBe(true);
  });

  it("leaves a loader's own signal alone", () => {
    const calls = recording();
    const ac = new AbortController();
    const own = new AbortController();
    runPanelLoaders([["custom", () => void fetch("/x", { signal: own.signal })]], undefined, {
      signal: ac.signal,
    });
    expect(calls[0].signal).toBe(own.signal);
  });

  it("puts no further requests on the wire once the generation is aborted", async () => {
    const onWire: string[] = [];
    // Honours the signal the way a real fetch does — rejecting on abort. A stub that ignored it
    // would leave the in-flight request pending forever and misreport the tally as stuck.
    globalThis.fetch = ((url: string, init?: RequestInit) => {
      onWire.push(String(url));
      return new Promise<Response>((_res, rej) => {
        init?.signal?.addEventListener("abort", () => rej(new Error("aborted")), { once: true });
      });
    }) as typeof fetch;
    const ac = new AbortController();
    const entries: [string, () => void][] = ["a", "b", "c", "d"].map((n) => [n, () => void fetch("/" + n)]);
    // Cap of 1, so one request is on the wire and three are queued behind a lane when abort lands.
    const tally = runPanelLoaders(entries, undefined, { signal: ac.signal, concurrency: 1 });
    expect(onWire).toEqual(["/a"]);
    ac.abort();
    await new Promise((r) => setTimeout(r, 0));
    // The queued three are released to observe the abort, and each rejects WITHOUT being issued —
    // that is the point; the pool is freed rather than refilled.
    expect(onWire).toEqual(["/a"]);
    // And the strip still reaches its total instead of sitting short forever on panels that are
    // never coming.
    expect(panelProgressOf(tally).fraction).toBe(1);
  });

  it("starts nothing at all when the signal is already aborted", () => {
    const onWire: string[] = [];
    globalThis.fetch = ((url: string) => {
      onWire.push(String(url));
      return new Promise<Response>(() => {});
    }) as typeof fetch;
    const ac = new AbortController();
    ac.abort();
    const tally = runPanelLoaders([["a", () => void fetch("/a")]], undefined, {
      signal: ac.signal,
    });
    expect(onWire).toEqual([]);
    expect(panelProgressOf(tally).fraction).toBe(1);
  });

  // ── Concurrency cap ──────────────────────────────────────────────────────────────────────────

  /**
   * Drain microtasks AND a couple of macrotask ticks.
   *
   * One `setTimeout(0)` is not enough here. The lane's no-body-read backstop is itself a
   * `setTimeout(0)`, and it is armed from a microtask that runs AFTER the test has already
   * scheduled its own timer — so a single tick fires before the backstop, not after it. The
   * backstop has to be a macrotask (a microtask would beat the loader's own `r.json()` to the
   * release), so the test waits rather than the code hurrying.
   */
  // Deliberately NOT pollFor: these tests assert what has and has NOT reached the wire at a given
  // moment, and absence is not a condition you can poll for. A fixed drain, written out rather
  // than looped so it cannot be read as a hand-rolled poll.
  const tick = () => new Promise((r) => setTimeout(r, 0));
  const flush = async () => {
    await tick();
    await tick();
    await tick();
  };

  /** A fetch stub recording the URLs that actually reached the wire, gated by hand. */
  function wireLog() {
    const urls: string[] = [];
    const gates: { ok: (body?: string) => void; fail: () => void }[] = [];
    globalThis.fetch = ((url: string) => {
      urls.push(String(url));
      return new Promise<Response>((res, rej) => {
        gates.push({ ok: (body = "{}") => res(new Response(body)), fail: () => rej(new Error("x")) });
      });
    }) as typeof fetch;
    return { urls, gates };
  }

  it("caps REQUESTS on the wire, not loaders — a fan-out loader cannot exceed the cap", async () => {
    // loadVeloTriage issues four requests and loadMcpRun three, all from one synchronous body.
    // Counting loaders let a single one of those put its whole fan-out on a six-connection pool,
    // which is the saturation the cap exists to prevent.
    const { urls, gates } = wireLog();
    runPanelLoaders(
      [
        [
          "veloTriage",
          () => {
            void fetch("/a");
            void fetch("/b");
            void fetch("/c");
            void fetch("/d");
          },
        ],
      ],
      undefined,
      { concurrency: 2 },
    );
    expect(urls).toEqual(["/a", "/b"]); // /c and /d are held back, inside one loader
    gates[0].ok();
    await flush();
    expect(urls).toEqual(["/a", "/b", "/c"]);
  });

  /**
   * A fetch stub that separates the two moments a real response has: headers, then body.
   *
   * wireLog() cannot tell the two apart — its `new Response("{}")` has a body that resolves on its
   * own — so a test built on it passes whether the lane is released at the headers or at the body.
   * Confirmed by mutation: reverting to a header-release left all of these green.
   */
  function bodyGated() {
    const urls: string[] = [];
    const headers: (() => void)[] = [];
    const bodies: (() => void)[] = [];
    globalThis.fetch = ((url: string) => {
      urls.push(String(url));
      return new Promise<Response>((resolve) => {
        headers.push(() =>
          resolve({
            ok: true,
            status: 200,
            json: () => new Promise((r) => bodies.push(() => r({}))),
          } as unknown as Response),
        );
      });
    }) as typeof fetch;
    return { urls, headers, bodies };
  }

  it("holds a lane until the body is read, not just until the headers land", async () => {
    // fetch fulfils on HEADERS while the body is still coming down the connection. Releasing there
    // admits the next request against a lane that is not actually free.
    const { urls, headers, bodies } = bodyGated();
    runPanelLoaders(
      [
        ["a", () => void fetch("/a").then((r) => r.json())],
        ["b", () => void fetch("/b")],
      ],
      undefined,
      { concurrency: 1 },
    );
    expect(urls).toEqual(["/a"]);
    headers[0](); // headers land; the body is still streaming
    await flush();
    // THE ASSERTION THAT MATTERS: /b must still be held back. A header-release fails right here.
    expect(urls).toEqual(["/a"]);
    bodies[0](); // body finishes — only now is the connection genuinely free
    await flush();
    expect(urls).toEqual(["/a", "/b"]);
  });

  it("frees the lane for a loader that never reads the body at all", async () => {
    // Plenty of loaders only check r.ok. Without a backstop their lane would never come back.
    const { urls, gates } = wireLog();
    runPanelLoaders(
      [
        ["a", () => void fetch("/a").then((r) => r.ok)],
        ["b", () => void fetch("/b")],
      ],
      undefined,
      { concurrency: 1 },
    );
    gates[0].ok();
    await flush();
    expect(urls).toEqual(["/a", "/b"]);
  });

  it("frees the lane when a request fails outright", async () => {
    const { urls, gates } = wireLog();
    runPanelLoaders(
      [
        ["a", () => void fetch("/a").catch(() => {})],
        ["b", () => void fetch("/b")],
      ],
      undefined,
      { concurrency: 1 },
    );
    gates[0].fail();
    await flush();
    expect(urls).toEqual(["/a", "/b"]);
  });

  it("does not stall when a capped loader issues no request at all", () => {
    controllable();
    const started: string[] = [];
    const entries: [string, () => void][] = ["a", "b", "c"].map((n) => [n, () => void started.push(n)]);
    // A loader that asks for no connection takes no lane, so a cap of 1 must not serialize these
    // across event-loop turns.
    const tally = runPanelLoaders(entries, undefined, { concurrency: 1 });
    expect(started).toEqual(["a", "b", "c"]);
    expect(panelProgressOf(tally).fraction).toBe(1);
  });

  it("is unbounded when no concurrency is given", () => {
    controllable();
    const started: string[] = [];
    const entries: [string, () => void][] = ["a", "b", "c"].map((n) => [
      n,
      () => {
        started.push(n);
        void fetch("/" + n);
      },
    ]);
    runPanelLoaders(entries);
    expect(started).toEqual(["a", "b", "c"]);
  });
});

describe("afterPaint", () => {
  const realRaf = globalThis.requestAnimationFrame;
  afterEach(() => {
    globalThis.requestAnimationFrame = realRaf;
  });

  it("resolves even when requestAnimationFrame never fires", async () => {
    // A backgrounded or throttled tab does not run rAF callbacks AT ALL. This await sits in the
    // middle of the case load, between the download and JSON.parse — if it can hang, the case
    // never renders and the overlay never hides. Found live: opening a case and switching tabs
    // left the dashboard permanently stuck at "Parsing …" with an empty timeline.
    globalThis.requestAnimationFrame = () => 0;
    const raced = await Promise.race([
      afterPaint(10).then(() => "resolved"),
      new Promise((r) => setTimeout(() => r("hung"), 500)),
    ]);
    expect(raced).toBe("resolved");
  });

  it("resolves when there is no requestAnimationFrame at all", async () => {
    globalThis.requestAnimationFrame = undefined as unknown as typeof requestAnimationFrame;
    await expect(afterPaint(10)).resolves.toBeUndefined();
  });

  it("still waits for the paint when frames are actually being delivered", async () => {
    let frames = 0;
    globalThis.requestAnimationFrame = (cb: FrameRequestCallback) => {
      frames++;
      setTimeout(() => cb(0), 0);
      return frames;
    };
    await afterPaint(500);
    // Two frames: the first schedules the style change, the second guarantees it was painted.
    expect(frames).toBe(2);
  });
});
