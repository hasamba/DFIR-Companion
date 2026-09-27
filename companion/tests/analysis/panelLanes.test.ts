// #1713: one request cap for the whole page.
//
// A live `state` push armed ~21 debounced panel reloads that all fired together ~800 ms later,
// outside the four-lane cap the case load and the #1709 catch-up run under. The fix gives the page
// ONE lane pool that every panel request path shares, and cancels a queued request on its own
// run's abort — a shared queue holds other runs' waiters, so a run-wide drain is no longer right.
import { describe, it, expect, afterEach } from "vitest";
import {
  createLanePool,
  createPanelReloader,
  runPanelLoaders,
  panelProgressOf,
} from "../../../public/js/case-load-progress.js";

const tick = () => new Promise((r) => setTimeout(r, 0));
const flush = async () => {
  await tick();
  await tick();
  await tick();
};

describe("a lane pool shared by several panel runs (#1713)", () => {
  const realFetch = globalThis.fetch;
  afterEach(() => {
    globalThis.fetch = realFetch;
  });

  /** A fetch stub recording the URLs that reached the wire, each answered by hand. */
  function wireLog() {
    const urls: string[] = [];
    const gates: (() => void)[] = [];
    globalThis.fetch = ((url: string) => {
      urls.push(String(url));
      return new Promise<Response>((res) => gates.push(() => res(new Response("{}"))));
    }) as typeof fetch;
    return { urls, gates };
  }
  const loader = (url: string) => () => void fetch(url).then((r) => r.json());

  it("caps two runs jointly, not each on its own", async () => {
    const { urls, gates } = wireLog();
    const lanes = createLanePool(2);
    runPanelLoaders(
      [
        ["a", loader("/a")],
        ["b", loader("/b")],
      ],
      undefined,
      { lanes },
    );
    runPanelLoaders(
      [
        ["c", loader("/c")],
        ["d", loader("/d")],
      ],
      undefined,
      { lanes },
    );
    expect(urls).toEqual(["/a", "/b"]);
    gates[0]();
    await flush();
    expect(urls).toEqual(["/a", "/b", "/c"]);
  });

  it("an abort releases only the aborted run's queued requests, and the other run keeps its place", async () => {
    const { urls, gates } = wireLog();
    const lanes = createLanePool(1);
    const keep = new AbortController();
    const drop = new AbortController();
    runPanelLoaders([["busy", loader("/busy")]], undefined, { lanes, signal: keep.signal });
    const dropped = runPanelLoaders([["x", loader("/x")]], undefined, { lanes, signal: drop.signal });
    runPanelLoaders([["y", loader("/y")]], undefined, { lanes, signal: keep.signal });
    drop.abort();
    await flush();
    // The dropped run settles without a request; the kept run is still queued behind /busy.
    expect(panelProgressOf(dropped).fraction).toBe(1);
    expect(urls).toEqual(["/busy"]);
    gates[0]();
    await flush();
    expect(urls).toEqual(["/busy", "/y"]);
  });

  it("an aborted waiter does not leak a lane", async () => {
    const { urls, gates } = wireLog();
    const lanes = createLanePool(1);
    const drop = new AbortController();
    runPanelLoaders([["busy", loader("/busy")]], undefined, { lanes });
    runPanelLoaders([["x", loader("/x")]], undefined, { lanes, signal: drop.signal });
    drop.abort();
    await flush();
    gates[0]();
    await flush();
    runPanelLoaders([["z", loader("/z")]], undefined, { lanes });
    expect(urls).toEqual(["/busy", "/z"]);
  });

  it("a pool with no positive limit is unbounded", () => {
    const { urls } = wireLog();
    const lanes = createLanePool(0);
    runPanelLoaders(
      ["a", "b", "c", "d", "e", "f", "g"].map((n) => [n, loader(`/${n}`)] as const),
      undefined,
      { lanes },
    );
    expect(urls).toHaveLength(7);
  });
});

describe("the debounced panel reloader (#1713)", () => {
  const realFetch = globalThis.fetch;
  afterEach(() => {
    globalThis.fetch = realFetch;
  });

  function wire() {
    const urls: string[] = [];
    const gates: (() => void)[] = [];
    const seen: (AbortSignal | undefined)[] = [];
    globalThis.fetch = ((url: string, init?: RequestInit) => {
      urls.push(String(url));
      seen.push(init?.signal ?? undefined);
      return new Promise<Response>((res, rej) => {
        gates.push(() => res(new Response("{}")));
        init?.signal?.addEventListener("abort", () => rej(new DOMException("aborted", "AbortError")));
      });
    }) as typeof fetch;
    return { urls, gates, seen };
  }

  it("a burst of reloads goes out at most `limit` at a time, the rest as lanes free", async () => {
    const { urls, gates } = wire();
    const reloader = createPanelReloader(createLanePool(4));
    const loaded: string[] = [];
    for (let i = 0; i < 21; i++)
      reloader.run(`p${i}`, () => void fetch(`/p${i}`).then(() => loaded.push(`p${i}`)));
    expect(urls).toHaveLength(4);
    gates[0]();
    gates[1]();
    await flush();
    expect(urls).toHaveLength(6);
    expect(loaded).toEqual(["p0", "p1"]);
  });

  it("retire() abandons queued and in-flight reloads and the next reload still runs", async () => {
    const { urls, gates, seen } = wire();
    const reloader = createPanelReloader(createLanePool(1));
    const painted: string[] = [];
    reloader.run("old1", () => void fetch("/old1").then(() => painted.push("old1")));
    reloader.run("old2", () => void fetch("/old2").then(() => painted.push("old2")));
    reloader.retire();
    await flush();
    expect(seen[0]?.aborted).toBe(true);
    reloader.run("new", () => void fetch("/new").then(() => painted.push("new")));
    await flush();
    // /old2 never reached the wire, and the aborted /old1 drew nothing.
    expect(urls).toEqual(["/old1", "/new"]);
    gates[1]();
    await flush();
    expect(painted).toEqual(["new"]);
  });

  it("a loader that throws does not break the reloader", () => {
    wire();
    const reloader = createPanelReloader(createLanePool(4));
    expect(() =>
      reloader.run("bad", () => {
        throw new Error("boom");
      }),
    ).not.toThrow();
  });
});
