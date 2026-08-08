import { describe, expect, it } from "vitest";
import { loadDashboardModule } from "../helpers/dashboardModule.js";
import { FEATURES } from "./featureManifest.js";

// EXECUTION COVERAGE FOR THE SWIMLANE (#479).
//
// dashboard-swimlane.js had a FEATURES entry naming initSwimlane as its initializer, and nothing
// ever RAN it. Two mutations passed all 101 feature tests: deleting the guarded initializer call in
// dashboard.html, and deleting the swimlaneZoomIn listener. The first leaves the whole feature
// unwired; the second leaves a dead button. Neither is visible to a manifest check, because a
// manifest records what the code is SUPPOSED to do.
//
// It is the 461-line feature extracted from the inline script in PR #475 — exactly when a wiring
// regression is most likely — and it was the one feature with no execution coverage.
//
// EVERY LISTENER IS NAMED, not counted. Per #475's own lesson: a `length > N` threshold cannot tell
// "all seventeen" from "any five", and it reads a DUPLICATE registration as more evidence of
// success. Naming them catches both directions.
describe("initSwimlane wires every control it owns", () => {
  const feat = FEATURES.find((f) => f.file === "dashboard-swimlane.js")!;

  const WIRED = [
    // The canvas itself — pan, zoom, hover and select.
    "swimlaneCanvas:click",
    "swimlaneCanvas:mousedown",
    "swimlaneCanvas:mouseleave",
    "swimlaneCanvas:wheel",
    // A drag continues and ends OUTSIDE the canvas, so these two are on the window. Losing either
    // strands a drag: the lane keeps following the pointer after the button is released.
    "window:mousemove",
    "window:mouseup",
    // Fullscreen is a document-level concern.
    "document:fullscreenchange",
    "document:keydown",
    // The toolbar.
    "swimlaneFullscreen:click",
    "swimlaneGroupBy:change",
    "swimlanePng:click",
    "swimlaneScopeView:click",
    "swimlaneSelClear:click",
    "swimlaneSelFp:click",
    "swimlaneZoomFit:click",
    "swimlaneZoomIn:click",
    "swimlaneZoomOut:click",
  ];

  /** Enough of a browser for the initializer to wire itself, recording every registration by name. */
  function fixture(opts: { withCanvas?: boolean } = {}) {
    const listeners: string[] = [];
    const observed: string[] = [];
    const els = new Map<string, Record<string, unknown>>();

    const el = (id: string): Record<string, unknown> => {
      if (!els.has(id)) {
        els.set(id, {
          id,
          value: "",
          textContent: "",
          innerHTML: "",
          hidden: false,
          width: 800,
          height: 400,
          style: {},
          dataset: {},
          classList: { add() {}, remove() {}, toggle() {}, contains: () => false },
          addEventListener: (type: string) => listeners.push(`${id}:${type}`),
          getBoundingClientRect: () => ({ left: 0, top: 0, width: 800, height: 400 }),
          // Only swRenderCanvas() reaches for a 2d context, and initSwimlane does not call it — but
          // a stub costs nothing and keeps a future render inside the initializer from turning this
          // suite red for the wrong reason.
          getContext: () => new Proxy({}, { get: () => () => undefined }),
          querySelector: () => null,
          querySelectorAll: () => [],
          appendChild() {},
          requestFullscreen: () => Promise.resolve(),
        });
      }
      return els.get(id) as Record<string, unknown>;
    };

    // initSwimlane returns EARLY when the canvas is absent. That is correct on a page that has not
    // rendered the panel — and it is also how a fixture can certify a feature it never wired, so
    // the absent-canvas case is asserted below rather than assumed.
    const document = {
      getElementById: (id: string) => (id === "swimlaneCanvas" && opts.withCanvas === false ? null : el(id)),
      querySelector: () => null,
      querySelectorAll: () => [],
      createElement: () => el("__created"),
      addEventListener: (type: string) => listeners.push(`document:${type}`),
      body: { classList: { add() {}, remove() {} }, appendChild() {} },
      fullscreenElement: null,
    };

    class ResizeObserver {
      constructor(cb: () => void) {
        void cb;
      }
      observe(target: { id?: string }): void {
        observed.push(String(target?.id));
      }
      disconnect(): void {}
    }

    return {
      listeners,
      observed,
      globals: {
        document,
        ResizeObserver,
        // `sandbox.window = sandbox`, so a window-level listener is a bare global here.
        addEventListener: (type: string) => listeners.push(`window:${type}`),
        requestAnimationFrame: (cb: () => void) => {
          void cb;
          return 0;
        },
        fetch: () => Promise.resolve({ ok: true, json: () => Promise.resolve({}) }),
      },
    };
  }

  const load = (opts: { withCanvas?: boolean } = {}) => {
    const fx = fixture(opts);
    const api = loadDashboardModule<Record<string, unknown>>("dashboard-swimlane.js", [], fx.globals);
    return { api, fx };
  };

  const init = (api: Record<string, unknown>): void => (api[feat.initializer!] as () => void)();

  it("registers nothing before the initializer runs", () => {
    // The load-time half of the contract: this file's top level publishes six names and wires
    // nothing. If wiring leaks back out of initSwimlane into module scope it runs before the markup
    // exists, which is silently no wiring at all.
    const { fx } = load();
    expect(fx.listeners).toEqual([]);
  });

  it("wires every control it owns, named one by one", () => {
    const { api, fx } = load();
    init(api);
    expect(
      [...fx.listeners].sort(),
      "a control this feature owns is unwired, or wired twice — either way the analyst gets a " +
        "button that does nothing or fires twice, with no error anywhere",
    ).toEqual([...WIRED].sort());
  });

  it("observes the wrapper for resize so the canvas redraws", () => {
    // Not a listener, so the named list above cannot cover it — and without it the chart keeps its
    // first size forever, which reads as a rendering bug rather than a missing observer.
    const { api, fx } = load();
    init(api);
    expect(fx.observed).toEqual(["swimlaneWrap"]);
  });

  it("wires nothing at all when the panel is absent", () => {
    // The early return is deliberate. Asserting it keeps the fixture honest: a stub answering
    // truthy for every lookup would make the test above pass on a page that has no swimlane.
    const { api, fx } = load({ withCanvas: false });
    init(api);
    expect(fx.listeners).toEqual([]);
    expect(fx.observed).toEqual([]);
  });

  it("is safe to run twice, as a re-render would", () => {
    // Double-wiring is the failure a `length > N` check reads as success. Each control must appear
    // exactly twice after two inits — never once, which would mean a registration was skipped.
    const { api, fx } = load();
    init(api);
    init(api);
    const counts = new Map<string, number>();
    for (const l of fx.listeners) counts.set(l, (counts.get(l) ?? 0) + 1);
    expect([...counts.keys()].sort()).toEqual([...WIRED].sort());
    expect([...counts.values()].every((c) => c === 2)).toBe(true);
  });
});
