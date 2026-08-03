import { readFile } from "node:fs/promises";
import { describe, expect, it, vi } from "vitest";
import { STATIC_ASSETS } from "../../src/http/staticAssets.js";
import { dashboardClientSource, loadDashboardModule } from "../helpers/dashboardModule.js";

// public/js/dashboard-state.js — the store the rest of dashboard.html's 422 top-level bindings are
// meant to migrate onto, and the answer to #415's actual question: who owns `lastState`.
//
// Two kinds of test here, and the second kind is the important one. The first exercises the cell
// mechanism. The second enforces the rule the mechanism exists to express — that these cells have
// ONE writer — as a gate on the source rather than as a runtime check, because a runtime check can
// only fire in a browser after the second writer has already shipped.

const MODULE = new URL("../../../public/js/dashboard-state.js", import.meta.url);
const DASHBOARD = new URL("../../../public/dashboard.html", import.meta.url);

describe("dfirCell", () => {
  const cellOf = (initial?: unknown) => loadDashboardModule("dashboard-state.js").DfirState.cell(initial);

  it("holds a value and hands it back", () => {
    const c = cellOf(1);
    expect(c.get()).toBe(1);
    c.set(2);
    expect(c.get()).toBe(2);
  });

  it("returns the value it was given, so a write can be used as an expression", () => {
    expect(cellOf().set("x")).toBe("x");
  });

  // Subscribers exist to re-render FROM the cell, so a subscriber that reads it during
  // notification must see the value that caused the notification, not the one it replaced.
  it("commits before notifying", () => {
    const c = cellOf("before");
    let seen: unknown;
    c.subscribe(() => {
      seen = c.get();
    });
    c.set("after");
    expect(seen).toBe("after");
  });

  it("passes the new value to every subscriber, in subscription order", () => {
    const c = cellOf();
    const calls: string[] = [];
    c.subscribe((v: string) => calls.push(`a:${v}`));
    c.subscribe((v: string) => calls.push(`b:${v}`));
    c.set("x");
    expect(calls).toEqual(["a:x", "b:x"]);
  });

  it("stops calling a subscriber that unsubscribes", () => {
    const c = cellOf();
    const fn = vi.fn();
    const off = c.subscribe(fn);
    c.set(1);
    off();
    c.set(2);
    expect(fn).toHaveBeenCalledTimes(1);
  });

  // The array is copied before iterating. Without that, a subscriber unsubscribing itself mid-
  // notification shifts the array under the loop and the NEXT subscriber is silently skipped —
  // a bug that only shows up when two panels are listening and one of them tears down.
  it("still notifies later subscribers when an earlier one unsubscribes itself", () => {
    const c = cellOf();
    const second = vi.fn();
    const off: Array<() => void> = [];
    off.push(c.subscribe(() => off[0]()));
    c.subscribe(second);
    c.set(1);
    expect(second).toHaveBeenCalledTimes(1);
  });
});

describe("activeView", () => {
  const load = () => loadDashboardModule("dashboard-state.js").DfirState;

  it("starts as null, meaning the Custom layout", () => {
    expect(load().activeView()).toBeNull();
  });

  it("round-trips a view and normalises every falsy input to null", () => {
    const s = load();
    const view = { id: "now", name: "Now" };
    expect(s.setActiveView(view)).toBe(view);
    expect(s.activeView()).toBe(view);
    // applyDashboardView(undefined) means "go back to Custom", and so does
    // applyDashboardView(null) — the store answers null to both rather than leaking undefined
    // into the fourteen `!activeView()` checks.
    for (const falsy of [null, undefined, false, 0, ""]) {
      s.setActiveView(falsy);
      expect(s.activeView()).toBeNull();
    }
  });

  it("notifies subscribers of the change", () => {
    const s = load();
    const seen: unknown[] = [];
    s.onActiveViewChange((v: unknown) => seen.push(v));
    s.setActiveView({ id: "now" });
    s.setActiveView(null);
    expect(seen).toEqual([{ id: "now" }, null]);
  });
});

// THE ACTUAL INVARIANT. Tier 1 and tier 2 in the module's header are defined by having very few
// writers — `lastState` has exactly one across 43 readers — and the whole decision rests on that
// staying true. A second writer appearing is the failure this design has to prevent, and the
// cheapest place to prevent it is here, in the PR that would add it.
describe("the single-writer rule", () => {
  it("has exactly one call site that writes activeView", async () => {
    const source = dashboardClientSource();
    const writes = [...source.matchAll(/DfirState\.setActiveView\(/g)];
    expect(
      writes,
      "activeView is owned by applyDashboardView(). A second writer means the cell is shared " +
        "mutable state again, which is the thing js/dashboard-state.js exists to stop.",
    ).toHaveLength(1);
  });

  it("puts that call site inside applyDashboardView", async () => {
    const html = await readFile(DASHBOARD, "utf8");
    const at = html.indexOf("DfirState.setActiveView(");
    const owner = html.lastIndexOf("function applyDashboardView(", at);
    const nextFn = html.indexOf("\n    function ", owner + 1);
    expect(owner, "no applyDashboardView() before the write").toBeGreaterThan(-1);
    expect(at, "the write escaped applyDashboardView()").toBeLessThan(nextFn);
  });

  // The bare identifier is gone from the page: `let activeView` no longer exists, so a stray
  // `activeView = x` would be a ReferenceError rather than a silent second source of truth.
  it("leaves no top-level activeView binding behind in the inline script", async () => {
    const html = await readFile(DASHBOARD, "utf8");
    expect(html).not.toMatch(/^\s*(let|var|const)\s+activeView\b/m);
  });
});

describe("wiring", () => {
  it("is loaded by dashboard.html, ahead of the inline script, and served by the whitelist", async () => {
    const html = await readFile(DASHBOARD, "utf8");
    expect(html).toContain('<script src="/js/dashboard-state.js"></script>');
    expect(html.indexOf('src="/js/dashboard-state.js"')).toBeLessThan(html.lastIndexOf("<script nonce="));
    expect(STATIC_ASSETS["/js/dashboard-state.js"]).toBe("application/javascript; charset=utf-8");
  });

  it("stays a classic script, like the helpers the inline script calls by name", async () => {
    expect(await readFile(MODULE, "utf8")).not.toMatch(/^\s*(export|import)\s/m);
  });
});
