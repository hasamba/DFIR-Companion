import { describe, expect, it } from "vitest";
import { loadDashboardModule } from "../helpers/dashboardModule.js";

// #2985: the pending list keeps at most 500 values. A hold with more used to look complete; the
// panel now says how many more the stop found than the list can hold, and to re-run for the rest.

interface Api {
  loadPresidioPending(caseId: string): void;
  setPresidioPending(findings: unknown[], caseId?: string, gen?: number): void;
}

const people = (n: number) =>
  Array.from({ length: n }, (_, i) => ({ value: `Person ${i}`, category: "PERSON" }));

function harness(store: { pending: unknown[]; notShown?: number }) {
  const els: Record<string, Record<string, unknown>> = {};
  const el = (id: string) =>
    (els[id] ??= {
      id,
      value: id === "caseId" ? "INC-1" : "",
      textContent: "",
      innerHTML: "",
      style: {},
      classList: { add() {}, remove() {}, toggle() {} },
      querySelectorAll: () => [],
      setAttribute() {},
    });
  let gets = 0;
  const m = loadDashboardModule<Api>("dashboard-presidio.js", ["dashboard-escape.js"], {
    document: { getElementById: el, querySelectorAll: () => [] },
    refreshAiState() {},
    fetch: (url: string) => {
      if (url.endsWith("/presidio-pending")) gets++;
      return Promise.resolve({ ok: true, status: 200, json: () => Promise.resolve(store) });
    },
  });
  const panel = () => String(el("presidioPending").innerHTML);
  const rows = () => (panel().match(/class="presidio-row"/g) ?? []).length;
  return { m, panel, rows, badge: () => String(el("presidioPendingBadge").textContent), gets: () => gets };
}

const flush = () => new Promise((r) => setTimeout(r, 0));

describe("the Presidio panel says when a stop held more than the list keeps (#2985)", () => {
  it("names the values it could not hold and says to re-run for the rest", async () => {
    const h = harness({ pending: people(500), notShown: 100 });
    h.m.loadPresidioPending("INC-1");
    await flush();
    expect(h.rows()).toBe(500);
    expect(h.panel()).toContain("500 new value(s) still to decide");
    expect(h.panel()).toContain("100 more");
    expect(h.panel()).toMatch(/re-run the same action/);
    expect(h.badge()).toBe("⚠ Presidio: 500+");
  });

  it("says nothing extra when the whole hold fits", async () => {
    const h = harness({ pending: people(3), notShown: 0 });
    h.m.loadPresidioPending("INC-1");
    await flush();
    expect(h.panel()).not.toContain("more than the list can hold");
    expect(h.badge()).toBe("⚠ Presidio: 3");
  });

  it("drops the note once the list is empty", async () => {
    const h = harness({ pending: people(500), notShown: 100 });
    h.m.loadPresidioPending("INC-1");
    await flush();
    h.m.setPresidioPending([]);
    expect(h.panel()).toBe("");
    h.m.setPresidioPending(people(2));
    expect(h.panel()).not.toContain("more than the list can hold");
  });

  it("replaces a raw 600-value hold answer with the 500 the server kept, and the count", async () => {
    const h = harness({ pending: people(500), notShown: 100 });
    h.m.loadPresidioPending("INC-1");
    await flush();
    const before = h.gets();
    h.m.setPresidioPending(people(600), "INC-1");
    await flush();
    expect(h.gets()).toBe(before + 1);
    expect(h.rows()).toBe(500);
    expect(h.panel()).toContain("100 more");
  });
});
