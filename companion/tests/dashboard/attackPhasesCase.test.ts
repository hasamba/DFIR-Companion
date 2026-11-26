// #2894: the Attack Phases module kept case A's phases across a case switch. render() asks
// hasPhases() before redrawing the panel, so a state render for case B drew A's phases against B's
// timeline — even with the section hidden, when loadPhases never runs for B. The phases now belong
// to the case they were fetched for.
import { describe, expect, it } from "vitest";
import { loadDashboardModule } from "../helpers/dashboardModule.js";

interface PhasesApi {
  loadPhases(caseId: string): void;
  hasPhases(): boolean;
  renderPhases(): void;
}

// Drains the answer -> json() -> render chain (as panelDefer.test.ts does); nothing is polled for.
const settle = () => new Promise((r) => setTimeout(r, 0));
const flushAll = async () => {
  for (let i = 0; i < 4; i++) await settle();
};

const PHASE = (id: string) => ({
  id,
  label: `phase ${id}`,
  startTimestamp: "2024-01-01T00:00:00Z",
  eventCount: 1,
  eventIds: [],
});

function page() {
  const caseEl = { value: "CASE-A" };
  const listeners: ((e: unknown) => void)[] = [];
  const phasesEl = {
    innerHTML: "",
    addEventListener: (_t: string, fn: (e: unknown) => void) => listeners.push(fn),
  };
  const requests: { url: string; answer(body: unknown): void }[] = [];
  const api = loadDashboardModule<PhasesApi & { initAttackPhases(): void }>(
    "dashboard-attack-phases.js",
    ["dashboard-escape.js"],
    {
      document: {
        getElementById: (id: string) => (id === "caseId" ? caseEl : id === "phases" ? phasesEl : null),
      },
      fetch: (url: string) =>
        new Promise((resolve) => {
          requests.push({ url, answer: (body) => resolve({ ok: true, json: async () => body }) });
        }),
      DfirState: { lastFt: () => [] },
      _hasActiveFilter: () => false,
      KC_SEV_COLOR: {},
      mitreLinks: () => "",
    },
  );
  api.initAttackPhases();
  // Expanding a phase is a click on its head (the delegated handler).
  const expand = (id: string) =>
    listeners.forEach((fn) => fn({ target: { closest: () => ({ dataset: { phid: id } }) } }));
  return { api, caseEl, phasesEl, requests, expand };
}

describe("Attack Phases belong to the case they were loaded for (#2894)", () => {
  it("a case switch alone (no phases load for the new case) makes hasPhases() false", async () => {
    const p = page();
    p.api.loadPhases("CASE-A");
    p.requests[0].answer([PHASE("a1")]);
    await flushAll();
    expect(p.api.hasPhases()).toBe(true);
    p.caseEl.value = "CASE-B"; // the section is hidden for B, so loadPhases never runs
    expect(p.api.hasPhases()).toBe(false);
  });

  it("drawing the panel for another case shows the empty line, never the old case's phases", async () => {
    const p = page();
    p.api.loadPhases("CASE-A");
    p.requests[0].answer([PHASE("a1")]);
    await flushAll();
    expect(p.phasesEl.innerHTML).toContain("phase a1");
    p.caseEl.value = "CASE-B";
    p.api.renderPhases();
    expect(p.phasesEl.innerHTML).not.toContain("phase a1");
    expect(p.phasesEl.innerHTML).toContain("No dated events");
  });

  it("an answer for the case the analyst has left is ignored", async () => {
    const p = page();
    p.api.loadPhases("CASE-A");
    p.caseEl.value = "CASE-B";
    p.requests[0].answer([PHASE("a1")]);
    await flushAll();
    expect(p.api.hasPhases()).toBe(false);
    expect(p.phasesEl.innerHTML).toBe("");
  });

  it("a same-case reload keeps the expanded phases; a new case's load does not inherit them", async () => {
    const p = page();
    p.api.loadPhases("CASE-A");
    p.requests[0].answer([PHASE("x")]);
    await flushAll();
    p.expand("x");
    expect(p.phasesEl.innerHTML).toContain("ph-open");
    p.api.loadPhases("CASE-A");
    p.requests[1].answer([PHASE("x")]);
    await flushAll();
    expect(p.phasesEl.innerHTML).toContain("ph-open");
    p.caseEl.value = "CASE-B";
    p.api.loadPhases("CASE-B");
    p.requests[2].answer([PHASE("x")]); // same phase id in another case
    await flushAll();
    expect(p.phasesEl.innerHTML).not.toContain("ph-open");
  });
});
