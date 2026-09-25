// #1653: the four IOC metadata loaders (sources, provenance, risk, provenance chain) stored
// whatever answer came back and repainted the IOC panel with it. A slow answer for case A that
// landed after the analyst switched to case B painted B with A's corroboration, provenance and
// risk data. The fix reuses the #937 authority: the page's activeCaseId, checked at loader entry
// and again when the answer lands, plus a per-resource sequence so an A -> B -> A switch cannot
// let the first A answer overwrite the second.
import { describe, it, expect } from "vitest";
import { loadDashboardModule } from "../helpers/dashboardModule.js";

interface Api {
  activeCaseId: string | null;
  loadIocSources: (caseId: string) => void;
  loadIocProvenance: (caseId: string) => void;
  loadIocRisk: (caseId: string) => void;
  loadIocProvenanceChains: (caseId: string) => void;
  scheduleIocProvenanceReload: () => void;
  flushDeferredIocProvenanceReloads: () => void;
  iocCorroborationCount: (id: string) => number;
  iocProvenanceOf: (id: string) => string;
  iocRiskRankOf: (id: string) => number;
  iocChainFor: (id: string) => unknown;
}

interface Pending {
  url: string;
  resolve: (body: unknown, ok?: boolean) => void;
  reject: () => void;
}

const A_SOURCES = { "ioc-1": ["velociraptor", "thor"] };
const A_PROVENANCE = { "ioc-1": "detection" };
const A_RISK = { "ioc-1": { score: "critical", factors: ["A"] } };
const A_CHAIN = {
  "ioc-1": { type: "ip", value: "203.0.113.9", extraction: [], enrichment: [], findings: [] },
};

function harness(opts: { importRunning?: () => boolean } = {}) {
  const pending: Pending[] = [];
  let renders = 0;
  const overlay = {
    dataset: {} as Record<string, string>,
    classList: {
      open: false,
      add() {
        overlay.classList.open = true;
      },
      remove() {
        overlay.classList.open = false;
      },
      contains() {
        return overlay.classList.open;
      },
    },
  };
  const caseInput = { value: "A" };
  // The state the page holds — no caseId unless a test names one, like a pre-#1653 fixture.
  const shown: { state: { iocs: unknown[]; caseId?: string } | null } = { state: { iocs: [] } };
  const el = (id: string) => (id === "caseId" ? caseInput : id === "iocChainOverlay" ? overlay : null);
  const api = loadDashboardModule<Api>("dashboard-ioc-provenance.js", ["dashboard-escape.js"], {
    activeCaseId: "A",
    fetch: (url: string) =>
      new Promise((res, rej) => {
        pending.push({
          url,
          resolve: (body, ok = true) => res({ ok, status: ok ? 200 : 500, json: async () => body }),
          reject: () => rej(new Error("network")),
        });
      }),
    document: { getElementById: el, querySelectorAll: () => [] },
    DfirState: { lastState: () => shown.state, lastFt: () => [] },
    DfirScope: { project: (s: unknown) => s },
    renderIocs: () => {
      renders++;
    },
    ICON_CHAIN: "<svg></svg>",
    localStorage: { getItem: () => null, setItem() {} },
    setTimeout: (fn: () => void, ms: number) => globalThis.setTimeout(fn, ms),
    clearTimeout: (id: unknown) => globalThis.clearTimeout(id as number),
    runningJob: (kind: string) => (kind === "import" && opts.importRunning?.() ? { id: "imp-1" } : undefined),
  });
  const find = (suffix: string, caseId: string) => {
    const hit = [...pending].reverse().find((p) => p.url === `/cases/${caseId}/${suffix}`);
    if (!hit) throw new Error(`no request for ${caseId}/${suffix}`);
    return hit;
  };
  return { api, pending, overlay, caseInput, shown, find, renders: () => renders };
}

const flush = () => new Promise((r) => setTimeout(r, 0));

function loadAll(api: Api, caseId: string) {
  api.loadIocSources(caseId);
  api.loadIocProvenance(caseId);
  api.loadIocRisk(caseId);
  api.loadIocProvenanceChains(caseId);
}

async function answerA(h: ReturnType<typeof harness>, caseId = "A") {
  h.find("ioc-sources", caseId).resolve(A_SOURCES);
  h.find("ioc-provenance", caseId).resolve(A_PROVENANCE);
  h.find("ioc-risk", caseId).resolve(A_RISK);
  h.find("ioc-provenance-chain", caseId).resolve(A_CHAIN);
  await flush();
}

function expectEmpty(api: Api) {
  expect(api.iocCorroborationCount("ioc-1")).toBe(0);
  expect(api.iocProvenanceOf("ioc-1")).toBe("telemetry");
  expect(api.iocRiskRankOf("ioc-1")).toBe(-1);
  expect(api.iocChainFor("ioc-1")).toBeUndefined();
}

function expectA(api: Api) {
  expect(api.iocCorroborationCount("ioc-1")).toBe(2);
  expect(api.iocProvenanceOf("ioc-1")).toBe("detection");
  expect(api.iocRiskRankOf("ioc-1")).toBe(4);
  expect(api.iocChainFor("ioc-1")).toBeTruthy();
}

describe("IOC metadata answers belong to the case that asked (#1653)", () => {
  it("control: an answer for the case on screen is stored and repaints the panel", async () => {
    const h = harness();
    loadAll(h.api, "A");
    await answerA(h);
    expectA(h.api);
    expect(h.renders()).toBe(3); // sources, provenance, risk — the chain map feeds only the panel
  });

  it("a slow case-A answer that lands after the switch to B is dropped, for all four resources", async () => {
    const h = harness();
    loadAll(h.api, "A");
    h.api.activeCaseId = "B";
    loadAll(h.api, "B");
    await answerA(h, "A");
    expectEmpty(h.api);
    expect(h.renders()).toBe(0);
  });

  it("B's own answer still lands after A's stale one is dropped", async () => {
    const h = harness();
    loadAll(h.api, "A");
    h.api.activeCaseId = "B";
    loadAll(h.api, "B");
    await answerA(h, "A");
    await answerA(h, "B"); // same payload, served for B
    expectA(h.api);
    expect(h.renders()).toBe(3);
  });

  it("switching case clears A's data at once, before B answers — and a failed B leaves it empty", async () => {
    const h = harness();
    loadAll(h.api, "A");
    await answerA(h);
    expectA(h.api);
    h.api.activeCaseId = "B";
    loadAll(h.api, "B");
    expectEmpty(h.api); // synchronous: B never shows A's badges while its own answer is pending
    h.find("ioc-sources", "B").reject();
    h.find("ioc-provenance", "B").resolve({ error: "boom" }, false);
    h.find("ioc-risk", "B").reject();
    h.find("ioc-provenance-chain", "B").reject();
    await flush();
    expectEmpty(h.api);
  });

  it("A -> B -> A: the first A answer landing last does not overwrite the second", async () => {
    const h = harness();
    loadAll(h.api, "A");
    const firstA = {
      sources: h.find("ioc-sources", "A"),
      provenance: h.find("ioc-provenance", "A"),
      risk: h.find("ioc-risk", "A"),
      chain: h.find("ioc-provenance-chain", "A"),
    };
    h.api.activeCaseId = "B";
    loadAll(h.api, "B");
    h.api.activeCaseId = "A";
    loadAll(h.api, "A");
    await answerA(h, "A"); // the second A request answers first
    expectA(h.api);
    firstA.sources.resolve({});
    firstA.provenance.resolve({});
    firstA.risk.resolve({});
    firstA.chain.resolve({});
    await flush();
    expectA(h.api);
  });

  it("a cancelled case load (no active case) drops the answer", async () => {
    const h = harness();
    loadAll(h.api, "A");
    h.api.activeCaseId = null;
    await answerA(h);
    expectEmpty(h.api);
    expect(h.renders()).toBe(0);
  });

  it("a stale caller for a case not on screen sends no request and keeps the parked reload", () => {
    let running = true;
    const h = harness({ importRunning: () => running });
    h.caseInput.value = "B";
    h.api.activeCaseId = "B";
    h.api.scheduleIocProvenanceReload(); // parked: B is importing
    loadAll(h.api, "A"); // e.g. a debounce timer armed for A before the switch
    expect(h.pending).toEqual([]);
    running = false;
    h.api.flushDeferredIocProvenanceReloads();
    return new Promise<void>((done) =>
      setTimeout(() => {
        expect(h.pending.map((p) => p.url)).toEqual(["/cases/B/ioc-provenance"]);
        done();
      }, 850),
    );
  });

  it("an open provenance-chain panel from case A closes when case B's chains start loading", async () => {
    const h = harness();
    h.api.loadIocProvenanceChains("A");
    await flush();
    h.overlay.classList.add();
    h.overlay.dataset.iocid = "ioc-1";
    h.api.activeCaseId = "B";
    h.api.loadIocProvenanceChains("B");
    expect(h.overlay.classList.open).toBe(false);
    expect(h.overlay.dataset.iocid).toBeUndefined();
  });

  it("a same-case reload does not close the chain panel the analyst is reading", async () => {
    const h = harness();
    h.api.loadIocProvenanceChains("A");
    h.overlay.classList.add();
    h.overlay.dataset.iocid = "ioc-1";
    h.api.loadIocProvenanceChains("A");
    expect(h.overlay.classList.open).toBe(true);
  });

  it("B's answer landing while the page still holds A's state does not repaint A's rows", async () => {
    const h = harness();
    h.shown.state = { iocs: [], caseId: "A" };
    h.api.activeCaseId = "B";
    loadAll(h.api, "B");
    await answerA(h, "B");
    expect(h.renders()).toBe(0); // B's own state render reads the metadata when it lands
    h.shown.state = { iocs: [], caseId: "B" };
    h.api.loadIocRisk("B");
    h.find("ioc-risk", "B").resolve(A_RISK);
    await flush();
    expect(h.renders()).toBe(1);
  });

  it("after a cancelled switch, metadata the abandoned case committed reads as empty", async () => {
    const h = harness();
    h.api.activeCaseId = "B";
    loadAll(h.api, "B");
    await answerA(h, "B");
    expectA(h.api);
    h.api.activeCaseId = null; // the analyst cancels B's load; A's rows may still be on screen
    expectEmpty(h.api);
  });

  it("reload timers act for the active case, not for a case typed into the picker", async () => {
    const h = harness();
    h.caseInput.value = "B"; // typed, or left behind by a cancelled unlock; A is still loaded
    h.api.scheduleIocProvenanceReload();
    await new Promise((r) => setTimeout(r, 850));
    expect(h.pending.map((p) => p.url)).toEqual(["/cases/A/ioc-provenance"]);
  });
});
