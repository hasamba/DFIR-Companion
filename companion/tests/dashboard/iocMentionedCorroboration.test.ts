// #1474: an IOC with `provenance: "mentioned"` (#1459 hash, #1461 network) was read out of free
// text — a command line, a script block. The import/merge invariant means it had no structured
// sighting, so every event that "contains" its value is one that merely mentions it. The IOC
// panel's "⊕ N — Corroborated by N sources" badge, the "⊕ 2+/3+ src" lens and "Signal only" all
// read iocCorroborationCount(), and until this change they counted a mention as corroboration.
import { describe, it, expect } from "vitest";
import { loadDashboardModule } from "../helpers/dashboardModule.js";

interface Ioc {
  id: string;
  type: string;
  value: string;
  provenance?: string;
}
interface State {
  iocs: Ioc[];
}
interface ProvenanceApi {
  loadIocSources: (caseId: string) => void;
  iocCorroborationCount: (iocId: string) => number;
  iocCorroBadge: (iocId: string) => string;
}

const SOURCES: Record<string, string[]> = {
  i1: ["Hayabusa", "Cyber Triage"],
  i2: ["Hayabusa", "Cyber Triage"],
  i3: ["Hayabusa", "Chainsaw", "THOR"],
};

function stateWith(iocs: Ioc[]): State {
  return { iocs };
}

const BASE_IOCS: Ioc[] = [
  { id: "i1", type: "ip", value: "203.0.113.5", provenance: "mentioned" },
  { id: "i2", type: "ip", value: "203.0.113.6" },
  { id: "i3", type: "hash", value: "a".repeat(64), provenance: "mentioned" },
];

function harness(initial: State | null) {
  let current: State | null = initial;
  const fetched: string[] = [];
  const el = (id: string) => (id === "caseId" ? { value: "CASE-1" } : null);
  const api = loadDashboardModule<ProvenanceApi>("dashboard-ioc-provenance.js", ["dashboard-escape.js"], {
    activeCaseId: "CASE-1", // the loaders refuse a case that is not on screen (#1653)
    fetch: async (url: string) => {
      fetched.push(url);
      return { ok: true, json: async () => (url.endsWith("/ioc-sources") ? SOURCES : {}) };
    },
    document: { getElementById: el, querySelectorAll: () => [] },
    DfirState: { lastState: () => current, lastFt: () => [] },
    DfirScope: { project: (s: unknown) => s },
    // loadIocSources re-renders the panel once the map lands; the panel is core page machinery.
    renderIocs: () => {},
    ICON_CHAIN: "<svg></svg>",
    localStorage: { getItem: () => null, setItem() {} },
  });
  const setState = (s: State | null) => {
    current = s;
  };
  return { api, fetched, setState };
}

async function settled(): Promise<void> {
  // fetch → json → assign is a three-hop promise chain; a macrotask turn drains it.
  await new Promise((r) => setTimeout(r, 0));
}

describe("IOC panel — a mention is not corroboration (#1474)", () => {
  it("counts 0 sources for a mentioned IOC and the real count for a plain one", async () => {
    const { api, fetched } = harness(stateWith(BASE_IOCS));
    api.loadIocSources("CASE-1");
    await settled();
    expect(fetched).toEqual(["/cases/CASE-1/ioc-sources"]);
    expect(api.iocCorroborationCount("i1")).toBe(0);
    expect(api.iocCorroborationCount("i2")).toBe(2);
    expect(api.iocCorroborationCount("i3")).toBe(0);
  });

  it("keeps the green badge for a plain IOC", async () => {
    const { api } = harness(stateWith(BASE_IOCS));
    api.loadIocSources("CASE-1");
    await settled();
    const html = api.iocCorroBadge("i2");
    expect(html).toContain("Corroborated by 2 sources");
    expect(html).toContain("⊕ 2");
  });

  it("draws a neutral 'referenced' chip for a mentioned IOC, never the corroboration badge", async () => {
    const { api } = harness(stateWith(BASE_IOCS));
    api.loadIocSources("CASE-1");
    await settled();
    const ip = api.iocCorroBadge("i1");
    expect(ip).toContain("↗ 2");
    expect(ip).toContain("Referenced in events from 2 sources");
    expect(ip).toContain("Hayabusa, Cyber Triage");
    expect(ip).not.toContain("Corroborated");
    expect(ip).not.toContain("⊕");
    const hash = api.iocCorroBadge("i3");
    expect(hash).toContain("↗ 3");
    expect(hash).not.toContain("Corroborated");
  });

  it("compares the mark strictly — a 'mentioned-ish' provenance is an ordinary sighting", async () => {
    const { api } = harness(
      stateWith([{ id: "i1", type: "ip", value: "203.0.113.5", provenance: "mentioned-ish" }]),
    );
    api.loadIocSources("CASE-1");
    await settled();
    expect(api.iocCorroborationCount("i1")).toBe(2);
    expect(api.iocCorroBadge("i1")).toContain("Corroborated by 2 sources");
  });

  it("re-reads the marks when the state object changes (cache keyed on identity)", async () => {
    const { api, setState } = harness(stateWith(BASE_IOCS));
    api.loadIocSources("CASE-1");
    await settled();
    expect(api.iocCorroborationCount("i1")).toBe(0);
    setState(stateWith([{ id: "i1", type: "ip", value: "203.0.113.5" }]));
    expect(api.iocCorroborationCount("i1")).toBe(2);
    expect(api.iocCorroBadge("i1")).toContain("Corroborated by 2 sources");
  });

  it("with no state loaded, nothing is treated as mentioned and the count is unchanged", async () => {
    const { api } = harness(null);
    api.loadIocSources("CASE-1");
    await settled();
    expect(api.iocCorroborationCount("i1")).toBe(2);
    expect(api.iocCorroborationCount("missing")).toBe(0);
    expect(api.iocCorroBadge("missing")).toBe("");
  });
});
