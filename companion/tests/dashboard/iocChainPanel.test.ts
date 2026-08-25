import { describe, it, expect } from "vitest";
import { loadDashboardModule } from "../helpers/dashboardModule.js";

// #640 — the chain panel used to state "linked — a real source-event reference, not a guess" and
// then show ONE event's text. Both halves can be true while the IOC value is nowhere in that text:
// aggregation collapses many records into one event and keeps the FIRST one's description, and
// `description`/`message` are truncated before storage. The analyst reads that as the tool
// attributing an address to a connection that never carried it. The panel has to say which.

interface ChainPanelApi {
  loadIocProvenanceChains(caseId: string): void;
  openIocChainPanel(caseId: string, iocId: string): void;
}

interface FakeEl {
  innerHTML: string;
  textContent: string;
  dataset: Record<string, string>;
  classList: { add(): void; remove(): void };
  value: string;
}

const drain = () => new Promise((r) => setImmediate(r));

function panel(chains: Record<string, unknown>) {
  const els = new Map<string, FakeEl>();
  const el = (id: string): FakeEl => {
    let e = els.get(id);
    if (!e) {
      e = {
        innerHTML: "",
        textContent: "",
        dataset: {},
        classList: { add() {}, remove() {} },
        value: "CASE-1",
      };
      els.set(id, e);
    }
    return e;
  };
  const api = loadDashboardModule<ChainPanelApi>("dashboard-ioc-provenance.js", ["dashboard-escape.js"], {
    fetch: async () => ({ ok: true, json: async () => chains }),
    document: { getElementById: el, querySelectorAll: () => [] },
    DfirState: { lastState: () => null, lastFt: () => [] },
    DfirScope: { project: (s: unknown) => s },
    eventDeepLink: (c: string, id: string) => `/#${c}/${id}`,
    ICON_CHAIN: "<svg></svg>",
    localStorage: { getItem: () => null, setItem() {} },
  });
  return { api, body: () => el("iocChainBody").innerHTML };
}

function chainWith(extraction: Record<string, unknown>[]) {
  return {
    i1: {
      iocId: "i1",
      value: "203.0.113.99",
      type: "ip",
      extraction,
      extractionTruncated: 0,
      extractionAuthoritative: true,
      enrichment: [],
      findings: [],
    },
  };
}

describe("IOC chain panel — merge and truncation disclosure (#640)", () => {
  it("says how many records a merged extraction event stands for", async () => {
    const { api, body } = panel(
      chainWith([
        {
          eventId: "e1",
          timestamp: "2026-01-01T00:00:00Z",
          endTimestamp: "2026-01-01T06:00:00Z",
          description: "Sigma: Net Conn - TgtIP: 203.0.113.10",
          severity: "Medium",
          count: 47,
        },
      ]),
    );
    api.loadIocProvenanceChains("CASE-1");
    await drain();
    api.openIocChainPanel("CASE-1", "i1");
    expect(body()).toContain("47");
    expect(body()).toMatch(/1 of 47/i);
    expect(body()).toContain("2026-01-01T06:00:00Z");
  });

  it("warns when the IOC value is absent from the event text it shows", async () => {
    const { api, body } = panel(
      chainWith([
        {
          eventId: "e1",
          timestamp: "2026-01-01T00:00:00Z",
          description: "Sigma: Net Conn - TgtIP: 203.0.113.10",
          severity: "Medium",
          count: 47,
          valueHidden: true,
        },
      ]),
    );
    api.loadIocProvenanceChains("CASE-1");
    await drain();
    api.openIocChainPanel("CASE-1", "i1");
    expect(body()).toMatch(/not (in|shown)/i);
  });

  it("does NOT claim a plain single-record link is merged or hidden", async () => {
    const { api, body } = panel(
      chainWith([
        {
          eventId: "e1",
          timestamp: "2026-01-01T00:00:00Z",
          description: "Sigma: Net Conn - TgtIP: 203.0.113.99",
          severity: "Medium",
        },
      ]),
    );
    api.loadIocProvenanceChains("CASE-1");
    await drain();
    api.openIocChainPanel("CASE-1", "i1");
    expect(body()).not.toMatch(/1 of /i);
    expect(body()).not.toMatch(/not (in|shown)/i);
  });

  it("escapes a merged count and end time rather than interpolating markup", async () => {
    const { api, body } = panel(
      chainWith([
        {
          eventId: "e1",
          timestamp: "2026-01-01T00:00:00Z",
          endTimestamp: "<img src=x onerror=alert(1)>",
          description: "d",
          severity: "Medium",
          count: 2,
        },
      ]),
    );
    api.loadIocProvenanceChains("CASE-1");
    await drain();
    api.openIocChainPanel("CASE-1", "i1");
    expect(body()).not.toContain("<img src=x");
    expect(body()).toContain("&lt;img");
  });
});
