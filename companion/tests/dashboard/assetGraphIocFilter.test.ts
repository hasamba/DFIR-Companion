import { readFileSync } from "node:fs";
import { describe, it, expect } from "vitest";
import { loadDashboardModule } from "../helpers/dashboardModule.js";

// The Compromised Assets & IOC graph drew every IOC linked to a host. A case with 1,992 IOCs became a
// solid blob, and the Show box had no IOC control. It now has "IOCs" and "Flagged only" checkboxes
// (flagged-only on by default, like the IOC panel's "Signal only") and a count of what is hidden.

interface Ioc {
  id: string;
  assetIds: string[];
  verdict?: string;
}
interface AssetGraphApi {
  assetVisibleIocs(
    iocs: Ioc[],
    assetIds: Set<string>,
    view: { show: boolean; flaggedOnly: boolean },
  ): { visible: Ioc[]; total: number };
}

const api = () =>
  loadDashboardModule<AssetGraphApi>("dashboard-asset-graph.js", ["dashboard-escape.js"], {
    fetch: () => new Promise(() => {}),
    document: { getElementById: () => null, querySelectorAll: () => [] },
    DfirTimelineView: { timeQuery: () => "" },
  });

const IOCS: Ioc[] = [
  { id: "bad", assetIds: ["h1"], verdict: "malicious" },
  { id: "maybe", assetIds: ["h1"], verdict: "suspicious" },
  { id: "fine", assetIds: ["h1"], verdict: "harmless" },
  { id: "none", assetIds: ["h1"] },
  { id: "other-host", assetIds: ["h2"], verdict: "malicious" },
];
const H1 = new Set(["h1"]);
const ids = (r: { visible: Ioc[] }) => r.visible.map((i) => i.id);

describe("assetVisibleIocs", () => {
  it("flagged only keeps malicious and suspicious IOCs and counts the rest as hidden", () => {
    const r = api().assetVisibleIocs(IOCS, H1, { show: true, flaggedOnly: true });
    expect(ids(r)).toEqual(["bad", "maybe"]);
    expect(r.total).toBe(4);
  });

  it("with flagged-only off, draws every IOC linked to a visible host", () => {
    const r = api().assetVisibleIocs(IOCS, H1, { show: true, flaggedOnly: false });
    expect(ids(r)).toEqual(["bad", "maybe", "fine", "none"]);
  });

  it("with IOCs off, draws none and still reports how many are linked", () => {
    const r = api().assetVisibleIocs(IOCS, H1, { show: false, flaggedOnly: false });
    expect(r.visible).toEqual([]);
    expect(r.total).toBe(4);
  });

  it("ignores an IOC linked only to a host that is switched off", () => {
    const r = api().assetVisibleIocs(IOCS, new Set(["h3"]), { show: true, flaggedOnly: false });
    expect(r.total).toBe(0);
  });
});

describe("IOC checkboxes in the graph's Show box", () => {
  const html = readFileSync(new URL("../../../public/dashboard.html", import.meta.url), "utf8");
  const js = readFileSync(new URL("../../../public/js/dashboard-asset-graph.js", import.meta.url), "utf8");

  it("offers IOCs and Flagged only, both ticked, and a count", () => {
    expect(html).toMatch(/<input type="checkbox" id="assetShowIocs" checked>/);
    expect(html).toMatch(/<input type="checkbox" id="assetFlaggedIocs" checked>/);
    expect(html).toContain('id="assetIocCount"');
  });

  it("wires both checkboxes and redraws the graph", () => {
    expect(js).toContain('getElementById("assetShowIocs")');
    expect(js).toContain('getElementById("assetFlaggedIocs")');
    expect(js).toMatch(/assetIocView\.show = showIocs\.checked/);
    expect(js).toMatch(/assetIocView\.flaggedOnly = flaggedIocs\.checked/);
  });
});
