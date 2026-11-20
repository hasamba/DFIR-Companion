import { describe, expect, it } from "vitest";
import { loadDashboardModule } from "../helpers/dashboardModule.js";
import {
  FakeDocument,
  type FakeEl,
  flush,
  type Route,
  routedFetch,
  type FetchCall,
} from "./serverSetsFakeDom.js";

// New Case → threat hunt → client (#2670, decision D5). A client is its own record; its default
// server set only PRE-FILLS a new hunt case's Servers picker. The analyst's own pick always wins,
// nothing changes for existing cases, and host membership is never inferred from the client.

interface NewCaseApi {
  openNewCase(): Promise<void>;
  createNewCase(): Promise<void>;
  initNewCase(): void;
}

const SETS = {
  defaultId: "b",
  sets: [
    { id: "a", name: "Alpha", revision: 1, usedBy: 0 },
    { id: "b", name: "Beta", revision: 1, usedBy: 0 },
    { id: "c", name: "Gamma", revision: 1, usedBy: 0 },
  ],
};
const CLIENTS = [
  { id: "client-a-1", name: "Client A", defaultServerSetId: "a" },
  { id: "client-b-2", name: "Client B" },
  { id: "client-z-3", name: "Client Z", defaultServerSetId: "gone" },
];
const HUNT = { kind: "type", id: "threat-hunt", def: { id: "threat-hunt", mode: "hunt" } };
const RANSOMWARE = { kind: "type", id: "ransomware", def: { id: "ransomware" } };

type Routes = Record<string, Route | ((call: FetchCall) => Route | Promise<Route>)>;

function harness(extra: Routes = {}) {
  const doc = new FakeDocument();
  doc.add("input", "ncCaseId", "ncName", "ncInvestigator", "caseId");
  doc.add("div", "ncMsg", "ncTemplateDesc", "newCaseOverlay");
  doc.add("label", "ncHuntClientRow");
  doc.add("select", "ncServerSet", "ncTemplate", "ncHuntClient");
  doc.add("button", "newCaseBtn", "seedDemoBtn", "ncCreate", "ncCancel");
  const net = routedFetch({
    "GET /server-sets": { body: SETS },
    "GET /client-profiles": { body: CLIENTS },
    "GET /api/next-case-id": { body: { caseId: "INC-2026-001" } },
    "POST /cases": { status: 201, body: {} },
    "POST /cases/INC-2026-001/hunt/client": { body: {} },
    ...extra,
  });
  const pick = { current: HUNT as Record<string, unknown> };
  const alerts: string[] = [];
  const api = loadDashboardModule<NewCaseApi>("dashboard-new-case.js", ["dashboard-server-sets.js"], {
    document: doc,
    fetch: net.fetch,
    localStorage: { getItem: () => "", setItem: () => {} },
    populateTemplateSelect: () => {},
    selectedNewCasePlaybook: () => pick.current,
    onTemplateSelectChange: () => {},
    loadCaseList: () => {},
    connect: () => {},
    alert: (m: string) => alerts.push(m),
  });
  api.initNewCase();
  const el = (id: string) => doc.getElementById(id) as FakeEl;
  const chooseClient = async (id: string) => {
    el("ncHuntClient").value = id;
    el("ncHuntClient").fire("change");
    await flush();
  };
  return { api, net, el, pick, alerts, chooseClient };
}

describe("New Case: a threat hunt's client pre-fills its servers (#2670, D5)", () => {
  it("offers the client picker only for a threat-hunt type", async () => {
    const h = harness();
    h.pick.current = RANSOMWARE;
    await h.api.openNewCase();
    await flush();
    expect(h.el("ncHuntClientRow").hidden).toBe(true);
    h.pick.current = HUNT;
    h.el("ncTemplate").fire("change");
    expect(h.el("ncHuntClientRow").hidden).toBe(false);
    expect(h.el("ncHuntClient").options.map((o) => o.textContent)).toEqual([
      "No client",
      "Client A",
      "Client B",
      "Client Z",
    ]);
  });

  it("picking a client pre-fills its default server set, and the case links to that client", async () => {
    const h = harness();
    await h.api.openNewCase();
    await flush();
    expect(h.el("ncServerSet").value).toBe("b");
    await h.chooseClient("client-a-1");
    expect(h.el("ncServerSet").value).toBe("a");
    h.el("ncName").value = "Quarterly hunt";
    await h.api.createNewCase();
    const created = h.net.calls.find((c) => c.method === "POST" && c.url === "/cases");
    expect(created?.body?.serverSetId).toBe("a");
    const link = h.net.calls.find((c) => c.url === "/cases/INC-2026-001/hunt/client");
    expect(link?.body).toEqual({ clientId: "client-a-1" });
  });

  it("never overrides a server set the analyst picked themselves", async () => {
    const h = harness();
    await h.api.openNewCase();
    await flush();
    h.el("ncServerSet").value = "c";
    h.el("ncServerSet").fire("change");
    await h.chooseClient("client-a-1");
    expect(h.el("ncServerSet").value).toBe("c");
  });

  it("a client with no default, or a default set that no longer exists, leaves the picker alone", async () => {
    const h = harness();
    await h.api.openNewCase();
    await flush();
    await h.chooseClient("client-b-2");
    expect(h.el("ncServerSet").value).toBe("b");
    await h.chooseClient("client-z-3");
    expect(h.el("ncServerSet").value).toBe("b");
  });

  it("a non-hunt case is never linked to a client, even if one was picked earlier", async () => {
    const h = harness();
    await h.api.openNewCase();
    await flush();
    await h.chooseClient("client-a-1");
    h.pick.current = RANSOMWARE;
    h.el("ncTemplate").fire("change");
    h.el("ncName").value = "Ransomware";
    await h.api.createNewCase();
    expect(h.net.calls.some((c) => c.url.endsWith("/hunt/client"))).toBe(false);
  });

  it("hides the picker when client profiles are unavailable (the public demo answers 403)", async () => {
    const h = harness({ "GET /client-profiles": { status: 403, body: { error: "Demo mode", demo: true } } });
    await h.api.openNewCase();
    await flush();
    expect(h.el("ncHuntClientRow").hidden).toBe(true);
  });

  it("a failed link keeps the new case and says so", async () => {
    const h = harness({
      "POST /cases/INC-2026-001/hunt/client": { status: 403, body: { error: "forbidden" } },
    });
    await h.api.openNewCase();
    await flush();
    await h.chooseClient("client-a-1");
    h.el("ncName").value = "Quarterly hunt";
    await h.api.createNewCase();
    expect(h.alerts.join(" ")).toMatch(/created, but linking it to the client failed/);
    expect(h.el("newCaseOverlay").classList.contains("open")).toBe(false);
  });
});
