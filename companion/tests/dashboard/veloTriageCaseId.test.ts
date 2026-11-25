import { beforeEach, describe, expect, it } from "vitest";
import { loadDashboardModule } from "../helpers/dashboardModule.js";

// The case-less Velociraptor calls the dashboard makes from inside an open case must name that
// case, so the server answers from the case's own server set. With no case open they name none and
// the server uses the default set.

interface Call {
  url: string;
  body?: Record<string, unknown>;
}
interface Api {
  loadVeloClients(): void;
  doRefreshVeloClients(): void;
  doVeloReconnect(btnId?: string, msgId?: string): Promise<void>;
  veloTimeScopePreview(bundleId: string, form: unknown): void;
  activeCaseId: string | null;
  veloEnabled: boolean;
}

const calls: Call[] = [];
let answer: Record<string, unknown> = {};
const el = () => ({ textContent: "", innerHTML: "", disabled: false, value: "" });
const nodes: Record<string, ReturnType<typeof el>> = {};
const document = { getElementById: (id: string) => (nodes[id] ??= el()) };
const fetch = async (url: string, init?: { body?: string }) => {
  calls.push({ url, body: init?.body ? JSON.parse(init.body) : undefined });
  return {
    ok: true,
    json: async () => ({ updatedAt: "", clients: [], scoped: [], unscoped: [], ...answer }),
  };
};

const triage = loadDashboardModule<Api>(
  "dashboard-velo-triage.js",
  [
    "dashboard-escape.js",
    "dashboard-time.js",
    "dashboard-values.js",
    "dashboard-velo-case.js",
    "dashboard-velo-clients.js",
  ],
  { document, fetch, activeCaseId: null, veloEnabled: true, saveSettings: async () => true },
);

const form = () => {
  const parts: Record<string, { value: string; textContent: string }> = {
    ".velo-timescope": { value: "7d", textContent: "" },
    ".velo-ts-start": { value: "", textContent: "" },
    ".velo-ts-end": { value: "", textContent: "" },
    ".velo-ts-preview": { value: "", textContent: "" },
  };
  return { querySelector: (sel: string) => parts[sel] ?? { value: "", textContent: "" } };
};

beforeEach(() => {
  calls.length = 0;
  answer = {};
  triage.activeCaseId = null;
  triage.veloEnabled = true;
});

describe("the open case's id rides on the case-less Velociraptor calls", () => {
  it("client list, client refresh and time-scope preview send the open case's id", () => {
    triage.activeCaseId = "case-b";
    triage.loadVeloClients();
    triage.doRefreshVeloClients();
    triage.veloTimeScopePreview("best-practice", form());
    expect(calls.map((c) => c.url)).toEqual([
      "/velociraptor/clients?caseId=case-b",
      "/velociraptor/clients/refresh",
      "/velociraptor/bundles/best-practice/time-scope-preview",
    ]);
    expect(calls[1].body).toEqual({ caseId: "case-b" });
    expect(calls[2].body).toMatchObject({ preset: "7d", caseId: "case-b" });
  });

  it("with no case open they name no case, so the server uses the default set", () => {
    triage.loadVeloClients();
    triage.doRefreshVeloClients();
    triage.veloTimeScopePreview("best-practice", form());
    expect(calls[0].url).toBe("/velociraptor/clients");
    expect(calls[1].body).toEqual({});
    expect(calls[2].body).toEqual({ preset: "7d" });
  });

  it("Reconnect names the open case, so it reconnects the case's own server set", async () => {
    triage.activeCaseId = "case-b";
    await triage.doVeloReconnect();
    const call = calls.find((c) => c.url === "/velociraptor/reconnect");
    expect(call?.body).toEqual({ caseId: "case-b" });
  });

  it("Reconnect with no case open names no case, so the server reconnects the default set", async () => {
    await triage.doVeloReconnect();
    const call = calls.find((c) => c.url === "/velociraptor/reconnect");
    expect(call?.body).toEqual({});
  });
});

// #2887: a client list the server cut at its row limit says so on the triage card.
describe("the client list says when the server cut it", () => {
  const settle = () => new Promise((r) => setTimeout(r, 0));
  const clients = [{ clientId: "C.a", hostname: "ws-a", fqdn: "" }];

  it("a cut list carries the notice, after the refresh too", async () => {
    answer = { clients, truncated: true };
    triage.loadVeloClients();
    await settle();
    expect(nodes.veloClientsMsg.textContent).toContain("1 enrolled client");
    expect(nodes.veloClientsMsg.textContent).toContain(
      "Showing the first 100,000 clients the server returned — a client past that is not listed here; run a fleet hunt or use the Velociraptor GUI.",
    );
    nodes.veloClientsMsg.textContent = "";
    triage.doRefreshVeloClients();
    await settle();
    expect(nodes.veloClientsMsg.textContent).toContain("Showing the first 100,000 clients");
  });

  it("a complete list has no notice", async () => {
    answer = { clients };
    triage.loadVeloClients();
    await settle();
    expect(nodes.veloClientsMsg.textContent).toContain("1 enrolled client");
    expect(nodes.veloClientsMsg.textContent).not.toContain("100,000");
  });
});
