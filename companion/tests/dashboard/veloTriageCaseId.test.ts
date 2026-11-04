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
  veloTimeScopePreview(bundleId: string, form: unknown): void;
  activeCaseId: string | null;
  veloEnabled: boolean;
}

const calls: Call[] = [];
const el = () => ({ textContent: "", innerHTML: "", disabled: false, value: "" });
const nodes: Record<string, ReturnType<typeof el>> = {};
const document = { getElementById: (id: string) => (nodes[id] ??= el()) };
const fetch = async (url: string, init?: { body?: string }) => {
  calls.push({ url, body: init?.body ? JSON.parse(init.body) : undefined });
  return { ok: true, json: async () => ({ updatedAt: "", clients: [], scoped: [], unscoped: [] }) };
};

const triage = loadDashboardModule<Api>(
  "dashboard-velo-triage.js",
  ["dashboard-escape.js", "dashboard-values.js", "dashboard-velo-case.js"],
  { document, fetch, activeCaseId: null, veloEnabled: true },
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
});
