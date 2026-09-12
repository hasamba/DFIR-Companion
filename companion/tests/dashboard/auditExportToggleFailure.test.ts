// A failed on/off switch must not leave the checkbox lying about what the server is doing.
//
// The dangerous direction is OFF. An operator who unticks a destination — because a case turned
// sensitive, or the collector is the wrong one — sees an unticked box while the server still holds
// the destination enabled and keeps forwarding case activity. The PUT's `if (r.ok)` swallowed the
// failure entirely: no error, no revert, and the one surface that reports the truth (the list) was
// only re-read on success.
import { describe, it, expect } from "vitest";
import { loadDashboardModule } from "../helpers/dashboardModule.js";

interface AuditExportApi {
  loadAuditExport: () => void;
  axToggle: (id: string, enabled: boolean) => void;
}

const DESTINATION = {
  id: "d1",
  type: "splunk",
  name: "SOC",
  enabled: true,
  splunk: { url: "https://splunk.example.com:8088", hasToken: true },
  status: { destinationId: "d1", sentTotal: 4 },
};

interface Call {
  url: string;
  method: string;
}

/** The pane's elements, plus a fetch whose answer per call the test chooses. */
function harness(putOk: boolean) {
  const list = { innerHTML: "" };
  const msg = { textContent: "", style: { color: "" } };
  const count = { textContent: "" };
  const elements: Record<string, unknown> = {
    axList: list,
    axCount: count,
    axMsg: msg,
  };
  const calls: Call[] = [];
  const globals = {
    document: {
      getElementById: (id: string) => elements[id] ?? null,
      querySelector: () => null,
      addEventListener: () => {},
    },
    fetch: (url: string, init?: { method?: string }) => {
      const method = init?.method ?? "GET";
      calls.push({ url, method });
      if (method === "GET") {
        return Promise.resolve({
          ok: true,
          status: 200,
          json: () => Promise.resolve({ configured: true, destinations: [DESTINATION] }),
        });
      }
      return Promise.resolve({
        ok: putOk,
        status: putOk ? 200 : 500,
        json: () => Promise.resolve(putOk ? DESTINATION : { error: "config file is read-only" }),
      });
    },
    confirm: () => true,
  };
  return {
    msg,
    calls,
    api: loadDashboardModule<AuditExportApi>("dashboard-audit-export.js", ["dashboard-escape.js"], globals),
  };
}

const settle = () => new Promise((r) => setTimeout(r, 10));

describe("switching an audit destination off", () => {
  it("re-reads the real state and names the error when the write fails", async () => {
    const { api, msg, calls } = harness(false);
    api.loadAuditExport();
    await settle();
    calls.length = 0;

    api.axToggle("d1", false);
    await settle();

    expect(calls[0]).toMatchObject({ url: "/audit-export/d1", method: "PUT" });
    // The list is re-read, so the checkbox goes back to what the server actually holds.
    expect(calls.some((c) => c.method === "GET" && c.url === "/audit-export")).toBe(true);
    // And the operator is told, rather than being left with a box that says "off".
    expect(msg.textContent).toMatch(/read-only|could not/i);
  });

  it("still refreshes the list when the write succeeds", async () => {
    const { api, calls } = harness(true);
    api.loadAuditExport();
    await settle();
    calls.length = 0;

    api.axToggle("d1", false);
    await settle();

    expect(calls.filter((c) => c.method === "GET" && c.url === "/audit-export")).toHaveLength(1);
  });

  it("does nothing for an id it has never seen", async () => {
    const { api, calls } = harness(true);
    api.loadAuditExport();
    await settle();
    calls.length = 0;
    api.axToggle("unknown", false);
    await settle();
    expect(calls).toEqual([]);
  });
});
