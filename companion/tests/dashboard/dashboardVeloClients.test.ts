import { describe, expect, it } from "vitest";
import type { VeloClientsApi } from "./dashboardApi.js";
import { loadDashboardModule } from "../helpers/dashboardModule.js";

// public/js/dashboard-velo-clients.js — what the client lists say about the clients they do NOT show.
//
// #2887: the server reads at most 100,000 enrolled clients. A list cut there used to read as the whole
// fleet; the inventory now carries `truncated` and both lists say so. No search by id or host exists
// for those lists, so the notice must not promise one.
// The AI Agent picker's 2,000-row cap (the sibling defect) hid every endpoint past the 2,000th, and its
// filter only searched the rows it had drawn — so an endpoint past the cap could never be found.
const vc = loadDashboardModule<VeloClientsApi>("dashboard-velo-clients.js", []);

const fleet = (n: number) =>
  Array.from({ length: n }, (_, i) => ({ clientId: `C.c${i}`, hostname: `ws-${i}`, fqdn: "" }));

describe("veloClientsCutNotice", () => {
  it("is the fixed sentence for a cut list, and nothing otherwise", () => {
    expect(vc.veloClientsCutNotice({ truncated: true })).toBe(
      "Showing the first 100,000 clients the server returned — a client past that is not listed here; run a fleet hunt or use the Velociraptor GUI.",
    );
    expect(vc.veloClientsCutNotice({})).toBe("");
    expect(vc.veloClientsCutNotice({ truncated: "yes" })).toBe("");
    expect(vc.veloClientsCutNotice(null)).toBe("");
  });

  it("never promises a search", () => {
    expect(vc.veloClientsCutNotice({ truncated: true })).not.toMatch(/search/i);
  });
});

describe("veloPickerRows", () => {
  it("draws at most the cap, and counts the whole fleet", () => {
    const r = vc.veloPickerRows(fleet(2500), "");
    expect(r.rows).toHaveLength(2000);
    expect(r.matched).toBe(2500);
    expect(r.total).toBe(2500);
  });

  it("filters the FULL list, so an endpoint past the cap can be found", () => {
    const r = vc.veloPickerRows(fleet(2500), "WS-2400");
    expect(r.rows.map((c) => c.clientId)).toEqual(["C.c2400"]);
    expect(r.matched).toBe(1);
    expect(r.total).toBe(2500);
  });

  it("matches on the client id and the FQDN too", () => {
    const clients = [
      { clientId: "C.abc", hostname: "", fqdn: "box.lab.test" },
      { clientId: "C.def", hostname: "other", fqdn: "" },
    ];
    expect(vc.veloPickerRows(clients, "lab.test").rows.map((c) => c.clientId)).toEqual(["C.abc"]);
    expect(vc.veloPickerRows(clients, "c.def").rows.map((c) => c.clientId)).toEqual(["C.def"]);
  });

  it("treats a missing list as empty", () => {
    expect(vc.veloPickerRows(null, "")).toEqual({ rows: [], matched: 0, total: 0 });
  });
});

describe("veloPickerNote", () => {
  it("says nothing when every row is drawn", () => {
    expect(vc.veloPickerNote(vc.veloPickerRows(fleet(10), ""))).toBe("");
  });

  it("says how many are drawn and to type to filter when the cap hides some", () => {
    expect(vc.veloPickerNote(vc.veloPickerRows(fleet(2500), ""))).toBe(
      "Showing 2,000 of 2,500 endpoints — type to filter",
    );
  });

  it("counts the matches, not the fleet, while a filter is typed", () => {
    expect(vc.veloPickerNote(vc.veloPickerRows(fleet(30000), "ws-1"))).toBe(
      "Showing 2,000 of 11,111 endpoints — type to filter",
    );
  });
});

describe("veloPickerLabel", () => {
  it("names the endpoint by host, then FQDN, then id, with the id beside it", () => {
    expect(vc.veloPickerLabel({ clientId: "C.a", hostname: "ws", fqdn: "ws.lab" })).toBe("ws (C.a)");
    expect(vc.veloPickerLabel({ clientId: "C.a", hostname: "", fqdn: "ws.lab" })).toBe("ws.lab (C.a)");
    expect(vc.veloPickerLabel({ clientId: "C.a" })).toBe("C.a (C.a)");
  });
});
