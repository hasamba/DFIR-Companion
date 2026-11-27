import { describe, expect, it } from "vitest";
import type { VeloTriageApi } from "./dashboardApi.js";
import { loadDashboardModule } from "../helpers/dashboardModule.js";

// public/js/dashboard-velo-triage.js — who may write the shared client inventory, and in what order.
//
// #2970: the bundle run form refreshes the client list when it opens and hands the fresh inventory
// to the shared cache. A cached read of the OLD inventory that was already in flight must not land on
// top of it afterwards, or the next run form, the Settings count and the live-monitor host list all
// fall back to the stale snapshot the refresh was meant to replace.
describe("acceptVeloClientInventory (#2970)", () => {
  it("drops a cached client read that lands after a fresher inventory was accepted", async () => {
    let releaseGet: () => void = () => {};
    const getGate = new Promise<void>((r) => (releaseGet = r));
    const triage = loadDashboardModule<VeloTriageApi>(
      "dashboard-velo-triage.js",
      ["dashboard-escape.js", "dashboard-velo-case.js", "dashboard-velo-clients.js"],
      {
        document: { getElementById: () => null },
        activeCaseId: "case-a",
        veloEnabled: true,
        fetch: async () => {
          await getGate;
          return {
            ok: true,
            json: async () => ({ updatedAt: "old", clients: [{ clientId: "C.1", labels: ["lab-old"] }] }),
          };
        },
      },
    );
    triage.loadVeloClients(); // the cached GET starts and stalls
    triage.acceptVeloClientInventory({
      updatedAt: "new",
      clients: [{ clientId: "C.1", labels: ["lab-new"] }],
    });
    releaseGet();
    await new Promise((r) => setTimeout(r, 0));
    await new Promise((r) => setTimeout(r, 0));
    expect(triage.veloClientsList()).toEqual([{ clientId: "C.1", labels: ["lab-new"] }]);
  });
});
