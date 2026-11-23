import { describe, it, expect } from "vitest";
import { mkdtemp, rm } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { CaseStore } from "../../src/storage/caseStore.js";
import { VelociraptorClientStore } from "../../src/analysis/velociraptorClientStore.js";
import { UpdateCheckStore } from "../../src/analysis/updateCheckStore.js";
import { startPostListenTasks } from "../../src/composition/maintenanceTasks.js";
import { USED_IDS_FILENAME } from "../../src/storage/usedCaseIds.js";
import { stubServerClients } from "../helpers/serverClientsStub.js";
import { pollFor, pollBudget } from "../helpers/poll.js";

// #2858: a case created before ids were recorded at create has no ledger entry, so removing its
// folder by hand would still free its number. The restart records every case already on disk.

describe("startPostListenTasks — used case id backfill", () => {
  it("records every case already on disk once the server is up", async () => {
    const root = await mkdtemp(join(tmpdir(), "dfir-used-ids-"));
    const store = new CaseStore(root);
    await store.createCase({ caseId: "INC-2026-007", name: "x", investigator: "a", aiProvider: null });
    await rm(join(root, USED_IDS_FILENAME)); // as on an install from before #2858
    expect(await store.listUsedCaseIds()).toEqual([]);

    startPostListenTasks({
      store,
      demoMode: false,
      serverSets: { list: () => [] },
      serverClients: stubServerClients({}),
      clientInventoryFor: () => new VelociraptorClientStore(join(root, "velo-clients.json")),
      updateCheckStore: new UpdateCheckStore(join(root, "update-check.json")),
      updateRepo: "hasamba/DFIR-Companion",
    });
    // Polled, not slept: the backfill is fire-and-forget disk work, and its timing varies by platform.
    const used = await pollFor(
      "the startup backfill to record the existing case",
      async () => {
        const ids = await store.listUsedCaseIds();
        return ids.length > 0 ? ids : undefined;
      },
      { timeoutMs: pollBudget(5_000) },
    );
    expect(used).toEqual(["INC-2026-007"]);
  });
});
