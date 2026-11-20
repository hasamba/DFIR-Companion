import { mkdtemp } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { describe, expect, it } from "vitest";
import { WatsonChatStore } from "../../src/analysis/ai/watson/chatStore.js";
import { recoverWatsonLaunches } from "../../src/composition/watsonVeloRecovery.js";
import { CaseStore } from "../../src/storage/caseStore.js";

// #2774: a Watson reaction scheduled before a restart is re-armed by the startup recovery loop.

describe("recoverWatsonLaunches re-arms pending reactions (#2774)", () => {
  it("asks the reactor to resume every listed case", async () => {
    const store = new CaseStore(await mkdtemp(join(tmpdir(), "dfir-watson-react-rec-")));
    await store.createCase({ caseId: "c1", name: "n", investigator: "i", aiProvider: null });
    await store.createCase({ caseId: "c2", name: "n", investigator: "i", aiProvider: null });
    const chatStore = new WatsonChatStore(store);
    const resumed: string[] = [];
    const reactor = { resume: async (caseId: string) => void resumed.push(caseId) };
    await recoverWatsonLaunches(store, chatStore, () => undefined, { watsonReactor: reactor });
    expect(resumed.sort()).toEqual(["c1", "c2"]);
  });

  it("a case whose resume fails is logged and the next case still resumes", async () => {
    const store = new CaseStore(await mkdtemp(join(tmpdir(), "dfir-watson-react-rec-")));
    await store.createCase({ caseId: "c1", name: "n", investigator: "i", aiProvider: null });
    await store.createCase({ caseId: "c2", name: "n", investigator: "i", aiProvider: null });
    const lines: string[] = [];
    const resumed: string[] = [];
    const reactor = {
      resume: async (caseId: string) => {
        if (caseId === "c1") throw new Error("boom");
        resumed.push(caseId);
      },
    };
    await recoverWatsonLaunches(store, new WatsonChatStore(store), (l) => lines.push(l), {
      watsonReactor: reactor,
    });
    expect(resumed).toEqual(["c2"]);
    expect(lines.some((l) => l.includes("c1") && l.includes("boom"))).toBe(true);
  });
});
