import { mkdir, mkdtemp, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterEach, describe, expect, it } from "vitest";
import {
  FOLDERS_KEPT_MOVING,
  MAX_ATTEMPTS,
  findLinkedCases,
  listCaseFolders,
  type CaseFolders,
} from "../../src/analysis/clientProfileLinks.js";
import type { FolderMoveState } from "../../src/storage/caseFolderMoves.js";
import { CaseStore } from "../../src/storage/caseStore.js";

// #2945: the client delete check reads the case store's move counter before and after each look.
// A case that moved at all while it looked — even twice, ending where it started — means look again.

const dirs: string[] = [];
const tempDir = async (prefix: string) => {
  const d = await mkdtemp(join(tmpdir(), prefix));
  dirs.push(d);
  return d;
};
afterEach(async () => {
  for (const d of dirs.splice(0))
    await rm(d, { recursive: true, force: true, maxRetries: 5, retryDelay: 100 });
});

const LINK = JSON.stringify({ clientId: "client-a", linkedAt: "", linkedBy: "" });

async function archivedCase(root: string, id: string, name: string) {
  await mkdir(join(root, "_archived", id, "state"), { recursive: true });
  await writeFile(join(root, "_archived", id, "case.json"), JSON.stringify({ name }));
  await writeFile(join(root, "_archived", id, "state", "hunt-client.json"), LINK);
}

/** Case folders backed by a scripted move counter: each state() call returns the next entry. */
function scripted(root: string, states: FolderMoveState[]): CaseFolders {
  let i = 0;
  return {
    casesRoot: root,
    folderMoves: { state: () => states[Math.min(i++, states.length - 1)] },
    getCaseMeta: async (id) => ({ name: id }),
  };
}

describe("findLinkedCases reads the move counter (#2945)", () => {
  it("looks again when the case moved twice inside the first look and was missed", async () => {
    const root = await tempDir("dfir-2945-double-");
    await archivedCase(root, "c-moving", "Moving");
    let lists = 0;
    // First look: restored after the active read, archived again before the archived read — hidden.
    const list = async (dir: string, skip: string | null) => (++lists <= 2 ? [] : listCaseFolders(dir, skip));
    const folders = scripted(root, [
      { started: 4, inFlight: 0 },
      { started: 6, inFlight: 0 }, // two moves started and finished during the look
      { started: 6, inFlight: 0 },
      { started: 6, inFlight: 0 },
    ]);
    expect(await findLinkedCases(folders, "client-a", list)).toEqual([
      { caseId: "c-moving", name: "c-moving" },
    ]);
    expect(lists).toBe(4);
  });

  it("looks again when a move was in flight at the start or at the end", async () => {
    const root = await tempDir("dfir-2945-inflight-");
    await archivedCase(root, "c-1", "One");
    let lists = 0;
    const list = async (dir: string, skip: string | null) => {
      lists++;
      return listCaseFolders(dir, skip);
    };
    const folders = scripted(root, [
      { started: 1, inFlight: 1 },
      { started: 1, inFlight: 1 }, // attempt 1: in flight throughout
      { started: 1, inFlight: 0 },
      { started: 2, inFlight: 1 }, // attempt 2: a move started and is still running at the end
      { started: 2, inFlight: 0 },
      { started: 2, inFlight: 0 }, // attempt 3: still
    ]);
    expect(await findLinkedCases(folders, "client-a", list)).toEqual([{ caseId: "c-1", name: "c-1" }]);
    expect(lists).toBe(6); // two folder reads per look, three looks
  });

  it("refuses (throws) when the folders never hold still", async () => {
    const root = await tempDir("dfir-2945-churn-");
    let n = 0;
    const folders: CaseFolders = {
      casesRoot: root,
      folderMoves: { state: () => ({ started: n++, inFlight: 0 }) },
      getCaseMeta: async () => null,
    };
    await expect(findLinkedCases(folders, "client-a")).rejects.toThrow(FOLDERS_KEPT_MOVING);
    expect(n).toBe(MAX_ATTEMPTS * 2);
  });

  it("with a real case store: a case archived, restored and archived again mid-look is still found", async () => {
    const root = await tempDir("dfir-2945-store-");
    const store = new CaseStore(root);
    await store.createCase({ caseId: "c1", name: "Linked", investigator: "i", aiProvider: null });
    await mkdir(join(root, "c1", "state"), { recursive: true });
    await writeFile(join(root, "c1", "state", "hunt-client.json"), LINK);
    await store.archiveCaseFolder("c1");
    let lists = 0;
    const list = async (dir: string, skip: string | null) => {
      const names = await listCaseFolders(dir, skip);
      lists++;
      // The active read ran while c1 was archived; now restore it. The archived read then runs while
      // it is active; now archive it again. Neither read of this look sees c1.
      if (lists === 1) await store.restoreCaseFolder("c1");
      if (lists === 2) await store.archiveCaseFolder("c1");
      return names;
    };
    expect(await findLinkedCases(store, "client-a", list)).toEqual([{ caseId: "c1", name: "Linked" }]);
    expect(lists).toBe(4);
  });
});
