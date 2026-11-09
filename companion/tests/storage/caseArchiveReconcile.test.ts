import { describe, it, expect } from "vitest";
import { mkdtemp, mkdir, rename, readFile, writeFile } from "node:fs/promises";
import { existsSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { CaseStore } from "../../src/storage/caseStore.js";
import { reconcileArchiveLabels } from "../../src/storage/caseArchiveReconcile.js";

// #2437: archive and restore move the folder and then relabel case.json. A crash between the two
// steps leaves them disagreeing. At startup the companion reconciles both cases to "archived".

async function makeStore() {
  const root = await mkdtemp(join(tmpdir(), "dfir-2437-heal-"));
  const store = new CaseStore(root);
  await store.createCase({ caseId: "c1", name: "n", investigator: "i", aiProvider: null });
  return { root, store };
}

const failOnError = (id: string, err: Error) => {
  throw new Error(`reconcile failed for ${id}: ${err.message}`);
};

const statusOf = async (path: string) =>
  (JSON.parse(await readFile(path, "utf8")) as { status?: string }).status;

async function setStatus(path: string, status: string) {
  const meta = JSON.parse(await readFile(path, "utf8")) as Record<string, unknown>;
  await writeFile(path, JSON.stringify({ ...meta, status }));
}

describe("startup reconciles a case whose folder and status disagree (#2437)", () => {
  it("relabels a folder under _archived/ that still says closed", async () => {
    const { root, store } = await makeStore();
    await store.setCaseStatus("c1", "closed");
    await mkdir(join(root, "_archived"), { recursive: true });
    await rename(join(root, "c1"), join(root, "_archived", "c1")); // the move landed, the relabel did not
    expect(await reconcileArchiveLabels(store, failOnError)).toBe(1);
    expect(await statusOf(join(root, "_archived", "c1", "case.json"))).toBe("archived");
  });

  it("moves an active folder labelled archived back under _archived/, so restore works again", async () => {
    const { root, store } = await makeStore();
    await setStatus(join(root, "c1", "case.json"), "archived"); // restore moved it, then crashed
    expect(await reconcileArchiveLabels(store, failOnError)).toBe(1);
    expect(existsSync(join(root, "c1"))).toBe(false);
    expect(await statusOf(join(root, "_archived", "c1", "case.json"))).toBe("archived");
    expect((await store.restoreCaseFolder("c1", "closed"))?.status).toBe("closed");
  });

  it("leaves agreeing cases alone", async () => {
    const { root, store } = await makeStore();
    await store.createCase({ caseId: "c2", name: "n", investigator: "i", aiProvider: null });
    await store.setCaseStatus("c2", "closed");
    await store.archiveCaseFolder("c2", "archived");
    expect(await reconcileArchiveLabels(store, failOnError)).toBe(0);
    expect(await statusOf(join(root, "c1", "case.json"))).not.toBe("archived");
    expect(await statusOf(join(root, "_archived", "c2", "case.json"))).toBe("archived");
  });
});
