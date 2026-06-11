import { describe, it, expect, beforeEach } from "vitest";
import { mkdtemp } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { CaseStore } from "../../src/storage/caseStore.js";
import { PlaybookControlStore } from "../../src/analysis/playbookControl.js";

describe("PlaybookControlStore", () => {
  let store: PlaybookControlStore;
  beforeEach(async () => {
    const root = await mkdtemp(join(tmpdir(), "dfir-playbook-ctrl-"));
    const cases = new CaseStore(root);
    await cases.createCase({ caseId: "c1", name: "n", investigator: "i", aiProvider: null });
    store = new PlaybookControlStore(cases);
  });

  it("defaults to templates OFF when no file exists", async () => {
    expect(await store.load("c1")).toEqual({ useTemplates: false });
  });

  it("persists and reloads the toggle", async () => {
    const set = await store.set("c1", { useTemplates: true });
    expect(set).toEqual({ useTemplates: true });
    expect(await store.load("c1")).toEqual({ useTemplates: true });
  });

  it("ignores a non-boolean patch value", async () => {
    await store.set("c1", { useTemplates: true });
    const after = await store.set("c1", { useTemplates: "yes" as never });
    expect(after.useTemplates).toBe(true);
  });
});
