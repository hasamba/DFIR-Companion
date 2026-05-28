import { describe, it, expect, beforeEach } from "vitest";
import { mkdtemp, readFile, stat } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { CaseStore } from "../../src/storage/caseStore.js";

let root: string;
beforeEach(async () => {
  root = await mkdtemp(join(tmpdir(), "dfir-cases-"));
});

describe("CaseStore.createCase", () => {
  it("creates the folder layout and writes case.json", async () => {
    const store = new CaseStore(root);
    const meta = await store.createCase({
      caseId: "case-001",
      name: "Test Incident",
      investigator: "yaniv",
      aiProvider: null,
    });

    expect(meta.caseId).toBe("case-001");
    expect(meta.createdAt).toMatch(/^\d{4}-\d{2}-\d{2}T/);

    for (const sub of ["screenshots", "metadata", "state", "reports"]) {
      const s = await stat(join(root, "case-001", sub));
      expect(s.isDirectory()).toBe(true);
    }

    const written = JSON.parse(
      await readFile(join(root, "case-001", "case.json"), "utf8"),
    );
    expect(written.name).toBe("Test Incident");
    expect(written.investigator).toBe("yaniv");
  });

  it("exposes correct paths", () => {
    const store = new CaseStore(root);
    expect(store.screenshotsDir("case-001")).toBe(join(root, "case-001", "screenshots"));
    expect(store.capturesLogPath("case-001")).toBe(join(root, "case-001", "metadata", "captures.jsonl"));
  });
});
