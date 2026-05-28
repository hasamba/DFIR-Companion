import { describe, it, expect, beforeEach } from "vitest";
import { mkdtemp, readFile, stat } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { CaseStore } from "../../src/storage/caseStore.js";
import type { CaptureMetadata } from "../../src/types.js";

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

describe("CaseStore evidence writes", () => {
  it("saves a screenshot to the screenshots dir", async () => {
    const store = new CaseStore(root);
    await store.createCase({ caseId: "c1", name: "n", investigator: "i", aiProvider: null });

    await store.saveScreenshot("c1", "000001_t.webp", Buffer.from([1, 2, 3, 4]));
    const written = await readFile(join(root, "c1", "screenshots", "000001_t.webp"));
    expect(Array.from(written)).toEqual([1, 2, 3, 4]);
  });

  it("appendCapture writes one JSONL line per call (append-only)", async () => {
    const store = new CaseStore(root);
    await store.createCase({ caseId: "c2", name: "n", investigator: "i", aiProvider: null });

    const base: Omit<CaptureMetadata, "sequenceNumber"> = {
      caseId: "c2",
      timestamp: "2026-05-28T10:00:00.000Z",
      url: "https://velociraptor.local/hunts",
      tabTitle: "Hunts",
      triggerType: "timer",
      perceptualHash: "ffffffffffffffff",
      isDuplicate: false,
      screenshotFile: "000001_t.webp",
    };

    await store.appendCapture("c2", { ...base, sequenceNumber: 1 });
    await store.appendCapture("c2", { ...base, sequenceNumber: 2, screenshotFile: "000002_t.webp" });

    const log = await readFile(store.capturesLogPath("c2"), "utf8");
    const lines = log.trim().split("\n");
    expect(lines).toHaveLength(2);
    expect(JSON.parse(lines[0]).sequenceNumber).toBe(1);
    expect(JSON.parse(lines[1]).screenshotFile).toBe("000002_t.webp");
  });

  it("nextSequenceNumber returns 1 for a new case, then increments with the log", async () => {
    const store = new CaseStore(root);
    await store.createCase({ caseId: "c3", name: "n", investigator: "i", aiProvider: null });

    expect(await store.nextSequenceNumber("c3")).toBe(1);
    await store.appendCapture("c3", {
      caseId: "c3", timestamp: "2026-05-28T10:00:00.000Z", url: "u", tabTitle: "t",
      triggerType: "timer", perceptualHash: "0000000000000000", isDuplicate: false,
      screenshotFile: "000001_t.webp", sequenceNumber: 1,
    });
    expect(await store.nextSequenceNumber("c3")).toBe(2);
  });
});
