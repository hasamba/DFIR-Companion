import { describe, it, expect, beforeEach } from "vitest";
import { mkdtemp, readFile, stat, mkdir, rename, writeFile } from "node:fs/promises";
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
      contentHash: "ffffffffffffffff",
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
      triggerType: "timer", contentHash: "0000000000000000", isDuplicate: false,
      screenshotFile: "000001_t.webp", sequenceNumber: 1,
    });
    expect(await store.nextSequenceNumber("c3")).toBe(2);
  });
});

describe("CaseStore OCR index (#176)", () => {
  const entry = (file: string, text: string) => ({
    screenshotFile: file,
    text,
    ocrAt: "2026-06-29T00:00:00.000Z",
    wordCount: text.split(" ").length,
  });

  it("returns {} for a case with no index yet", async () => {
    const store = new CaseStore(root);
    await store.createCase({ caseId: "o1", name: "n", investigator: "i", aiProvider: null });
    expect(await store.loadOcrIndex("o1")).toEqual({});
  });

  it("putOcrEntry persists and round-trips, keyed by screenshotFile", async () => {
    const store = new CaseStore(root);
    await store.createCase({ caseId: "o2", name: "n", investigator: "i", aiProvider: null });

    await store.putOcrEntry("o2", entry("000001_t.webp", "mimikatz on host"));
    await store.putOcrEntry("o2", entry("000002_t.webp", "clean console"));

    const idx = await store.loadOcrIndex("o2");
    expect(Object.keys(idx)).toEqual(["000001_t.webp", "000002_t.webp"]);
    expect(idx["000001_t.webp"].text).toBe("mimikatz on host");

    // on-disk file is at metadata/ocr.json
    const written = JSON.parse(await readFile(store.ocrIndexPath("o2"), "utf8"));
    expect(written["000002_t.webp"].wordCount).toBe(2);
  });

  it("re-OCR of the same screenshot replaces the row (no duplicate)", async () => {
    const store = new CaseStore(root);
    await store.createCase({ caseId: "o3", name: "n", investigator: "i", aiProvider: null });

    await store.putOcrEntry("o3", entry("000001_t.webp", "old text"));
    await store.putOcrEntry("o3", entry("000001_t.webp", "new text"));

    const idx = await store.loadOcrIndex("o3");
    expect(Object.keys(idx)).toHaveLength(1);
    expect(idx["000001_t.webp"].text).toBe("new text");
  });

  it("preserves every entry when OCR workers write the same case concurrently", async () => {
    const store = new CaseStore(root);
    await store.createCase({ caseId: "o4", name: "n", investigator: "i", aiProvider: null });

    await Promise.all(
      Array.from({ length: 7 }, (_, i) =>
        store.putOcrEntry("o4", entry(`${String(i + 1).padStart(6, "0")}_t.webp`, `text ${i}`)),
      ),
    );

    const idx = await store.loadOcrIndex("o4");
    expect(Object.keys(idx)).toHaveLength(7);
  });
});

describe("CaseStore.caseDir archive fallback (case archive lifecycle)", () => {
  it("resolves to the active root when the case lives there", async () => {
    const store = new CaseStore(root);
    await store.createCase({ caseId: "arch-1", name: "n", investigator: "i", aiProvider: null });
    expect(store.caseDir("arch-1")).toBe(join(root, "arch-1"));
  });

  it("resolves to _archived/<caseId> once the folder has been moved there", async () => {
    const store = new CaseStore(root);
    await store.createCase({ caseId: "arch-2", name: "n", investigator: "i", aiProvider: null });
    await mkdir(join(root, "_archived"), { recursive: true });
    await rename(join(root, "arch-2"), join(root, "_archived", "arch-2"));
    expect(store.caseDir("arch-2")).toBe(join(root, "_archived", "arch-2"));
  });

  it("falls back to the active root for a case that doesn't exist yet", () => {
    const store = new CaseStore(root);
    expect(store.caseDir("brand-new")).toBe(join(root, "brand-new"));
  });
});

describe("CaseStore archive/restore folder moves", () => {
  it("archiveCaseFolder moves the case directory under _archived/", async () => {
    const store = new CaseStore(root);
    await store.createCase({ caseId: "af-1", name: "n", investigator: "i", aiProvider: null });
    await store.archiveCaseFolder("af-1");

    const moved = await stat(join(root, "_archived", "af-1", "case.json"));
    expect(moved.isFile()).toBe(true);
    await expect(stat(join(root, "af-1"))).rejects.toThrow();
  });

  it("restoreCaseFolder moves it back to the active root", async () => {
    const store = new CaseStore(root);
    await store.createCase({ caseId: "af-2", name: "n", investigator: "i", aiProvider: null });
    await store.archiveCaseFolder("af-2");
    await store.restoreCaseFolder("af-2");

    const back = await stat(join(root, "af-2", "case.json"));
    expect(back.isFile()).toBe(true);
    await expect(stat(join(root, "_archived", "af-2"))).rejects.toThrow();
  });

  it("listCases includes archived cases alongside active ones", async () => {
    const store = new CaseStore(root);
    await store.createCase({ caseId: "af-3", name: "Active", investigator: "i", aiProvider: null });
    await store.createCase({ caseId: "af-4", name: "Archived", investigator: "i", aiProvider: null });
    await store.archiveCaseFolder("af-4");

    const cases = await store.listCases();
    expect(cases.map((c) => c.caseId).sort()).toEqual(["af-3", "af-4"]);
  });

  it("caseExists returns true for an archived case, so callers can 409 before overwriting it", async () => {
    const store = new CaseStore(root);
    await store.createCase({ caseId: "af-5", name: "n", investigator: "i", aiProvider: null });
    await store.archiveCaseFolder("af-5");

    expect(await store.caseExists("af-5")).toBe(true);
  });

  it("archiveCaseFolder rejects when the case doesn't exist in the active root", async () => {
    const store = new CaseStore(root);
    await expect(store.archiveCaseFolder("never-created")).rejects.toThrow();
  });

  it("restoreCaseFolder rejects when the case isn't currently archived", async () => {
    const store = new CaseStore(root);
    await store.createCase({ caseId: "af-6", name: "n", investigator: "i", aiProvider: null });
    await expect(store.restoreCaseFolder("af-6")).rejects.toThrow();
  });
});

describe("CaseStore.deleteCaseFolder", () => {
  it("deletes an active case's folder entirely", async () => {
    const store = new CaseStore(root);
    await store.createCase({ caseId: "del-1", name: "n", investigator: "i", aiProvider: null });
    await store.deleteCaseFolder("del-1");
    await expect(stat(join(root, "del-1"))).rejects.toThrow();
  });

  it("deletes an archived case's folder (under _archived/)", async () => {
    const store = new CaseStore(root);
    await store.createCase({ caseId: "del-2", name: "n", investigator: "i", aiProvider: null });
    await store.archiveCaseFolder("del-2");
    await store.deleteCaseFolder("del-2");
    await expect(stat(join(root, "_archived", "del-2"))).rejects.toThrow();
  });

  it("rejects when the case doesn't exist", async () => {
    const store = new CaseStore(root);
    await expect(store.deleteCaseFolder("never-created")).rejects.toThrow();
  });

  it("refuses to delete a directory that isn't actually a case (no case.json)", async () => {
    const store = new CaseStore(root);
    await mkdir(join(root, "not-a-case"), { recursive: true });
    await writeFile(join(root, "not-a-case", "some-file.txt"), "hello", "utf8");
    await expect(store.deleteCaseFolder("not-a-case")).rejects.toThrow();
    // confirm it's genuinely still there — nothing was deleted
    const s = await stat(join(root, "not-a-case", "some-file.txt"));
    expect(s.isFile()).toBe(true);
  });
});

describe("CaseStore.nextImportSeq", () => {
  it("hands out a distinct sequence to each concurrent caller", async () => {
    // nextImportSeq derives the next number by COUNTING the imports log, and callers append to that
    // log only later (after writing the blob). Concurrent imports therefore all read the same count
    // and get the SAME seq — they overwrite each other's stored evidence file and hand the importer
    // the same idPrefix, so their events collide by id and the state merge dedups all but one away.
    const store = new CaseStore(root);
    await store.createCase({ caseId: "seq-1", name: "n", investigator: "i", aiProvider: null });
    const seqs = await Promise.all(Array.from({ length: 12 }, () => store.nextImportSeq("seq-1")));
    expect(new Set(seqs).size).toBe(12);
    expect([...seqs].sort((a, b) => a - b)).toEqual([1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12]);
  });

  it("resumes from the on-disk log for a case with existing imports", async () => {
    const store = new CaseStore(root);
    await store.createCase({ caseId: "seq-2", name: "n", investigator: "i", aiProvider: null });
    await store.appendImport("seq-2", {
      caseId: "seq-2", sequenceNumber: 1, importedAt: new Date().toISOString(),
      filename: "0001_a.log", originalName: "a.log", rows: 0, bytes: 1,
    });
    // A fresh store (server restart) must pick up where the log left off, not restart at 1.
    expect(await new CaseStore(root).nextImportSeq("seq-2")).toBe(2);
  });
});
