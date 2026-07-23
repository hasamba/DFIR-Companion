import { describe, it, expect, beforeEach } from "vitest";
import { mkdtemp, readdir, readFile, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { CaseStore } from "../../src/storage/caseStore.js";
import { ingestCapture } from "../../src/ingest/captureIngest.js";

// Capture and import sequence numbers were derived from "current audit-log length + 1" with no
// reservation, so two ingestions racing for the same case both picked the same number. When the
// derived filenames also matched, one evidence file silently overwrote the other while both audit
// records were appended — evidence destroyed, provenance broken (#214).
let store: CaseStore;
const CASE = "c1";
const CONCURRENT = 10;

beforeEach(async () => {
  store = new CaseStore(await mkdtemp(join(tmpdir(), "dfir-seq-")));
  await store.createCase({ caseId: CASE, name: "n", investigator: "i", aiProvider: null });
});

// A distinct 1x1-ish payload per index, so every capture has different bytes (and a different hash).
const imageFor = (i: number): string => Buffer.from(`capture-payload-${i}`).toString("base64");

describe("capture sequence allocation (#214)", () => {
  it("hands out a unique sequence number to every concurrent capture", async () => {
    const seqs = await Promise.all(
      Array.from({ length: CONCURRENT }, () => store.nextSequenceNumber(CASE)),
    );
    expect(new Set(seqs).size).toBe(CONCURRENT);
  });

  it("never overwrites one capture's evidence with another's", async () => {
    // Identical timestamp AND title: the rest of the filename is identical, so a duplicated
    // sequence number is the only thing that could make two captures collide on disk.
    const results = await Promise.all(
      Array.from({ length: CONCURRENT }, (_, i) =>
        ingestCapture(
          store,
          {
            caseId: CASE,
            timestamp: "2026-05-22T14:00:00.000Z",
            url: "https://example.test/page",
            tabTitle: "same title",
            triggerType: "timer",
            imageBase64: imageFor(i),
          },
          false, // dedup off — every capture is distinct evidence here
        ),
      ),
    );

    // Unique sequence numbers and unique filenames.
    expect(new Set(results.map((r) => r.sequenceNumber)).size).toBe(CONCURRENT);
    expect(new Set(results.map((r) => r.screenshotFile)).size).toBe(CONCURRENT);

    // Every file actually exists on disk, and holds ITS OWN bytes (not another capture's).
    const files = await readdir(store.screenshotsDir(CASE));
    expect(files).toHaveLength(CONCURRENT);
    for (let i = 0; i < CONCURRENT; i++) {
      const bytes = await readFile(join(store.screenshotsDir(CASE), results[i].screenshotFile!));
      expect(bytes.toString("utf8"), `capture ${i} content`).toBe(`capture-payload-${i}`);
    }

    // And the audit log has one complete line per capture.
    const log = await readFile(join(store.metadataDir(CASE), "captures.jsonl"), "utf8");
    const lines = log.split("\n").filter((l) => l.trim());
    expect(lines).toHaveLength(CONCURRENT);
    expect(new Set(lines.map((l) => JSON.parse(l).sequenceNumber)).size).toBe(CONCURRENT);
  });
});

describe("import sequence allocation (#214)", () => {
  it("hands out a unique sequence number to every concurrent import", async () => {
    const seqs = await Promise.all(Array.from({ length: CONCURRENT }, () => store.nextImportSeq(CASE)));
    expect(new Set(seqs).size).toBe(CONCURRENT);
  });

  it("keeps numbering monotonic across a reserve-then-append cycle", async () => {
    // A reserved-but-not-yet-appended number must not be handed out again, and once the audit
    // line lands the next number must still move forward.
    const first = await store.nextImportSeq(CASE);
    const second = await store.nextImportSeq(CASE);
    expect(second).toBeGreaterThan(first);

    await store.appendImport(CASE, {
      caseId: CASE, sequenceNumber: first, importedAt: new Date().toISOString(),
      filename: "0001_a.csv", originalName: "a.csv", rows: 0, bytes: 0,
    });
    const third = await store.nextImportSeq(CASE);
    expect(third).toBeGreaterThan(second);
  });

  it("refuses to silently overwrite an evidence file that already exists", async () => {
    // Defence in depth beneath the sequence fix: even if a name were somehow reused, the write
    // must fail loudly rather than destroy the earlier evidence.
    await store.saveScreenshot(CASE, "000001_dup.webp", Buffer.from("original evidence"));
    await expect(store.saveScreenshot(CASE, "000001_dup.webp", Buffer.from("overwrite"))).rejects.toThrow();
    const bytes = await readFile(join(store.screenshotsDir(CASE), "000001_dup.webp"));
    expect(bytes.toString("utf8")).toBe("original evidence");
  });
});
