import { describe, expect, it } from "vitest";
import { mkdtemp, readFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { CaseStore } from "../../src/storage/caseStore.js";
import {
  CloudCoverageStore,
  UPLOADS_TRACKED_PER_CASE_MAX,
  type CloudCoverageDraft,
} from "../../src/analysis/cloudCoverage.js";

// #2540 — a drop-folder batch folds coverage once: recordMany must leave exactly what one record()
// per file leaves, eviction past the tracked-upload cap included. (foldMany is the pure fold reduced
// in order; tests/composition/importIngestBatch.test.ts compares the weakness file on real records.)

async function stores() {
  const root = await mkdtemp(join(tmpdir(), "dfir-foldmany-"));
  const store = new CaseStore(root);
  await store.createCase({ caseId: "c1", name: "n", investigator: "i", aiProvider: null });
  return { store, coverage: new CloudCoverageStore(store) };
}

const draft = (uploadId: string, category: string): CloudCoverageDraft => ({
  provider: "aws",
  scope: { kind: "account", value: "123456789012" },
  uploadId,
  recordCount: 1,
  first: "2021-07-29T13:00:00Z",
  last: "2021-07-29T13:00:00Z",
  categories: [{ name: category, count: 1 }],
});

const at = (i: number): string => new Date(Date.UTC(2026, 10, 11, 0, 0, i)).toISOString();

describe("CloudCoverageStore.recordMany ≡ one record() per upload (#2540)", () => {
  it("matches across the eviction cap, a re-imported upload and an evicted upload that comes back", async () => {
    const n = UPLOADS_TRACKED_PER_CASE_MAX + 5;
    const uploads = Array.from({ length: n }, (_, i) => ({ drafts: [draft(`u${i}`, `Cat${i % 3}`)], at: at(i) }));
    uploads.push({ drafts: [draft("u7", "Cat9")], at: at(n) }); // re-imported, still tracked
    uploads.push({ drafts: [draft("u1", "Cat1")], at: at(n + 1) }); // evicted earlier, back as new
    const seq = await stores();
    for (const u of uploads) await seq.coverage.record("c1", u.drafts, u.at);
    const many = await stores();
    await many.coverage.recordMany("c1", uploads);
    expect(await many.coverage.load("c1")).toEqual(await seq.coverage.load("c1"));
    const everSeen = async (s: Awaited<ReturnType<typeof stores>>) =>
      readFile(join(s.store.stateDir("c1"), "cloud-coverage-seen.json"), "utf8");
    expect(await everSeen(many)).toEqual(await everSeen(seq));
  });
});
