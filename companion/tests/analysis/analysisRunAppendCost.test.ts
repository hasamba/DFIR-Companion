import { describe, it, expect, beforeEach, vi } from "vitest";

// Counts directory listings while delegating to the real filesystem, so the cost of
// an append is measured rather than inferred. Isolated in its own file because the
// module mock is hoisted over every import in it.
vi.mock("node:fs/promises", async (importOriginal) => {
  const actual = await importOriginal<typeof import("node:fs/promises")>();
  return { ...actual, readdir: vi.fn(actual.readdir) };
});

import { mkdtemp, readdir } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { CaseStore } from "../../src/storage/caseStore.js";
import { AnalysisRunStore } from "../../src/analysis/analysisRunStore.js";
import type { AnalysisRunRecordInput } from "../../src/analysis/analysisRunTypes.js";

const BASE_RUN: Omit<AnalysisRunRecordInput, "id"> = {
  kind: "deterministic",
  startedAt: "2026-07-31T10:00:00.000Z",
  finishedAt: "2026-07-31T10:00:01.000Z",
  versions: {},
  input: { artifacts: [], eventIds: [], entityIds: [] },
  output: { entityIds: [], hashes: [], claims: [] },
};

function ledgerListings(): string[] {
  return vi
    .mocked(readdir)
    .mock.calls.map(([target]) => String(target))
    .filter((target) => target.includes("analysis-runs"));
}

describe("AnalysisRunStore append cost", () => {
  let cases: CaseStore;
  let store: AnalysisRunStore;

  beforeEach(async () => {
    const root = await mkdtemp(join(tmpdir(), "dfir-append-cost-"));
    cases = new CaseStore(root);
    await cases.createCase({ caseId: "c1", name: "n", investigator: "i", aiProvider: null });
    store = new AnalysisRunStore(cases, { appVersion: "0.33.0" });
    vi.mocked(readdir).mockClear();
  });

  it("never lists the ledger directory on a healthy append", async () => {
    await store.record("c1", { ...BASE_RUN, id: "run-1" });
    vi.mocked(readdir).mockClear();

    for (const id of ["run-2", "run-3", "run-4", "run-5"]) {
      await store.record("c1", { ...BASE_RUN, id });
    }

    expect(ledgerListings()).toEqual([]);
  });

  it("keeps append cost flat as the ledger grows", async () => {
    for (const id of ["run-1", "run-2", "run-3", "run-4", "run-5", "run-6"]) {
      await store.record("c1", { ...BASE_RUN, id });
    }
    vi.mocked(readdir).mockClear();

    const late = await store.record("c1", { ...BASE_RUN, id: "run-7" });

    expect(late.sequence).toBe(7);
    expect(ledgerListings()).toEqual([]);
  });

  it("lists the directory only when the pinned head cannot be trusted", async () => {
    await store.record("c1", { ...BASE_RUN, id: "run-1" });
    await cases.createCase({ caseId: "c2", name: "n2", investigator: "i", aiProvider: null });
    vi.mocked(readdir).mockClear();

    // c2 has no head at all, so the tip has to be rebuilt from the directory.
    await store.record("c2", { ...BASE_RUN, id: "own-1" });

    expect(ledgerListings().length).toBeGreaterThan(0);
  });
});
