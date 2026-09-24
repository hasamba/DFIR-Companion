import { describe, it, expect } from "vitest";
import { mkdtemp, readFile, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { CaseStore } from "../../src/storage/caseStore.js";
import { JevGradeStore } from "../../src/analysis/ai/jev/jevGradeRecord.js";

// The server's own copy of what a missed-evidence review graded (#1578). The promote route writes a
// severity and a provenance tag from this record and from nothing the browser sends, so the record
// has to outlive the request, the tab and the process, and a later review must refine it rather
// than wipe it.

async function cases() {
  const root = await mkdtemp(join(tmpdir(), "dfir-jev-grades-"));
  const store = new CaseStore(root);
  await store.createCase({ caseId: "c1", name: "n", investigator: "i", aiProvider: null });
  return store;
}

const graded = (id: string, grade: "Info" | "Low" | "Medium" | "High" | "Critical", confidence = 0.8) => ({
  id,
  grade,
  confidence,
  score: 2,
});

describe("the review grade record", () => {
  it("is empty for a case that was never reviewed", async () => {
    const store = await cases();
    expect(await new JevGradeStore(store).load("c1")).toEqual(new Map());
  });

  it("keeps each row's grade, confidence, score and model, and survives a restart", async () => {
    const store = await cases();
    await new JevGradeStore(store).record(
      "c1",
      "typesafe/jev-1.13",
      [graded("r1", "High", 0.91)],
      "2026-09-24T10:00:00.000Z",
    );

    // A fresh instance over the same directory is what a server restart looks like.
    const entry = (await new JevGradeStore(store).load("c1")).get("r1");
    expect(entry).toEqual({
      grade: "High",
      confidence: 0.91,
      score: 2,
      model: "typesafe/jev-1.13",
      reviewedAt: "2026-09-24T10:00:00.000Z",
    });
  });

  it("merges a later review: re-graded rows take the new grade, untouched rows keep theirs", async () => {
    const store = await cases();
    const grades = new JevGradeStore(store);
    await grades.record(
      "c1",
      "jev-a",
      [graded("r1", "High"), graded("r2", "Low")],
      "2026-09-24T10:00:00.000Z",
    );
    await grades.record("c1", "jev-b", [graded("r2", "Critical", 0.99)], "2026-09-24T11:00:00.000Z");

    const record = await grades.load("c1");
    expect(record.get("r1")).toMatchObject({ grade: "High", model: "jev-a" });
    expect(record.get("r2")).toMatchObject({ grade: "Critical", confidence: 0.99, model: "jev-b" });
    expect(record.get("r2")?.reviewedAt).toBe("2026-09-24T11:00:00.000Z");
  });

  it("does not lose a write when two reviews record at the same moment", async () => {
    const store = await cases();
    const grades = new JevGradeStore(store);
    await Promise.all([
      grades.record("c1", "jev", [graded("r1", "High")]),
      new JevGradeStore(store).record("c1", "jev", [graded("r2", "Low")]),
    ]);
    expect([...(await grades.load("c1")).keys()].sort()).toEqual(["r1", "r2"]);
  });

  it("drops an entry the file holds in a shape it cannot trust, and keeps the rest", async () => {
    const store = await cases();
    const grades = new JevGradeStore(store);
    await grades.record("c1", "jev", [graded("r1", "High")]);
    const path = join(store.stateDir("c1"), "jev-grades.json");
    const doc = JSON.parse(await readFile(path, "utf8"));
    doc.rows.bad = { grade: "Severe", confidence: 0.5, score: 1, model: "jev", reviewedAt: "x" };
    await writeFile(path, JSON.stringify(doc));

    const record = await grades.load("c1");
    expect(record.has("r1")).toBe(true);
    expect(record.has("bad")).toBe(false);
  });
});
