import { describe, expect, it } from "vitest";
import {
  DROP_BATCH_FILE_MAX_BYTES,
  DROP_BATCH_MAX_BYTES,
  DROP_BATCH_MAX_FILES,
  planDropWork,
  sortByRelpath,
  type DropSniff,
  type DropWorkItem,
} from "../../src/composition/dropBatchPlan.js";
import type { DropFileStat } from "../../src/analysis/dropScan.js";

// #2540 — the drop folder's ordered work list: a contiguous run of small gzip CloudTrail files with
// the same declared host becomes one batch; anything else keeps its place and imports alone.

const file = (relpath: string, size = 2048): DropFileStat => ({ relpath, size, mtimeMs: 1 });
const aws: DropSniff = { kind: "aws", gzip: true, assetHost: "" };

const shape = (work: DropWorkItem[]): string[] =>
  work.map((w) => (w.type === "batch" ? `batch:${w.files.map((f) => f.relpath).join(",")}` : `solo:${w.file.relpath}`));

describe("drop batch plan (#2540)", () => {
  it("batches a contiguous run of small gzip CloudTrail files", () => {
    const files = [file("a.json.gz"), file("b.json.gz"), file("c.json.gz")];
    const sniffs = new Map(files.map((f) => [f.relpath, aws]));
    expect(shape(planDropWork(files, sniffs))).toEqual(["batch:a.json.gz,b.json.gz,c.json.gz"]);
  });

  it("keeps order: a file of another kind breaks the run and stays in place", () => {
    const files = [file("a.json.gz"), file("b.json.gz"), file("c.csv"), file("d.json.gz"), file("e.json.gz")];
    const sniffs = new Map<string, DropSniff>(files.map((f) => [f.relpath, aws]));
    sniffs.set("c.csv", { kind: "csv", gzip: false, assetHost: "" });
    expect(shape(planDropWork(files, sniffs))).toEqual([
      "batch:a.json.gz,b.json.gz",
      "solo:c.csv",
      "batch:d.json.gz,e.json.gz",
    ]);
  });

  it("imports a run of one on its own", () => {
    const files = [file("a.json.gz"), file("b.log")];
    const sniffs = new Map<string, DropSniff>([["a.json.gz", aws]]);
    expect(shape(planDropWork(files, sniffs))).toEqual(["solo:a.json.gz", "solo:b.log"]);
  });

  it("never batches a plain (non-gzip) export, another cloud kind, or an unsniffed file", () => {
    const files = [file("a.json"), file("b.json"), file("c.gz"), file("d.gz"), file("e.gz"), file("f.gz")];
    const sniffs = new Map<string, DropSniff>([
      ["a.json", { kind: "aws", gzip: false, assetHost: "" }],
      ["b.json", { kind: "aws", gzip: false, assetHost: "" }],
      ["c.gz", { kind: "m365", gzip: true, assetHost: "" }],
      ["d.gz", { kind: "m365", gzip: true, assetHost: "" }],
    ]);
    expect(planDropWork(files, sniffs).every((w) => w.type === "solo")).toBe(true);
  });

  it("splits by declared host: files under different asset folders never share a batch", () => {
    const files = [file("asset=H1/a.gz"), file("asset=H1/b.gz"), file("asset=H2/c.gz"), file("asset=H2/d.gz")];
    const sniffs = new Map<string, DropSniff>([
      ["asset=H1/a.gz", { ...aws, assetHost: "H1" }],
      ["asset=H1/b.gz", { ...aws, assetHost: "H1" }],
      ["asset=H2/c.gz", { ...aws, assetHost: "H2" }],
      ["asset=H2/d.gz", { ...aws, assetHost: "H2" }],
    ]);
    const work = planDropWork(files, sniffs);
    expect(shape(work)).toEqual(["batch:asset=H1/a.gz,asset=H1/b.gz", "batch:asset=H2/c.gz,asset=H2/d.gz"]);
    expect(work.map((w) => (w.type === "batch" ? w.assetHost : null))).toEqual(["H1", "H2"]);
  });

  it("bounds a batch by file count", () => {
    const files = Array.from({ length: DROP_BATCH_MAX_FILES + 3 }, (_, i) => file(`f${String(i).padStart(4, "0")}.gz`));
    const sniffs = new Map(files.map((f) => [f.relpath, aws]));
    const work = planDropWork(files, sniffs);
    expect(work).toHaveLength(2);
    expect(work[0]?.type === "batch" && work[0].files.length).toBe(DROP_BATCH_MAX_FILES);
    expect(work[1]?.type === "batch" && work[1].files.length).toBe(3);
  });

  it("bounds a batch by total bytes, and a large file imports alone", () => {
    const big = DROP_BATCH_FILE_MAX_BYTES; // the largest file that may still batch
    const perBatch = Math.floor(DROP_BATCH_MAX_BYTES / big);
    const files = [
      ...Array.from({ length: perBatch + 1 }, (_, i) => file(`a${String(i).padStart(3, "0")}.gz`, big)),
      file("z-huge.gz", big + 1),
    ];
    const sniffs = new Map(files.map((f) => [f.relpath, aws]));
    const work = planDropWork(files, sniffs);
    expect(work[0]?.type === "batch" && work[0].files.length).toBe(perBatch);
    expect(work[1]).toMatchObject({ type: "solo" }); // the one left over is a run of one
    expect(work[2]).toMatchObject({ type: "solo", file: { relpath: "z-huge.gz" } });
  });

  it("sorts the ready files by relpath, the one order a sweep imports in", () => {
    expect(sortByRelpath([file("b"), file("a/z"), file("a")]).map((f) => f.relpath)).toEqual(["a", "a/z", "b"]);
  });
});
