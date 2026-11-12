import { describe, it, expect, beforeEach, afterEach, vi } from "vitest";
import { mkdtemp, readFile, writeFile, appendFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { createHash } from "node:crypto";
import { CaseStore } from "../../src/storage/caseStore.js";
import { AppendOnlyLogTail } from "../../src/storage/appendOnlyLogTail.js";
import { CustodyStore, CUSTODY_HEAD_FILENAME, type CustodyRecordInput } from "../../src/analysis/custody.js";

// #2584: the custody append reads the log's line count and last line incrementally. Every chain
// guarantee (#231 links to the last stored line, #2150 pinned head and regression) must hold exactly
// as with the full re-read, and any change other than an append must take the full read.

let cases: CaseStore;
let store: CustodyStore;
let logPath: string;
let pinPath: string;

const sha = (text: string) => createHash("sha256").update(text, "utf8").digest("hex");
const lines = async () => (await readFile(logPath, "utf8")).split("\n").filter((l) => l.trim());
const fullReads = () =>
  vi.spyOn(AppendOnlyLogTail.prototype as unknown as { fullRead: () => Promise<unknown> }, "fullRead");

function input(n: number): CustodyRecordInput {
  return {
    artifactPath: join(cases.importsDir("c1"), `evidence-${n}.csv`),
    sha256: "0".repeat(64),
    collectedBy: "alice",
    collectedAt: "2026-11-12T10:00:00.000Z",
    source: "ws",
    trigger: "manual",
    caseId: "c1",
  };
}

beforeEach(async () => {
  const root = await mkdtemp(join(tmpdir(), "dfir-custodytail-"));
  cases = new CaseStore(root);
  await cases.createCase({ caseId: "c1", name: "n", investigator: "i", aiProvider: null });
  store = new CustodyStore(cases);
  logPath = cases.custodyLogPath("c1");
  pinPath = join(cases.metadataDir("c1"), CUSTODY_HEAD_FILENAME);
});

afterEach(() => {
  vi.restoreAllMocks();
});

describe("custody append over an incrementally read log (#2584)", () => {
  it("reads the log in full once per fold, then only each append, and the chain verifies", async () => {
    await store.record("c1", input(0)); // creates the log: nothing to snapshot yet
    await store.record("c1", input(1)); // the one full read per fold (line tail, seq)
    const reads = fullReads();
    for (let n = 2; n <= 10; n++) await store.record("c1", input(n));
    await store.recordMany("c1", [input(11), input(12)]);
    expect(reads).not.toHaveBeenCalled();
    const all = await lines();
    expect(all).toHaveLength(13);
    expect(JSON.parse(await readFile(pinPath, "utf8"))).toEqual({
      records: 13,
      headSeq: 13,
      headHash: sha(all[12]),
    });
    expect(await store.verifyChain("c1")).toEqual([]);
  });

  it("links the next record to a line another writer appended", async () => {
    await store.record("c1", input(1));
    const foreign = JSON.stringify({
      ...input(2),
      seq: 40,
      prevHash: sha((await lines())[0]),
      event: "collected",
    });
    await appendFile(logPath, foreign + "\n");
    const next = await store.record("c1", input(3));
    expect(next.prevHash).toBe(sha(foreign));
    expect(next.seq).toBe(41);
    expect(await store.verifyChain("c1")).toEqual([]);
  });

  it("advances the pin past a log that is ahead of it (a crash between append and pin write)", async () => {
    await store.record("c1", input(1));
    const pinBefore = await readFile(pinPath, "utf8");
    await store.record("c1", input(2));
    await writeFile(pinPath, pinBefore); // the second append's pin write never happened
    await store.record("c1", input(3));
    const all = await lines();
    expect(JSON.parse(await readFile(pinPath, "utf8"))).toMatchObject({ records: 3, headHash: sha(all[2]) });
    expect(await store.verifyChain("c1")).toEqual([]);
  });

  it("re-reads in full after a truncation, and keeps reporting the regression", async () => {
    for (let n = 1; n <= 5; n++) await store.record("c1", input(n));
    const all = await lines();
    await writeFile(logPath, all.slice(0, 3).join("\n") + "\n");
    const reads = fullReads();
    const next = await store.record("c1", input(6));
    expect(reads).toHaveBeenCalled();
    expect(next.prevHash).toBe(sha(all[2]));
    expect(await store.verifyChain("c1")).toEqual([{ line: 5, seq: 5, reason: "head-regression" }]);
    await store.record("c1", input(7));
    expect(await store.verifyChain("c1")).toEqual([{ line: 5, seq: 5, reason: "head-regression" }]);
  });

  it("re-reads in full when an already-read line was rewritten in place to the same length", async () => {
    for (let n = 1; n <= 3; n++) await store.record("c1", input(n));
    const all = await lines();
    const forged = all[1].replace('"alice"', '"mally"');
    expect(forged).toHaveLength(all[1].length);
    await writeFile(logPath, [all[0], forged, all[2]].join("\n") + "\n");
    const reads = fullReads();
    const next = await store.record("c1", input(4));
    expect(reads).toHaveBeenCalled();
    expect(next.prevHash).toBe(sha(all[2]));
    expect(await store.verifyChain("c1")).toContainEqual({ line: 3, seq: 3, reason: "prev-hash-mismatch" });
  });
});
