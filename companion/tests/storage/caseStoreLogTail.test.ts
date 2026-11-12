import { describe, it, expect, beforeEach, afterEach, vi } from "vitest";
import { mkdtemp, appendFile, readFile, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { CaseStore } from "../../src/storage/caseStore.js";
import { AppendOnlyLogTail } from "../../src/storage/appendOnlyLogTail.js";
import { AuditLogNeedsRepairError } from "../../src/storage/auditLogNeedsRepairError.js";
import type { ImportMetadata } from "../../src/types.js";

// #2584: import numbering reads imports.jsonl incrementally after an append, and in full after any
// other change — always with the answer a full re-read gives (#1119, #2150, #2253).

let root: string;
let store: CaseStore;

const meta = (sequenceNumber: number): ImportMetadata => ({
  caseId: "t1",
  sequenceNumber,
  importedAt: "2026-11-12T00:00:00.000Z",
  filename: `${sequenceNumber}.csv`,
  originalName: `${sequenceNumber}.csv`,
  rows: 1,
  bytes: 1,
});

const fullReads = () =>
  vi.spyOn(AppendOnlyLogTail.prototype as unknown as { fullRead: () => Promise<unknown> }, "fullRead");

/** What a store with no cache and no high-water mark reads from the log. */
const onDisk = (s: CaseStore) =>
  (s as unknown as { maxSequenceInLog: (...a: unknown[]) => Promise<number> }).maxSequenceInLog(
    "t1",
    "import",
    s.importsLogPath("t1"),
    "sequenceNumber",
  );

beforeEach(async () => {
  root = await mkdtemp(join(tmpdir(), "dfir-logtail-store-"));
  store = new CaseStore(root);
  await store.createCase({ caseId: "t1", name: "n", investigator: "i", aiProvider: null });
});

afterEach(() => {
  vi.restoreAllMocks();
});

describe("import numbering over an incrementally read log (#2584)", () => {
  it("reads the log in full once, then only what each import appended", async () => {
    await store.appendImport("t1", meta(1));
    const reads = fullReads();
    for (let n = 2; n <= 8; n++) {
      expect(await store.nextImportSeq("t1")).toBe(n);
      await store.appendImport("t1", meta(n));
    }
    expect(reads).toHaveBeenCalledTimes(1);
    expect(await onDisk(store)).toBe(await onDisk(new CaseStore(root)));
  });

  it("numbers past a line another writer appended (another process, a hand append)", async () => {
    await store.appendImport("t1", meta(1));
    expect(await store.nextImportSeq("t1")).toBe(2);
    await appendFile(store.importsLogPath("t1"), JSON.stringify(meta(50)) + "\n");
    expect(await store.nextImportSeq("t1")).toBe(51);
  });

  it("re-reads in full after the log was truncated and rewritten, and agrees with a fresh read", async () => {
    for (let n = 1; n <= 4; n++) await store.appendImport("t1", meta(n));
    expect(await onDisk(store)).toBe(4);
    const reads = fullReads();
    const text = await readFile(store.importsLogPath("t1"), "utf8");
    await writeFile(store.importsLogPath("t1"), text.split("\n").slice(0, 2).join("\n") + "\n");
    await appendFile(
      store.importsLogPath("t1"),
      JSON.stringify(meta(30)) + "\n" + JSON.stringify(meta(31)) + "\n",
    );
    expect(await onDisk(store)).toBe(31);
    expect(reads).toHaveBeenCalled();
    expect(await onDisk(store)).toBe(await onDisk(new CaseStore(root)));
  });

  it("keeps failing closed on a corrupted line appended after a cached read", async () => {
    await store.appendImport("t1", meta(1));
    expect(await store.nextImportSeq("t1")).toBe(2);
    await appendFile(store.importsLogPath("t1"), '{"caseId":"t1","sequ\n');
    for (let attempt = 0; attempt < 2; attempt++) {
      const err = await store.nextImportSeq("t1").catch((e: unknown) => e);
      expect(err).toBeInstanceOf(AuditLogNeedsRepairError);
      expect((err as AuditLogNeedsRepairError).lineNumber).toBe(2);
    }
  });

  it("starts a deleted-and-recreated case from its own log", async () => {
    for (let n = 1; n <= 3; n++) await store.appendImport("t1", meta(n));
    expect(await onDisk(store)).toBe(3);
    await store.deleteCaseFolder("t1");
    await store.createCase({ caseId: "t1", name: "n", investigator: "i", aiProvider: null });
    expect(await store.nextImportSeq("t1")).toBe(1);
  });
});
