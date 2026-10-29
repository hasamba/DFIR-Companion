import { describe, it, expect, beforeEach } from "vitest";
import { mkdtemp, mkdir, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { CaseStore } from "../../src/storage/caseStore.js";
import { AuditLogNeedsRepairError } from "../../src/storage/auditLogNeedsRepairError.js";

// #2252: a corrupted audit-log line still fails closed, but as a typed error that names the case,
// the file and the line an analyst has to fix — not a generic Error carrying an absolute path.

let root: string;
let store: CaseStore;

beforeEach(async () => {
  root = await mkdtemp(join(tmpdir(), "dfir-log-repair-"));
  store = new CaseStore(root);
  await store.createCase({ caseId: "lr-1", name: "n", investigator: "i", aiProvider: null });
  await mkdir(store.metadataDir("lr-1"), { recursive: true });
});

const good = (n: number): string => JSON.stringify({ caseId: "lr-1", sequenceNumber: n });

async function rejection(p: Promise<unknown>): Promise<AuditLogNeedsRepairError> {
  const err = await p.then(
    () => null,
    (e: unknown) => e,
  );
  expect(err).toBeInstanceOf(AuditLogNeedsRepairError);
  return err as AuditLogNeedsRepairError;
}

describe("AuditLogNeedsRepairError (#2252)", () => {
  it("names the case, the capture log and the physical line number", async () => {
    await writeFile(store.capturesLogPath("lr-1"), `${good(1)}\n${good(2)}\n{"caseId":"lr-1","seq\n`, "utf8");
    const err = await rejection(store.nextSequenceNumber("lr-1"));
    expect(err.caseId).toBe("lr-1");
    expect(err.kind).toBe("capture");
    expect(err.code).toBe("capture-log-needs-repair");
    expect(err.lineNumber).toBe(3);
    expect(err.logFile).toBe("captures.jsonl");
    expect(err.message).toContain('Case "lr-1"');
    expect(err.message).toContain("line 3");
    expect(err.message).toMatch(/corrupted\/truncated/);
    expect(err.message).not.toContain(root);
  });

  it("counts blank lines in the line number, the way an editor shows the file", async () => {
    await writeFile(store.capturesLogPath("lr-1"), `${good(1)}\n\n{broken\n`, "utf8");
    const err = await rejection(store.nextSequenceNumber("lr-1"));
    expect(err.lineNumber).toBe(3);
  });

  it("uses the same type for the import log", async () => {
    await writeFile(store.importsLogPath("lr-1"), "{broken\n", "utf8");
    const err = await rejection(store.nextImportSeq("lr-1"));
    expect(err.kind).toBe("import");
    expect(err.code).toBe("import-log-needs-repair");
    expect(err.lineNumber).toBe(1);
  });

  it("uses the same type for the custody log", async () => {
    await writeFile(store.custodyLogPath("lr-1"), `${JSON.stringify({ seq: 1 })}\n{broken\n`, "utf8");
    const err = await rejection(store.nextCustodySeq("lr-1"));
    expect(err.kind).toBe("custody");
    expect(err.code).toBe("custody-log-needs-repair");
    expect(err.lineNumber).toBe(2);
  });

  it("still fails closed — once repaired, allocation resumes past every recorded number", async () => {
    await writeFile(store.capturesLogPath("lr-1"), `${good(1)}\n${good(5)}\n{broken\n`, "utf8");
    await rejection(store.nextSequenceNumber("lr-1"));
    await writeFile(store.capturesLogPath("lr-1"), `${good(1)}\n${good(5)}\n`, "utf8");
    expect(await store.nextSequenceNumber("lr-1")).toBe(6);
  });
});
