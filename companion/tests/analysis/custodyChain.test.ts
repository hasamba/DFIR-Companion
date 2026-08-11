import { describe, it, expect, beforeEach } from "vitest";
import { mkdtemp, writeFile, readFile, appendFile, mkdir } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { createHash } from "node:crypto";
import { CaseStore } from "../../src/storage/caseStore.js";
import { CustodyStore, type CustodyRecordInput } from "../../src/analysis/custody.js";

let store: CustodyStore;
let cases: CaseStore;
let casesRoot: string;
let logPath: string;

const sha = (text: string) => createHash("sha256").update(text, "utf8").digest("hex");
const lines = async () => (await readFile(logPath, "utf8")).split("\n").filter((l) => l.trim());

function input(over: Partial<CustodyRecordInput> = {}): CustodyRecordInput {
  return {
    artifactPath: join(cases.importsDir("c1"), "evidence.csv"),
    sha256: "0".repeat(64),
    collectedBy: "alice",
    collectedAt: "2026-07-28T10:00:00.000Z",
    source: "workstation-7",
    trigger: "manual",
    caseId: "c1",
    ...over,
  };
}

beforeEach(async () => {
  casesRoot = await mkdtemp(join(tmpdir(), "dfir-custodychain-"));
  cases = new CaseStore(casesRoot);
  await cases.createCase({ caseId: "c1", name: "n", investigator: "i", aiProvider: null });
  store = new CustodyStore(cases);
  logPath = join(casesRoot, "c1", "metadata", "custody.jsonl");
});

describe("custody event type", () => {
  it("defaults to the collected event", async () => {
    const record = await store.record("c1", input());

    expect(record.event).toBe("collected");
    expect((await store.load("c1"))[0].event).toBe("collected");
  });

  it("records the event the caller asks for", async () => {
    const record = await store.record("c1", input({ event: "exported" }));

    expect(record).toMatchObject({ event: "exported", seq: 1 });
    expect((await store.load("c1"))[0].event).toBe("exported");
  });

  it("normalizes an unrecognized event to collected rather than logging it verbatim", async () => {
    await store.record("c1", input({ event: "shredded" as never }));

    expect((await store.load("c1"))[0].event).toBe("collected");
  });

  it("reads a legacy record with no event as collected", async () => {
    const legacy = { ...input(), artifactPath: "/tmp/legacy.dd" };
    await mkdir(join(casesRoot, "c1", "metadata"), { recursive: true });
    await appendFile(logPath, JSON.stringify(legacy) + "\n", "utf8");

    expect((await store.load("c1"))[0].event).toBe("collected");
  });
});

describe("custody hash chain", () => {
  it("starts the chain with an empty prevHash at seq 1", async () => {
    const record = await store.record("c1", input());

    expect(record).toMatchObject({ seq: 1, prevHash: "" });
  });

  it("links each record to the hash of the previous stored line", async () => {
    await store.record("c1", input());
    const second = await store.record("c1", input({ event: "exported" }));

    const [first] = await lines();
    expect(second.seq).toBe(2);
    expect(second.prevHash).toBe(sha(first));
  });

  it("chains over the stored line, so the chain survives the case being archived", async () => {
    await store.record("c1", input());
    await store.record("c1", input({ event: "exported" }));

    await cases.archiveCaseFolder("c1");

    expect(await store.verifyChain("c1")).toEqual([]);
  });

  it("keeps one unbroken chain when records are appended concurrently", async () => {
    await Promise.all(Array.from({ length: 12 }, () => store.record("c1", input())));

    expect(await store.verifyChain("c1")).toEqual([]);
    expect((await store.load("c1")).map((r) => r.seq)).toEqual([1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12]);
  });
});

describe("CustodyStore.verifyChain", () => {
  it("reports no breaks for an intact log", async () => {
    await store.record("c1", input());
    await store.record("c1", input());

    expect(await store.verifyChain("c1")).toEqual([]);
  });

  it("reports no breaks when nothing has been recorded", async () => {
    expect(await store.verifyChain("c1")).toEqual([]);
  });

  it("flags the following record when an entry is edited in place", async () => {
    await store.record("c1", input());
    await store.record("c1", input());
    const [first, second] = await lines();
    const tampered = JSON.parse(first) as Record<string, unknown>;
    tampered.collectedBy = "mallory";

    await writeFile(logPath, JSON.stringify(tampered) + "\n" + second + "\n", "utf8");

    expect(await store.verifyChain("c1")).toEqual([{ line: 2, seq: 2, reason: "prev-hash-mismatch" }]);
  });

  it("flags the gap when a record is deleted from the middle", async () => {
    await store.record("c1", input());
    await store.record("c1", input());
    await store.record("c1", input());
    const [first, , third] = await lines();

    await writeFile(logPath, first + "\n" + third + "\n", "utf8");

    expect(await store.verifyChain("c1")).toEqual([{ line: 2, seq: 3, reason: "prev-hash-mismatch" }]);
  });

  it("flags a record whose seq does not advance", async () => {
    await store.record("c1", input());
    const [first] = await lines();
    // Re-linked correctly but numbered backwards — a replayed record.
    const replay = { ...(JSON.parse(first) as Record<string, unknown>), seq: 1, prevHash: sha(first) };

    await appendFile(logPath, JSON.stringify(replay) + "\n", "utf8");

    expect(await store.verifyChain("c1")).toEqual([{ line: 2, seq: 1, reason: "seq-out-of-order" }]);
  });

  it("allows a gap in seq, which a failed append leaves behind by design", async () => {
    await store.record("c1", input());
    const [first] = await lines();
    const skipped = { ...(JSON.parse(first) as Record<string, unknown>), seq: 7, prevHash: sha(first) };

    await appendFile(logPath, JSON.stringify(skipped) + "\n", "utf8");

    expect(await store.verifyChain("c1")).toEqual([]);
  });

  it("does not flag legacy records that predate the chain", async () => {
    const legacy = { ...input(), artifactPath: "/tmp/legacy.dd" };
    await mkdir(join(casesRoot, "c1", "metadata"), { recursive: true });
    await appendFile(logPath, JSON.stringify(legacy) + "\n", "utf8");

    expect(await store.verifyChain("c1")).toEqual([]);
  });

  it("chains a new record onto a legacy tail, and verifies it", async () => {
    const legacy = { ...input(), artifactPath: "/tmp/legacy.dd" };
    await mkdir(join(casesRoot, "c1", "metadata"), { recursive: true });
    await appendFile(logPath, JSON.stringify(legacy) + "\n", "utf8");

    const next = await store.record("c1", input());

    expect(next.prevHash).toBe(sha(JSON.stringify(legacy)));
    expect(await store.verifyChain("c1")).toEqual([]);
  });
});
