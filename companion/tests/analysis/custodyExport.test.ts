import { describe, it, expect, beforeEach } from "vitest";
import { mkdtemp, writeFile, rm, readFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { createHash } from "node:crypto";
import { CaseStore } from "../../src/storage/caseStore.js";
import { CustodyStore } from "../../src/analysis/custody.js";

let store: CustodyStore;
let cases: CaseStore;
let one: string;
let two: string;

const sha = (text: string) => createHash("sha256").update(text, "utf8").digest("hex");

async function collect(path: string, text: string): Promise<void> {
  await writeFile(path, text, "utf8");
  await store.record("c1", {
    artifactPath: path,
    sha256: sha(text),
    collectedBy: "alice",
    collectedAt: "2026-07-28T10:00:00.000Z",
    source: "host-a",
    trigger: "import",
    caseId: "c1",
  });
}

beforeEach(async () => {
  const root = await mkdtemp(join(tmpdir(), "dfir-custodyexport-"));
  cases = new CaseStore(root);
  await cases.createCase({ caseId: "c1", name: "n", investigator: "i", aiProvider: null });
  store = new CustodyStore(cases);
  one = join(cases.importsDir("c1"), "one.csv");
  two = join(cases.importsDir("c1"), "two.csv");
});

describe("CustodyStore.recordExport", () => {
  it("appends one exported event per artifact under custody", async () => {
    await collect(one, "first\n");
    await collect(two, "second\n");

    const written = await store.recordExport("c1", { exportedBy: "alice", destination: "encrypted archive" });

    expect(written.map((r) => r.artifactPath).sort()).toEqual([one, two].sort());
    expect(written.every((r) => r.event === "exported")).toBe(true);
    expect(written.every((r) => r.source === "encrypted archive" && r.collectedBy === "alice")).toBe(true);
  });

  it("records one event per artifact however many prior records it has", async () => {
    await collect(one, "first\n");
    await store.record("c1", {
      artifactPath: one,
      sha256: sha("first\n"),
      collectedBy: "bob",
      collectedAt: "2026-07-28T11:00:00.000Z",
      source: "lab-3",
      trigger: "manual",
      caseId: "c1",
      event: "transferred",
    });

    const written = await store.recordExport("c1", { exportedBy: "alice", destination: "zip" });

    expect(written).toHaveLength(1);
  });

  it("re-hashes each artifact so the export records what actually left", async () => {
    await collect(one, "first\n");
    // Legitimately rewritten after collection — the export must state the bytes it carried out,
    // not the bytes recorded earlier.
    await writeFile(one, "amended\n", "utf8");

    const [record] = await store.recordExport("c1", { exportedBy: "alice", destination: "zip" });

    expect(record.sha256).toBe(sha("amended\n"));
  });

  it("skips an artifact that is no longer on disk, since it left in nothing", async () => {
    await collect(one, "first\n");
    await collect(two, "second\n");
    await rm(two);

    const written = await store.recordExport("c1", { exportedBy: "alice", destination: "zip" });

    expect(written.map((r) => r.artifactPath)).toEqual([one]);
  });

  it("writes nothing when the case has no custody records", async () => {
    expect(await store.recordExport("c1", { exportedBy: "alice", destination: "zip" })).toEqual([]);
    await expect(readFile(cases.custodyLogPath("c1"), "utf8")).rejects.toMatchObject({ code: "ENOENT" });
  });

  it("leaves the chain intact across the batch it appends", async () => {
    await collect(one, "first\n");
    await collect(two, "second\n");

    await store.recordExport("c1", { exportedBy: "alice", destination: "zip" });

    expect(await store.verifyChain("c1")).toEqual([]);
    expect((await store.load("c1")).map((r) => r.seq)).toEqual([1, 2, 3, 4]);
  });
});
