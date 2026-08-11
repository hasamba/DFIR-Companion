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
  const root = await mkdtemp(join(tmpdir(), "dfir-custodytransfer-"));
  cases = new CaseStore(root);
  await cases.createCase({ caseId: "c1", name: "n", investigator: "i", aiProvider: null });
  store = new CustodyStore(cases);
  one = join(cases.importsDir("c1"), "one.raw");
  two = join(cases.importsDir("c1"), "two.raw");
});

describe("CustodyStore.recordTransfer", () => {
  it("appends one transferred event per named artifact, naming where it went", async () => {
    await collect(one, "first\n");
    await collect(two, "second\n");

    const written = await store.recordTransfer("c1", {
      artifactPaths: [one, two],
      transferredBy: "alice",
      destination: "sift.lab.local:/cases/incoming",
    });

    expect(written.map((r) => r.artifactPath)).toEqual([one, two]);
    expect(written.every((r) => r.event === "transferred")).toBe(true);
    expect(written.every((r) => r.source === "sift.lab.local:/cases/incoming")).toBe(true);
    expect(written.every((r) => r.collectedBy === "alice")).toBe(true);
  });

  // The behaviour that separates a transfer from an export: an export claims everything under
  // custody left; a transfer must claim only what the caller actually sent.
  it("records only the artifacts named, not everything under custody", async () => {
    await collect(one, "first\n");
    await collect(two, "second\n");

    const written = await store.recordTransfer("c1", {
      artifactPaths: [two],
      transferredBy: "alice",
      destination: "remnux.lab.local",
    });

    expect(written.map((r) => r.artifactPath)).toEqual([two]);
    const transferred = (await store.load("c1")).filter((r) => r.event === "transferred");
    expect(transferred.map((r) => r.artifactPath)).toEqual([two]);
  });

  it("re-hashes each artifact so the record states the bytes that travelled", async () => {
    await collect(one, "first\n");
    // Legitimately rewritten after collection — what was sent is the current bytes, not the
    // ones recorded at import time.
    await writeFile(one, "amended\n", "utf8");

    const [record] = await store.recordTransfer("c1", {
      artifactPaths: [one],
      transferredBy: "alice",
      destination: "sift.lab.local",
    });

    expect(record.sha256).toBe(sha("amended\n"));
  });

  it('defaults the trigger to "transfer" and keeps a caller-supplied one', async () => {
    await collect(one, "first\n");
    await collect(two, "second\n");

    const [plain] = await store.recordTransfer("c1", {
      artifactPaths: [one],
      transferredBy: "alice",
      destination: "sift.lab.local",
    });
    const [tagged] = await store.recordTransfer("c1", {
      artifactPaths: [two],
      transferredBy: "alice",
      destination: "sift.lab.local",
      trigger: "mcp:sift-mcp",
    });

    expect(plain.trigger).toBe("transfer");
    expect(tagged.trigger).toBe("mcp:sift-mcp");
  });

  it("records the same artifact once however many times it is named", async () => {
    await collect(one, "first\n");

    const written = await store.recordTransfer("c1", {
      artifactPaths: [one, one, one],
      transferredBy: "alice",
      destination: "sift.lab.local",
    });

    expect(written).toHaveLength(1);
  });

  // An unreadable artifact cannot be attested to, so the whole batch is refused rather than
  // recorded as a partial transfer — the opposite of recordExport, which skips and carries on.
  it("throws when an artifact cannot be read, naming it", async () => {
    await collect(one, "first\n");
    const missing = join(cases.importsDir("c1"), "gone.raw");

    await expect(
      store.recordTransfer("c1", {
        artifactPaths: [one, missing],
        transferredBy: "alice",
        destination: "sift.lab.local",
      }),
    ).rejects.toThrow(/cannot record transfer of .*gone\.raw/);
  });

  it("appends nothing at all when one artifact in the batch is unreadable", async () => {
    await collect(one, "first\n");
    await collect(two, "second\n");
    await rm(two);

    await store
      .recordTransfer("c1", {
        artifactPaths: [one, two],
        transferredBy: "alice",
        destination: "sift.lab.local",
      })
      .catch(() => {
        /* asserted above; here we care about what landed */
      });

    // The two collections, and not a transfer for `one` — which hashed fine before `two` failed.
    const records = await store.load("c1");
    expect(records.map((r) => r.event)).toEqual(["collected", "collected"]);
  });

  it("writes nothing when no artifacts are named", async () => {
    expect(
      await store.recordTransfer("c1", {
        artifactPaths: [],
        transferredBy: "alice",
        destination: "sift.lab.local",
      }),
    ).toEqual([]);
    await expect(readFile(cases.custodyLogPath("c1"), "utf8")).rejects.toMatchObject({ code: "ENOENT" });
  });

  // Evidence can be sent somewhere before anyone recorded collecting it (tool output, a file
  // dropped straight into the case dir). Refusing that would lose the transfer entirely, which is
  // strictly worse than a chain whose first entry is the send.
  it("records a transfer for an artifact that has no prior custody record", async () => {
    await writeFile(one, "first\n", "utf8");

    const [record] = await store.recordTransfer("c1", {
      artifactPaths: [one],
      transferredBy: "alice",
      destination: "sift.lab.local",
    });

    expect(record.event).toBe("transferred");
    expect(record.prevHash).toBe("");
  });

  it("leaves the chain intact across the batch it appends", async () => {
    await collect(one, "first\n");
    await collect(two, "second\n");

    await store.recordTransfer("c1", {
      artifactPaths: [one, two],
      transferredBy: "alice",
      destination: "sift.lab.local",
    });

    expect(await store.verifyChain("c1")).toEqual([]);
    expect((await store.load("c1")).map((r) => r.seq)).toEqual([1, 2, 3, 4]);
  });

  // The chain links stored lines, and an in-case artifact is stored relative to the case dir.
  // A transfer must get the same relocation-proofing as a collection or the record would break
  // the moment the case was archived.
  it("stores an in-case artifact relative to the case dir and resolves it back", async () => {
    await collect(one, "first\n");

    await store.recordTransfer("c1", {
      artifactPaths: [one],
      transferredBy: "alice",
      destination: "sift.lab.local",
    });

    const raw = await readFile(cases.custodyLogPath("c1"), "utf8");
    const stored = JSON.parse(raw.trim().split("\n")[1]) as { artifactPath: string; relativeTo?: string };
    expect(stored.relativeTo).toBe("case-dir");
    expect(stored.artifactPath).not.toContain(cases.caseDir("c1"));
    expect((await store.load("c1"))[1].artifactPath).toBe(one);
  });
});
