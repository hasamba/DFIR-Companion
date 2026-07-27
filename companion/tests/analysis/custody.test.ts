import { describe, it, expect, beforeEach } from "vitest";
import { mkdtemp, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { createHash } from "node:crypto";
import { CaseStore } from "../../src/storage/caseStore.js";
import { CustodyStore } from "../../src/analysis/custody.js";

describe("CustodyStore", () => {
  let store: CustodyStore;
  let cases: CaseStore;
  let casesRoot: string;
  let artifactPath: string;

  beforeEach(async () => {
    casesRoot = await mkdtemp(join(tmpdir(), "dfir-custody-"));
    cases = new CaseStore(casesRoot);
    await cases.createCase({ caseId: "c1", name: "n", investigator: "i", aiProvider: null });
    store = new CustodyStore(cases);
    artifactPath = join(cases.importsDir("c1"), "evidence.csv");
    await writeFile(artifactPath, "hello world\n", "utf8");
  });

  it("returns [] when no custody has been recorded", async () => {
    expect(await store.load("c1")).toEqual([]);
  });

  it("appends a custody entry and lists it in append order", async () => {
    const record = await store.record("c1", {
      artifactPath,
      sha256: createHash("sha256").update("hello world\n").digest("hex"),
      collectedBy: "alice",
      collectedAt: "2026-07-24T00:00:00.000Z",
      source: "import",
      trigger: "manual",
      caseId: "c1",
    });
    expect(record.artifactPath).toBe(artifactPath);
    const list = await store.load("c1");
    expect(list).toHaveLength(1);
    expect(list[0].collectedBy).toBe("alice");
    expect(list[0].sha256).toHaveLength(64);
  });

  it("skips a malformed line instead of throwing", async () => {
    await store.record("c1", {
      artifactPath, sha256: "abc", collectedBy: "a", collectedAt: "t", source: "s", trigger: "m", caseId: "c1",
    });
    const { appendFile } = await import("node:fs/promises");
    await appendFile(join(casesRoot, "c1", "metadata", "custody.jsonl"), "not json\n", "utf8");
    const list = await store.load("c1");
    expect(list).toHaveLength(1);
    expect(list[0].sha256).toBe("abc");
  });

  it("verifyIntegrity returns no mismatches when the artifact is unchanged", async () => {
    const sha = createHash("sha256").update("hello world\n").digest("hex");
    await store.record("c1", {
      artifactPath, sha256: sha, collectedBy: "a", collectedAt: "t", source: "s", trigger: "m", caseId: "c1",
    });
    const mismatches = await store.verifyIntegrity("c1");
    expect(mismatches).toEqual([]);
  });

  it("verifyIntegrity reports a hash-mismatch when the artifact has been modified", async () => {
    const sha = createHash("sha256").update("hello world\n").digest("hex");
    await store.record("c1", {
      artifactPath, sha256: sha, collectedBy: "a", collectedAt: "t", source: "s", trigger: "m", caseId: "c1",
    });
    await writeFile(artifactPath, "tampered content\n", "utf8");
    const mismatches = await store.verifyIntegrity("c1");
    expect(mismatches).toHaveLength(1);
    expect(mismatches[0].reason).toBe("hash-mismatch");
    expect(mismatches[0].actualSha256).not.toBe(sha);
    expect(mismatches[0].recordedSha256).toBe(sha);
  });

  it("verifyIntegrity reports a missing artifact when the file no longer exists", async () => {
    const sha = createHash("sha256").update("hello world\n").digest("hex");
    await store.record("c1", {
      artifactPath, sha256: sha, collectedBy: "a", collectedAt: "t", source: "s", trigger: "m", caseId: "c1",
    });
    const { rm } = await import("node:fs/promises");
    await rm(artifactPath);
    const mismatches = await store.verifyIntegrity("c1");
    expect(mismatches).toHaveLength(1);
    expect(mismatches[0].reason).toBe("missing");
    expect(mismatches[0].actualSha256).toBeNull();
  });

  it("records multiple entries for the same case", async () => {
    const sha1 = createHash("sha256").update("hello world\n").digest("hex");
    await store.record("c1", {
      artifactPath, sha256: sha1, collectedBy: "a", collectedAt: "t1", source: "s", trigger: "m", caseId: "c1",
    });
    const second = join(cases.importsDir("c1"), "second.log");
    await writeFile(second, "second artifact\n", "utf8");
    const sha2 = createHash("sha256").update("second artifact\n").digest("hex");
    await store.record("c1", {
      artifactPath: second, sha256: sha2, collectedBy: "b", collectedAt: "t2", source: "s2", trigger: "m2", caseId: "c1",
    });
    const list = await store.load("c1");
    expect(list).toHaveLength(2);
    expect(list.map((r) => r.artifactPath)).toEqual([artifactPath, second]);
  });
});
