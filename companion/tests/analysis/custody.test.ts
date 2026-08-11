import { describe, it, expect, beforeEach } from "vitest";
import { mkdtemp, writeFile, readFile, rename, mkdir, appendFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { createHash } from "node:crypto";
import { CaseStore } from "../../src/storage/caseStore.js";
import { CustodyStore } from "../../src/analysis/custody.js";
import { runWithIdentity } from "../../src/auth/identityContext.js";
import type { AuthIdentity } from "../../src/auth/types.js";

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

  it("binds custody to the authenticated immutable identity", async () => {
    const identity: AuthIdentity = {
      id: "usr-immutable",
      kind: "oidc",
      username: "alice@example.invalid",
      displayName: "Alice Analyst",
      globalRole: "member",
      disabled: false,
      createdAt: "2026-07-31T00:00:00.000Z",
      updatedAt: "2026-07-31T00:00:00.000Z",
    };
    const record = await runWithIdentity(identity, () =>
      store.record("c1", {
        artifactPath,
        sha256: createHash("sha256").update("hello world\n").digest("hex"),
        collectedBy: "forged client name",
        collectedAt: "2026-07-31T00:00:00.000Z",
        source: "import",
        trigger: "manual",
        caseId: "c1",
      }),
    );

    expect(record).toMatchObject({
      actorId: "usr-immutable",
      actorDisplayName: "Alice Analyst",
      actorKind: "oidc",
      collectedBy: "Alice Analyst",
    });
  });

  it("skips a malformed line instead of throwing", async () => {
    await store.record("c1", {
      artifactPath,
      sha256: "abc",
      collectedBy: "a",
      collectedAt: "t",
      source: "s",
      trigger: "m",
      caseId: "c1",
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
      artifactPath,
      sha256: sha,
      collectedBy: "a",
      collectedAt: "t",
      source: "s",
      trigger: "m",
      caseId: "c1",
    });
    const mismatches = await store.verifyIntegrity("c1");
    expect(mismatches).toEqual([]);
  });

  it("verifyIntegrity reports a hash-mismatch when the artifact has been modified", async () => {
    const sha = createHash("sha256").update("hello world\n").digest("hex");
    await store.record("c1", {
      artifactPath,
      sha256: sha,
      collectedBy: "a",
      collectedAt: "t",
      source: "s",
      trigger: "m",
      caseId: "c1",
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
      artifactPath,
      sha256: sha,
      collectedBy: "a",
      collectedAt: "t",
      source: "s",
      trigger: "m",
      caseId: "c1",
    });
    const { rm } = await import("node:fs/promises");
    await rm(artifactPath);
    const mismatches = await store.verifyIntegrity("c1");
    expect(mismatches).toHaveLength(1);
    expect(mismatches[0].reason).toBe("missing");
    expect(mismatches[0].actualSha256).toBeNull();
  });

  // The case folder moves: archiving relocates it under _archived/, and the whole cases root moves
  // on a DFIR_CASES_DIR change, a container remount or a restore from backup. An artifact inside the
  // case dir is stored relative to it and re-resolved through caseDir() at verification time, so the
  // evidence stays verifiable wherever the folder ends up (#231 follow-up).
  describe("when the case folder moves", () => {
    const sha = createHash("sha256").update("hello world\n").digest("hex");
    const recordArtifact = (): Promise<unknown> =>
      store.record("c1", {
        artifactPath,
        sha256: sha,
        collectedBy: "a",
        collectedAt: "t",
        source: "s",
        trigger: "m",
        caseId: "c1",
      });

    it("stores an in-case artifact as a path relative to the case dir", async () => {
      await recordArtifact();
      const line = await readFile(join(casesRoot, "c1", "metadata", "custody.jsonl"), "utf8");
      const stored = JSON.parse(line.trim()) as { artifactPath: string; relativeTo?: string };
      expect(stored.artifactPath).toBe(join("imports", "evidence.csv"));
      expect(stored.relativeTo).toBe("case-dir");
    });

    it("load resolves a case-relative record back to an absolute path", async () => {
      await recordArtifact();
      const list = await store.load("c1");
      expect(list[0].artifactPath).toBe(artifactPath);
    });

    it("verifyIntegrity stays clean after the case is archived", async () => {
      await recordArtifact();
      await cases.archiveCaseFolder("c1");
      expect(await store.verifyIntegrity("c1")).toEqual([]);
    });

    it("verifyIntegrity stays clean after the cases root is moved", async () => {
      await recordArtifact();
      const movedRoot = join(await mkdtemp(join(tmpdir(), "dfir-custody-moved-")), "cases");
      await rename(casesRoot, movedRoot);
      const moved = new CustodyStore(new CaseStore(movedRoot));
      expect(await moved.verifyIntegrity("c1")).toEqual([]);
    });

    it("still catches tampering after the case is archived", async () => {
      await recordArtifact();
      await cases.archiveCaseFolder("c1");
      await writeFile(join(cases.importsDir("c1"), "evidence.csv"), "tampered\n", "utf8");
      const mismatches = await store.verifyIntegrity("c1");
      expect(mismatches).toHaveLength(1);
      expect(mismatches[0].reason).toBe("hash-mismatch");
      expect(mismatches[0].artifactPath).toBe(join(casesRoot, "_archived", "c1", "imports", "evidence.csv"));
    });
  });

  // Evidence collected manually via POST /cases/:id/custody routinely lives outside the case dir —
  // mounted images, external tool output. There is nothing to make it relative to, so it keeps being
  // stored (and verified) as the absolute path it is.
  describe("artifacts outside the case dir", () => {
    let external: string;
    let externalSha: string;

    beforeEach(async () => {
      external = join(await mkdtemp(join(tmpdir(), "dfir-custody-ext-")), "mounted-image.dd");
      await writeFile(external, "external evidence\n", "utf8");
      externalSha = createHash("sha256").update("external evidence\n").digest("hex");
      await store.record("c1", {
        artifactPath: external,
        sha256: externalSha,
        collectedBy: "a",
        collectedAt: "t",
        source: "s",
        trigger: "m",
        caseId: "c1",
      });
    });

    it("stores the absolute path with no case-dir marker", async () => {
      const line = await readFile(join(casesRoot, "c1", "metadata", "custody.jsonl"), "utf8");
      const stored = JSON.parse(line.trim()) as { artifactPath: string; relativeTo?: string };
      expect(stored.artifactPath).toBe(external);
      expect(stored.relativeTo).toBeUndefined();
    });

    it("verifyIntegrity stays clean after the case is archived", async () => {
      await cases.archiveCaseFolder("c1");
      expect(await store.verifyIntegrity("c1")).toEqual([]);
    });
  });

  // custody.jsonl files written before the relative-path change hold absolute paths and no marker.
  it("reads a record written in the pre-existing absolute-path format", async () => {
    const sha = createHash("sha256").update("hello world\n").digest("hex");
    const legacy = {
      artifactPath,
      sha256: sha,
      collectedBy: "a",
      collectedAt: "t",
      source: "s",
      trigger: "m",
      caseId: "c1",
    };
    await mkdir(join(casesRoot, "c1", "metadata"), { recursive: true });
    await appendFile(
      join(casesRoot, "c1", "metadata", "custody.jsonl"),
      JSON.stringify(legacy) + "\n",
      "utf8",
    );
    expect((await store.load("c1"))[0].artifactPath).toBe(artifactPath);
    expect(await store.verifyIntegrity("c1")).toEqual([]);
  });

  it("records multiple entries for the same case", async () => {
    const sha1 = createHash("sha256").update("hello world\n").digest("hex");
    await store.record("c1", {
      artifactPath,
      sha256: sha1,
      collectedBy: "a",
      collectedAt: "t1",
      source: "s",
      trigger: "m",
      caseId: "c1",
    });
    const second = join(cases.importsDir("c1"), "second.log");
    await writeFile(second, "second artifact\n", "utf8");
    const sha2 = createHash("sha256").update("second artifact\n").digest("hex");
    await store.record("c1", {
      artifactPath: second,
      sha256: sha2,
      collectedBy: "b",
      collectedAt: "t2",
      source: "s2",
      trigger: "m2",
      caseId: "c1",
    });
    const list = await store.load("c1");
    expect(list).toHaveLength(2);
    expect(list.map((r) => r.artifactPath)).toEqual([artifactPath, second]);
  });
});
