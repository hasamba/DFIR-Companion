import { describe, it, expect } from "vitest";
import { mkdtemp, readFile, writeFile, mkdir } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { CaseStore } from "../../src/storage/caseStore.js";
import {
  exportEncryptedCase,
  importEncryptedCase,
  CaseImportConflictError,
} from "../../src/analysis/caseExportArchive.js";
import { createZip } from "../../src/analysis/zipArchive.js";
import { encryptBuffer, DecryptionError } from "../../src/analysis/caseEncryption.js";

const PASSWORD = "correct horse battery staple";

async function harness() {
  const root = await mkdtemp(join(tmpdir(), "dfir-cea-"));
  return new CaseStore(root);
}

async function seedCase(store: CaseStore, caseId: string) {
  await store.createCase({ caseId, name: "Case One", investigator: "alice", aiProvider: "anthropic" });
  await store.saveScreenshot(caseId, "shot-001.webp", Buffer.from([0x52, 0x49, 0x46, 0x46, 1, 2, 3]));
  await store.appendCapture(caseId, {
    caseId, sequenceNumber: 1, timestamp: "2026-01-01T00:00:00Z", url: "https://example.com",
    tabTitle: "t", triggerType: "navigation", contentHash: "abc", isDuplicate: false, screenshotFile: "shot-001.webp",
  });
  await store.saveImport(caseId, "thor-001.json", JSON.stringify({ hits: [] }));
  await store.appendImport(caseId, {
    caseId, sequenceNumber: 1, importedAt: "2026-01-01T00:00:00Z", filename: "thor-001.json",
    originalName: "thor.json", rows: 0, bytes: 12,
  });
  await mkdir(store.stateDir(caseId), { recursive: true });
  await writeFile(
    join(store.stateDir(caseId), "investigation.json"),
    JSON.stringify({ caseId, findings: [{ id: "f1" }], iocs: [{ id: "i1" }], forensicTimeline: [{ id: "e1" }, { id: "e2" }] }),
    "utf8",
  );
}

describe("exportEncryptedCase", () => {
  it("throws for a case that does not exist", async () => {
    const store = await harness();
    await expect(exportEncryptedCase(store, "ghost", PASSWORD)).rejects.toThrow(/does not exist/);
  });

  it("produces a non-empty encrypted buffer for an existing case", async () => {
    const store = await harness();
    await seedCase(store, "INC-1");
    const archive = await exportEncryptedCase(store, "INC-1", PASSWORD);
    expect(archive.length).toBeGreaterThan(0);
  });
});

describe("importEncryptedCase", () => {
  it("imports under a target id, preserving evidence bytes exactly", async () => {
    const store = await harness();
    await seedCase(store, "INC-1");
    const archive = await exportEncryptedCase(store, "INC-1", PASSWORD);

    const { meta, counts } = await importEncryptedCase(store, archive, PASSWORD, { targetCaseId: "INC-2" });
    expect(meta.caseId).toBe("INC-2");
    expect(counts).toEqual({ forensicEvents: 2, findings: 1, iocs: 1, captures: 1, imports: 1 });

    // screenshot bytes travelled unchanged
    const original = await readFile(join(store.screenshotsDir("INC-1"), "shot-001.webp"));
    const restored = await readFile(join(store.screenshotsDir("INC-2"), "shot-001.webp"));
    expect(restored.equals(original)).toBe(true);

    // raw import file travelled unchanged
    const originalImport = await readFile(join(store.importsDir("INC-1"), "thor-001.json"));
    const restoredImport = await readFile(join(store.importsDir("INC-2"), "thor-001.json"));
    expect(restoredImport.equals(originalImport)).toBe(true);

    // caseId-bearing files were rewritten to the new id
    const invRestored = JSON.parse(await readFile(join(store.stateDir("INC-2"), "investigation.json"), "utf8"));
    expect(invRestored.caseId).toBe("INC-2");
    const capturesRestored = (await readFile(store.capturesLogPath("INC-2"), "utf8")).trim().split("\n").map((l) => JSON.parse(l));
    expect(capturesRestored[0].caseId).toBe("INC-2");
    const importsRestored = (await readFile(store.importsLogPath("INC-2"), "utf8")).trim().split("\n").map((l) => JSON.parse(l));
    expect(importsRestored[0].caseId).toBe("INC-2");
  });

  it("imports under the archive's own id into a fresh store when no target is given", async () => {
    const store1 = await harness();
    await seedCase(store1, "INC-1");
    const archive = await exportEncryptedCase(store1, "INC-1", PASSWORD);

    const store2 = await harness(); // a separate cases root where INC-1 is free
    const { meta } = await importEncryptedCase(store2, archive, PASSWORD);
    expect(meta.caseId).toBe("INC-1");
    expect(await store2.caseExists("INC-1")).toBe(true);
  });

  it("throws CaseImportConflictError when the target case already exists", async () => {
    const store = await harness();
    await seedCase(store, "INC-1");
    const archive = await exportEncryptedCase(store, "INC-1", PASSWORD);
    await expect(importEncryptedCase(store, archive, PASSWORD)).rejects.toThrow(CaseImportConflictError);
  });

  it("throws DecryptionError on the wrong password", async () => {
    const store = await harness();
    await seedCase(store, "INC-1");
    const archive = await exportEncryptedCase(store, "INC-1", PASSWORD);
    await expect(importEncryptedCase(store, archive, "totally-wrong-password", { targetCaseId: "INC-2" }))
      .rejects.toThrow(DecryptionError);
  });

  it("rejects an archive with an unsafe (path-traversal) entry and writes nothing", async () => {
    const store = await harness();
    await seedCase(store, "INC-1"); // gives us a valid case.json to reuse
    const caseJson = await readFile(store.caseMetaPath("INC-1"));
    const malicious = createZip([
      { path: "case.json", data: caseJson },
      { path: "../../evil.txt", data: Buffer.from("pwned") },
    ]);
    const archive = encryptBuffer(malicious, PASSWORD);

    await expect(importEncryptedCase(store, archive, PASSWORD, { targetCaseId: "INC-EVIL" }))
      .rejects.toThrow(/unsafe entry path/);
    expect(await store.caseExists("INC-EVIL")).toBe(false);
  });

  it("throws on an archive missing case.json", async () => {
    const store = await harness();
    const archive = encryptBuffer(createZip([{ path: "state/investigation.json", data: Buffer.from("{}") }]), PASSWORD);
    await expect(importEncryptedCase(store, archive, PASSWORD)).rejects.toThrow(/missing case\.json/);
  });
});
