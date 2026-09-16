// #1108: the durable, coverage-tracked collection-generation ledger. Real CaseStore-shaped
// fixtures throughout — a real imports.jsonl row and a real stored Velociraptor JSON file — so the
// re-parse-and-validate path in record() is exercised authentically, not stubbed.
import { describe, it, expect, beforeEach } from "vitest";
import { mkdtemp, mkdir, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { CollectionGenerationStore } from "../../src/analysis/collectionGenerationStore.js";
import { buildHostAliasIndex } from "../../src/analysis/hostAlias.js";

let dir = "";
const cases = {
  stateDir: () => dir,
  importsLogPath: () => join(dir, "imports.jsonl"),
  importsDir: () => join(dir, "imports"),
} as unknown as ConstructorParameters<typeof CollectionGenerationStore>[0];

const ACTOR = { id: "u1", displayName: "J. Analyst" };

const PERSISTENCE_ROWS = [
  {
    Hostname: "WS-01",
    Technique: "Run Key",
    Classification: "Suspicious",
    Path: "HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Run\\Updater",
    Value: "C:\\Users\\a\\AppData\\Local\\Temp\\updater.exe",
    "Access Gained": "User",
  },
  {
    Hostname: "WS-01",
    Technique: "Scheduled Task",
    Classification: "Clean",
    Path: "\\Microsoft\\Windows\\UpdateOrchestrator\\Reboot",
    Value: "C:\\Windows\\System32\\UsoClient.exe",
    "Access Gained": "System",
  },
];

// A fleet-hunt upload can combine several machines' rows in one artifact (Codex code-review
// finding H1) — this fixture pairs a WS-01 row with a WS-02 row in the SAME stored file.
const MULTI_HOST_ROWS = [
  PERSISTENCE_ROWS[0],
  {
    Hostname: "WS-02",
    Technique: "Run Key",
    Classification: "Suspicious",
    Path: "HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Run\\Other",
    Value: "C:\\Temp\\other.exe",
    "Access Gained": "User",
  },
];

const NON_PERSISTENCE_ROWS = [{ Name: "chrome.exe", Pid: 1234, Ppid: 1 }];

async function seedImport(seq: number, filename: string, rows: unknown[]): Promise<void> {
  await mkdir(join(dir, "imports"), { recursive: true });
  await writeFile(join(dir, "imports", filename), JSON.stringify(rows), "utf8");
  const line =
    JSON.stringify({
      caseId: "c1",
      sequenceNumber: seq,
      importedAt: "2026-01-12T10:00:00Z",
      filename,
      originalName: filename,
      rows: rows.length,
      bytes: JSON.stringify(rows).length,
    }) + "\n";
  await writeFile(join(dir, "imports.jsonl"), line, { flag: "a" });
}

beforeEach(async () => {
  dir = await mkdtemp(join(tmpdir(), "collection-generation-"));
});

describe("CollectionGenerationStore.record", () => {
  it("records a generation, freezing the persistence inventory from the raw stored file", async () => {
    await seedImport(1, "0001_persistencesniper.json", PERSISTENCE_ROWS);
    const store = new CollectionGenerationStore(cases);

    const generation = await store.record("c1", {
      rawHost: "WS-01",
      domain: "persistence",
      order: { kind: "captured", capturedAt: "2026-01-12T10:00:00Z" },
      importSeq: 1,
      completenessState: "complete",
      recordedBy: ACTOR,
    });

    expect(generation.inventory).toHaveLength(2);
    expect(generation.inventory[0]).toEqual({
      technique: "Run Key",
      path: "HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Run\\Updater",
      value: "C:\\Users\\a\\AppData\\Local\\Temp\\updater.exe",
    });
    expect(generation.artifactRef.importSeq).toBe(1);
    expect(generation.artifactRef.artifactHash).toMatch(/^[0-9a-f]{64}$/);
    expect(generation.recordedBy).toEqual(ACTOR);
    expect(await store.active("c1")).toHaveLength(1);
  });

  it("rejects a domain with zero matching rows in the referenced import — never records an empty generation", async () => {
    await seedImport(1, "0001_pslist.json", NON_PERSISTENCE_ROWS);
    const store = new CollectionGenerationStore(cases);

    await expect(
      store.record("c1", {
        rawHost: "WS-01",
        domain: "persistence",
        order: { kind: "captured", capturedAt: "2026-01-12T10:00:00Z" },
        importSeq: 1,
        completenessState: "complete",
        recordedBy: ACTOR,
      }),
    ).rejects.toThrow(/no rows matching domain/);
  });

  it("rejects an import sequence that does not exist", async () => {
    const store = new CollectionGenerationStore(cases);
    await expect(
      store.record("c1", {
        rawHost: "WS-01",
        domain: "persistence",
        order: { kind: "captured", capturedAt: "2026-01-12T10:00:00Z" },
        importSeq: 99,
        completenessState: "complete",
        recordedBy: ACTOR,
      }),
    ).rejects.toThrow(/does not exist/);
  });

  it("rejects an ambiguous import sequence — fails closed rather than picking one (#1119's own gap)", async () => {
    await mkdir(join(dir, "imports"), { recursive: true });
    await writeFile(join(dir, "imports", "0001_a.json"), JSON.stringify(PERSISTENCE_ROWS), "utf8");
    const dupLine =
      JSON.stringify({
        caseId: "c1",
        sequenceNumber: 1,
        importedAt: "2026-01-12T10:00:00Z",
        filename: "0001_a.json",
        originalName: "a.json",
        rows: 2,
        bytes: 10,
      }) + "\n";
    await writeFile(join(dir, "imports.jsonl"), dupLine + dupLine, "utf8");
    const store = new CollectionGenerationStore(cases);
    await expect(
      store.record("c1", {
        rawHost: "WS-01",
        domain: "persistence",
        order: { kind: "captured", capturedAt: "2026-01-12T10:00:00Z" },
        importSeq: 1,
        completenessState: "complete",
        recordedBy: ACTOR,
      }),
    ).rejects.toThrow(/ambiguous/);
  });

  it("rejects a duplicate declared sequence within the same (rawHost, domain) cohort", async () => {
    await seedImport(1, "0001_a.json", PERSISTENCE_ROWS);
    await seedImport(2, "0002_b.json", PERSISTENCE_ROWS);
    const store = new CollectionGenerationStore(cases);
    await store.record("c1", {
      rawHost: "WS-01",
      domain: "persistence",
      order: { kind: "declared", sequence: 1 },
      importSeq: 1,
      completenessState: "complete",
      recordedBy: ACTOR,
    });
    await expect(
      store.record("c1", {
        rawHost: "WS-01",
        domain: "persistence",
        order: { kind: "declared", sequence: 1 },
        importSeq: 2,
        completenessState: "complete",
        recordedBy: ACTOR,
      }),
    ).rejects.toThrow(/already exists/);
  });

  it("allows the same declared sequence for a DIFFERENT host — cohorts are per-host", async () => {
    await seedImport(1, "0001_a.json", PERSISTENCE_ROWS);
    await seedImport(
      2,
      "0002_b.json",
      PERSISTENCE_ROWS.map((r) => ({ ...r, Hostname: "WS-02" })),
    );
    const store = new CollectionGenerationStore(cases);
    await store.record("c1", {
      rawHost: "WS-01",
      domain: "persistence",
      order: { kind: "declared", sequence: 1 },
      importSeq: 1,
      completenessState: "complete",
      recordedBy: ACTOR,
    });
    await expect(
      store.record("c1", {
        rawHost: "WS-02",
        domain: "persistence",
        order: { kind: "declared", sequence: 1 },
        importSeq: 2,
        completenessState: "complete",
        recordedBy: ACTOR,
      }),
    ).resolves.toBeTruthy();
  });

  it("freezes only the rows belonging to the requested host — a fleet-hunt upload never contaminates another host's generation", async () => {
    await seedImport(1, "0001_hunt.json", MULTI_HOST_ROWS);
    const store = new CollectionGenerationStore(cases);
    const generation = await store.record("c1", {
      rawHost: "WS-01",
      domain: "persistence",
      order: { kind: "captured", capturedAt: "2026-01-12T10:00:00Z" },
      importSeq: 1,
      completenessState: "complete",
      recordedBy: ACTOR,
    });
    expect(generation.inventory).toHaveLength(1);
    expect(generation.inventory[0].path).toBe(PERSISTENCE_ROWS[0].Path);
  });

  it("resolves both sides through the CURRENT alias index — a differently-spelled duplicate collides", async () => {
    await seedImport(1, "0001_a.json", PERSISTENCE_ROWS);
    await seedImport(2, "0002_b.json", PERSISTENCE_ROWS);
    const aliasIndex = buildHostAliasIndex([{ hostname: "ws-01", fqdn: "WS-01" }], {});
    const store = new CollectionGenerationStore(cases);
    await store.record("c1", {
      rawHost: "WS-01",
      domain: "persistence",
      order: { kind: "declared", sequence: 1 },
      importSeq: 1,
      completenessState: "complete",
      recordedBy: ACTOR,
      aliasIndex,
    });
    await expect(
      store.record("c1", {
        rawHost: "ws-01",
        domain: "persistence",
        order: { kind: "declared", sequence: 1 },
        importSeq: 2,
        completenessState: "complete",
        recordedBy: ACTOR,
        aliasIndex,
      }),
    ).rejects.toThrow(/already exists/);
  });

  it("a revoked generation's own declared sequence no longer blocks its correction", async () => {
    await seedImport(1, "0001_a.json", PERSISTENCE_ROWS);
    await seedImport(2, "0002_b.json", PERSISTENCE_ROWS);
    const store = new CollectionGenerationStore(cases);
    const first = await store.record("c1", {
      rawHost: "WS-01",
      domain: "persistence",
      order: { kind: "declared", sequence: 1 },
      importSeq: 1,
      completenessState: "complete",
      recordedBy: ACTOR,
    });
    await store.revoke("c1", first.generationId, ACTOR, "2026-01-13T00:00:00Z");
    await expect(
      store.record("c1", {
        rawHost: "WS-01",
        domain: "persistence",
        order: { kind: "declared", sequence: 1 },
        importSeq: 2,
        completenessState: "complete",
        recordedBy: ACTOR,
      }),
    ).resolves.toBeTruthy();
  });
});

describe("CollectionGenerationStore.verifyArtifact", () => {
  it("ok when the stored artifact is unchanged", async () => {
    await seedImport(1, "0001_a.json", PERSISTENCE_ROWS);
    const store = new CollectionGenerationStore(cases);
    const generation = await store.record("c1", {
      rawHost: "WS-01",
      domain: "persistence",
      order: { kind: "captured", capturedAt: "2026-01-12T10:00:00Z" },
      importSeq: 1,
      completenessState: "complete",
      recordedBy: ACTOR,
    });
    expect(await store.verifyArtifact("c1", generation.generationId)).toEqual({ ok: true });
  });

  it("detects a changed artifact — the frozen hash no longer matches", async () => {
    await seedImport(1, "0001_a.json", PERSISTENCE_ROWS);
    const store = new CollectionGenerationStore(cases);
    const generation = await store.record("c1", {
      rawHost: "WS-01",
      domain: "persistence",
      order: { kind: "captured", capturedAt: "2026-01-12T10:00:00Z" },
      importSeq: 1,
      completenessState: "complete",
      recordedBy: ACTOR,
    });
    await writeFile(join(dir, "imports", "0001_a.json"), JSON.stringify([{ tampered: true }]), "utf8");
    const result = await store.verifyArtifact("c1", generation.generationId);
    expect(result.ok).toBe(false);
    expect(result.reason).toMatch(/changed/);
  });

  it("reports not-found for an unknown generation id", async () => {
    const store = new CollectionGenerationStore(cases);
    expect(await store.verifyArtifact("c1", "nonexistent")).toEqual({
      ok: false,
      reason: "generation not found",
    });
  });
});

describe("CollectionGenerationStore.revoke", () => {
  it("marks a generation revoked and it drops out of active() but stays in all()", async () => {
    await seedImport(1, "0001_a.json", PERSISTENCE_ROWS);
    const store = new CollectionGenerationStore(cases);
    const generation = await store.record("c1", {
      rawHost: "WS-01",
      domain: "persistence",
      order: { kind: "captured", capturedAt: "2026-01-12T10:00:00Z" },
      importSeq: 1,
      completenessState: "complete",
      recordedBy: ACTOR,
    });

    await store.revoke("c1", generation.generationId, ACTOR, "2026-01-13T00:00:00Z");
    expect(await store.active("c1")).toHaveLength(0);
    expect(await store.all("c1")).toHaveLength(1);
    expect((await store.all("c1"))[0].revokedAt).toBe("2026-01-13T00:00:00Z");
  });

  it("is a no-op for an unknown generation id", async () => {
    const store = new CollectionGenerationStore(cases);
    const result = await store.revoke("c1", "nonexistent", ACTOR, "2026-01-13T00:00:00Z");
    expect(result).toEqual([]);
  });

  it("is a no-op for an already-revoked generation", async () => {
    await seedImport(1, "0001_a.json", PERSISTENCE_ROWS);
    const store = new CollectionGenerationStore(cases);
    const generation = await store.record("c1", {
      rawHost: "WS-01",
      domain: "persistence",
      order: { kind: "captured", capturedAt: "2026-01-12T10:00:00Z" },
      importSeq: 1,
      completenessState: "complete",
      recordedBy: ACTOR,
    });
    await store.revoke("c1", generation.generationId, ACTOR, "2026-01-13T00:00:00Z");
    const secondRevoke = await store.revoke("c1", generation.generationId, ACTOR, "2026-01-14T00:00:00Z");
    expect(secondRevoke[0].revokedAt).toBe("2026-01-13T00:00:00Z");
  });
});

describe("CollectionGenerationStore.load", () => {
  it("returns an empty list when the file does not exist", async () => {
    const store = new CollectionGenerationStore(cases);
    expect(await store.load("c1")).toEqual([]);
  });

  it("fails closed on a corrupt file rather than silently returning empty", async () => {
    await mkdir(dir, { recursive: true });
    await writeFile(join(dir, "collection-generations.json"), "{not json", "utf8");
    const store = new CollectionGenerationStore(cases);
    await expect(store.load("c1")).rejects.toThrow(/not valid JSON/);
  });
});
