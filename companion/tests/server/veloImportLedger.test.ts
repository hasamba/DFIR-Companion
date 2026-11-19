import { describe, it, expect } from "vitest";
import { mkdtemp, mkdir, readFile, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import {
  clearVeloImportLedger,
  readVeloLedger,
  recordVeloArtifact,
  veloLedgerKey,
  type LedgerEntry,
} from "../../src/routes/veloImportLedger.js";

// #2700: per case, per hunt or flow, per artifact — what the last import got.

async function store() {
  const dir = await mkdtemp(join(tmpdir(), "dfir-velo-ledger-"));
  return { dir, metadataDir: () => dir };
}

const entry = (over: Partial<LedgerEntry> = {}): LedgerEntry => ({
  importedAt: "2026-11-19T10:00:00.000Z",
  status: "complete",
  rows: 5,
  fingerprint: "abc",
  superOnly: false,
  minSeverity: "",
  ...over,
});

describe("veloLedgerKey", () => {
  it("namespaces by server and keys a flow on client and flow id", () => {
    const hunt = veloLedgerKey("cfg.yaml|root", { kind: "hunt", huntId: "H.A" });
    expect(hunt).toMatch(/^[0-9a-f]{16}\|hunt:H\.A$/);
    expect(veloLedgerKey("other.yaml|root", { kind: "hunt", huntId: "H.A" })).not.toBe(hunt);
    expect(veloLedgerKey("cfg.yaml|org2", { kind: "hunt", huntId: "H.A" })).not.toBe(hunt);
    expect(veloLedgerKey("cfg.yaml|root", { kind: "flow", clientId: "C.1", flowId: "F.X" })).toMatch(
      /\|flow:C\.1\/F\.X$/,
    );
  });
});

describe("veloImportLedger", () => {
  it("is empty for a case with no ledger", async () => {
    const s = await store();
    expect(await readVeloLedger(s, "c1", "k")).toEqual({});
  });

  it("records artifacts per source and overwrites an artifact's entry", async () => {
    const s = await store();
    await recordVeloArtifact(s, "c1", "k1", "A", entry({ status: "pending" }));
    await recordVeloArtifact(s, "c1", "k1", "B", entry());
    await recordVeloArtifact(s, "c1", "k2", "A", entry({ rows: 9 }));
    await recordVeloArtifact(s, "c1", "k1", "A", entry({ rows: 7 }));
    expect(await readVeloLedger(s, "c1", "k1")).toEqual({ A: entry({ rows: 7 }), B: entry() });
    expect((await readVeloLedger(s, "c1", "k2")).A.rows).toBe(9);
  });

  it("serialises concurrent writes so none is lost", async () => {
    const s = await store();
    await Promise.all(["A", "B", "C", "D"].map((a) => recordVeloArtifact(s, "c1", "k", a, entry())));
    expect(Object.keys(await readVeloLedger(s, "c1", "k")).sort()).toEqual(["A", "B", "C", "D"]);
  });

  it("reads a corrupt or wrong-shaped file as empty (everything looks stale, never up to date)", async () => {
    const s = await store();
    await mkdir(s.dir, { recursive: true });
    await writeFile(join(s.dir, "velo-import-ledger.json"), "{not json", "utf8");
    expect(await readVeloLedger(s, "c1", "k")).toEqual({});
    await writeFile(
      join(s.dir, "velo-import-ledger.json"),
      JSON.stringify({ version: 1, sources: { k: { A: { status: "complete" } } } }),
      "utf8",
    );
    expect(await readVeloLedger(s, "c1", "k")).toEqual({});
  });

  it("a write after a corrupt file starts a fresh ledger", async () => {
    const s = await store();
    await writeFile(join(s.dir, "velo-import-ledger.json"), "{not json", "utf8");
    await recordVeloArtifact(s, "c1", "k", "A", entry());
    expect(JSON.parse(await readFile(join(s.dir, "velo-import-ledger.json"), "utf8")).version).toBe(1);
  });

  it("clear forgets every source, and clearing a missing ledger is fine", async () => {
    const s = await store();
    await clearVeloImportLedger(s, "c1");
    await recordVeloArtifact(s, "c1", "k", "A", entry());
    await clearVeloImportLedger(s, "c1");
    expect(await readVeloLedger(s, "c1", "k")).toEqual({});
  });
});
