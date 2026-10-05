import { describe, it, expect } from "vitest";
import { mkdtemp, mkdir, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { priorVeloImport } from "../../src/routes/veloPriorImport.js";

// #1965: the "already pulled into this case" check reads the case's import audit log
// (metadata/imports.jsonl). Each Velociraptor artifact import appends one line whose originalName is
// `velo-hunt_<huntId>_<artifact>.json` or `velo-flow_<flowId>_<artifact>.json`.

async function storeWith(lines: string[] | null) {
  const root = await mkdtemp(join(tmpdir(), "dfir-velo-prior-"));
  const logPath = join(root, "imports.jsonl");
  if (lines) {
    await mkdir(root, { recursive: true });
    await writeFile(logPath, lines.join("\n") + "\n", "utf8");
  }
  return { importsLogPath: () => logPath };
}

const line = (originalName: string, importedAt: string) => JSON.stringify({ originalName, importedAt });

describe("priorVeloImport (#1965)", () => {
  it("returns null when the case has no import log yet", async () => {
    const store = await storeWith(null);
    expect(await priorVeloImport(store, "c1", { kind: "hunt", huntId: "H.ABC" })).toBeNull();
  });

  it("returns null when nothing in the log came from this hunt", async () => {
    const store = await storeWith([line("evidence.csv", "2026-10-01T00:00:00.000Z")]);
    expect(await priorVeloImport(store, "c1", { kind: "hunt", huntId: "H.ABC" })).toBeNull();
  });

  it("summarises a prior hunt import: first and last date, distinct artifacts", async () => {
    const store = await storeWith([
      line("velo-hunt_H.ABC_Windows.NTFS.MFT.json", "2026-10-02T10:00:00.000Z"),
      line("velo-hunt_H.ABC_Windows.System.Pslist.json", "2026-10-01T09:00:00.000Z"),
      line("velo-hunt_H.ABC_Windows.NTFS.MFT.json", "2026-10-03T08:00:00.000Z"),
    ]);
    expect(await priorVeloImport(store, "c1", { kind: "hunt", huntId: "H.ABC" })).toEqual({
      kind: "hunt",
      huntId: "H.ABC",
      firstImportedAt: "2026-10-01T09:00:00.000Z",
      lastImportedAt: "2026-10-03T08:00:00.000Z",
      artifacts: ["Windows.NTFS.MFT", "Windows.System.Pslist"],
    });
  });

  it("matches the whole id: H.AB is not H.ABC", async () => {
    const store = await storeWith([
      line("velo-hunt_H.ABC_Windows.NTFS.MFT.json", "2026-10-01T00:00:00.000Z"),
    ]);
    expect(await priorVeloImport(store, "c1", { kind: "hunt", huntId: "H.AB" })).toBeNull();
  });

  it("skips malformed and partial lines", async () => {
    const store = await storeWith([
      "{not json",
      JSON.stringify({ importedAt: "2026-10-01T00:00:00.000Z" }),
      JSON.stringify({ originalName: "velo-hunt_H.ABC_A.json" }),
      line("velo-hunt_H.ABC_B.json", "2026-10-01T00:00:00.000Z"),
    ]);
    const prior = await priorVeloImport(store, "c1", { kind: "hunt", huntId: "H.ABC" });
    expect(prior?.artifacts).toEqual(["B"]);
  });

  it("keys a flow on its flow id", async () => {
    const store = await storeWith([
      line("velo-flow_F.XY_Windows.NTFS.MFT.json", "2026-10-01T00:00:00.000Z"),
      line("velo-hunt_F.XY_Other.json", "2026-10-01T00:00:00.000Z"),
    ]);
    expect(await priorVeloImport(store, "c1", { kind: "flow", clientId: "C.1", flowId: "F.XY" })).toEqual({
      kind: "flow",
      clientId: "C.1",
      flowId: "F.XY",
      firstImportedAt: "2026-10-01T00:00:00.000Z",
      lastImportedAt: "2026-10-01T00:00:00.000Z",
      artifacts: ["Windows.NTFS.MFT"],
    });
  });

  it("does not take a hunt's uploads label for its rows", async () => {
    const store = await storeWith([line("velo-hunt-uploads_H.ABC", "2026-10-01T00:00:00.000Z")]);
    expect(await priorVeloImport(store, "c1", { kind: "hunt", huntId: "H.ABC" })).toBeNull();
  });
});
