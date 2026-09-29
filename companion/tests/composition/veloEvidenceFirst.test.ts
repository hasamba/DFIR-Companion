// Evidence first, then the import section (#1874) — the helpers the Velociraptor hunt collect and
// external ingest use to store what they fetched before the memory guard can refuse the import.
import { describe, it, expect } from "vitest";
import { mkdtemp, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import {
  evidenceSizeHint,
  planUploads,
  storeHuntArtifacts,
  storeUploads,
  utf8Bytes,
  HUNT_REFUSAL_WORDING,
} from "../../src/composition/veloEvidenceFirst.js";
import { IMPORT_INPUT_BYTES_PER_EVENT } from "../../src/analysis/importMemoryGuard.js";

const upload = (name: string, content = "{}") => ({ name, clientId: "C.1", content });

describe("evidenceSizeHint", () => {
  it("gives no hint when there is nothing to import, so a no-op is never refused", () => {
    expect(evidenceSizeHint({ rows: 0, bytes: 0 }, HUNT_REFUSAL_WORDING)).toBeUndefined();
    expect(evidenceSizeHint({ bytes: 0 }, HUNT_REFUSAL_WORDING)).toBeUndefined();
  });

  it("counts rows exactly and adds uploads at the guard's bytes-per-event figure", () => {
    const hint = evidenceSizeHint(
      { rows: 10, bytes: IMPORT_INPUT_BYTES_PER_EVENT * 3 + 1 },
      HUNT_REFUSAL_WORDING,
    );
    expect(hint).toEqual({ incomingEvents: 14, wording: HUNT_REFUSAL_WORDING });
  });

  it("sizes by bytes when the row count is unknown", () => {
    expect(evidenceSizeHint({ bytes: 5000 }, HUNT_REFUSAL_WORDING)).toEqual({
      incomingBytes: 5000,
      wording: HUNT_REFUSAL_WORDING,
    });
  });
});

describe("utf8Bytes", () => {
  it("counts UTF-8 bytes, not UTF-16 code units", () => {
    expect(utf8Bytes(["é", "ab"])).toBe(4);
  });
});

describe("planUploads", () => {
  const kinds: Record<string, string> = { "a.json": "thor", "b.bin": "unknown", "c.csv": "csv" };
  const deps = (ai: boolean, superOnly = false) => ({
    resolveImportKind: (name: string) => kinds[name] ?? "unknown",
    aiEnabled: async () => ai,
    superOnly,
    logLine: () => {},
  });

  it("skips unknown kinds, and CSV/log while AI is off", async () => {
    const { planned, skipped } = await planUploads(
      [upload("a.json"), upload("b.bin"), upload("c.csv")],
      deps(false),
    );
    expect(planned.map((p) => [p.up.name, p.kind])).toEqual([["a.json", "thor"]]);
    expect(skipped).toEqual(["b.bin", "c.csv"]);
  });

  it("keeps CSV/log when AI is on", async () => {
    const { planned } = await planUploads([upload("c.csv")], deps(true));
    expect(planned.map((p) => p.kind)).toEqual(["csv"]);
  });

  it("skips every upload of a super-only hunt", async () => {
    const { planned, skipped } = await planUploads([upload("a.json")], deps(true, true));
    expect(planned).toEqual([]);
    expect(skipped).toEqual(["a.json"]);
  });
});

describe("storing before the section", () => {
  it("stores each hunt artifact under its usual name, one at a time, with its own recorder", async () => {
    const dir = await mkdtemp(join(tmpdir(), "dfir-velo-ev-"));
    const files = [
      { name: "A.One", file: join(dir, "0_A.json"), rows: 1 },
      { name: "B.Two", file: join(dir, "1_B.json"), rows: 2 },
    ];
    for (const f of files) await writeFile(f.file, JSON.stringify({ [f.name]: [] }), "utf8");
    const calls: string[] = [];
    let inFlight = 0;
    const persist = async (_caseId: string, name: string, text: string) => {
      calls.push(`${name}:${text.length}`);
      inFlight++;
      expect(inFlight).toBe(1); // never two artifacts' text held by the store at once
      inFlight--;
      return { storedName: `000${calls.length}_${name}`, importedAt: "t", seq: calls.length };
    };
    const attempts: unknown[] = [];
    const stored = await storeHuntArtifacts(persist, "c1", "H.X", files, (d) => attempts.push(d));
    expect(calls.map((c) => c.split(":")[0])).toEqual([
      "velo-hunt_H.X_A.One.json",
      "velo-hunt_H.X_B.Two.json",
    ]);
    expect(stored.map((s) => [s.name, s.seq, s.rows])).toEqual([
      ["A.One", 1, 1],
      ["B.Two", 2, 2],
    ]);
    expect(attempts).toHaveLength(2);
    expect(stored[0].debug).toBe(attempts[0]);
  });

  it("leaves an upload whose store fails out of the import, and reports it", async () => {
    const { planned } = await planUploads([upload("a.json"), upload("b.json")], {
      resolveImportKind: () => "thor",
      aiEnabled: async () => true,
      logLine: () => {},
    });
    const failed: string[] = [];
    const stored = await storeUploads(
      async (_c, name) => {
        if (name === "a.json") throw new Error("disk full");
        return { storedName: `0001_${name}`, importedAt: "t", seq: 1 };
      },
      "c1",
      planned,
      (p) => failed.push(p.up.name),
    );
    expect(stored.map((s) => s.up.name)).toEqual(["b.json"]);
    expect(failed).toEqual(["a.json"]);
  });
});
