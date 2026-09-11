import { describe, it, expect, beforeEach } from "vitest";
import { mkdtemp, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { CaseStore } from "../../src/storage/caseStore.js";
import { DropStatusStore } from "../../src/analysis/dropStatus.js";

describe("DropStatusStore", () => {
  let store: DropStatusStore;
  beforeEach(async () => {
    const root = await mkdtemp(join(tmpdir(), "dfir-dropstatus-"));
    const cases = new CaseStore(root);
    await cases.createCase({ caseId: "c1", name: "n", investigator: "i", aiProvider: null });
    store = new DropStatusStore(cases);
  });

  it("returns an empty status when none exists", async () => {
    expect(await store.load("c1")).toEqual({
      lastSweepAt: "",
      dropPath: "",
      importedCount: 0,
      failedCount: 0,
      imported: [],
      failed: [],
      pendingRawInputs: [],
    });
  });

  it("records a sweep (imported + failed) and loads it back", async () => {
    const at = "2026-06-29T12:00:00.000Z";
    await store.record(
      "c1",
      {
        dropPath: "/cases/c1/drop",
        imported: ["triage/prefetch.csv", "events.json"],
        failed: [{ relpath: "broken.bin", reason: "unrecognized file type" }],
      },
      at,
    );
    const s = await store.load("c1");
    expect(s.lastSweepAt).toBe(at);
    expect(s.dropPath).toBe("/cases/c1/drop");
    expect(s.importedCount).toBe(2);
    expect(s.failedCount).toBe(1);
    expect(s.imported).toEqual(["triage/prefetch.csv", "events.json"]);
    expect(s.failed).toEqual([{ relpath: "broken.bin", reason: "unrecognized file type" }]);
  });

  it("clears back to empty", async () => {
    await store.record("c1", { dropPath: "/x", imported: ["a"], failed: [] });
    await store.clear("c1");
    const s = await store.load("c1");
    expect(s.importedCount).toBe(0);
    expect(s.imported).toEqual([]);
    expect(s.lastSweepAt).toBe("");
  });
});

// #919: state/drop-status.json rides inside a whole-case archive and is restored verbatim, so the
// list of "raw files awaiting a tool" is attacker-controlled the moment an untrusted .dfircase is
// imported. POST /cases/:id/drop/run-pending joins each relpath onto drop/ and reads, uploads and
// MOVES the result, so an escaping relpath must never come out of load() at all.
describe("DropStatusStore — pendingRawInputs relpath guard (#919)", () => {
  it("load() drops a pending entry whose relpath escapes the drop folder and keeps the rest", async () => {
    const root = await mkdtemp(join(tmpdir(), "dfir-dropstatus-919-"));
    const cases = new CaseStore(root);
    await cases.createCase({ caseId: "c1", name: "n", investigator: "i", aiProvider: null });
    const poisoned = {
      lastSweepAt: "2026-09-11T00:00:00.000Z",
      dropPath: "/x",
      importedCount: 0,
      failedCount: 0,
      imported: [],
      failed: [],
      pendingRawInputs: [
        { relpath: "../../../../etc/cron.d/pwn", ext: ".evtx", suggestedTool: null, configured: true },
        { relpath: "triage/security.evtx", ext: ".evtx", suggestedTool: null, configured: true },
        { relpath: "C:\\Windows\\win.ini", ext: ".ini", suggestedTool: null, configured: true },
      ],
    };
    await writeFile(join(cases.stateDir("c1"), "drop-status.json"), JSON.stringify(poisoned), "utf8");

    const s = await new DropStatusStore(cases).load("c1");
    expect(s.pendingRawInputs).toEqual([
      { relpath: "triage/security.evtx", ext: ".evtx", suggestedTool: null, configured: true },
    ]);
  });
});
