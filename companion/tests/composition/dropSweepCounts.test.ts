import { describe, it, expect } from "vitest";
import { join } from "node:path";
import { readdir, readFile, writeFile } from "node:fs/promises";
import type { NotificationEvent } from "../../src/analysis/notifications.js";
import {
  noteBatchCounts,
  runDropSweep,
  sweepCounts,
  tallyCounts,
  type DropOutcome,
  type SweepTally,
} from "../../src/composition/dropBatch.js";
import type { DropFileStat } from "../../src/analysis/dropScan.js";
import { notifyDropSweep } from "../../src/composition/dropImportNotify.js";
import { HUNT_ZIP_LEDGER_DIR } from "../../src/composition/dropHuntZipLedger.js";
import { buildZip, huntTree } from "../helpers/huntExportFixture.js";
import { makeHarness } from "../helpers/dropHuntHarness.js";

// #2982: a drop-folder sweep's "import finished" message carries the events its imports added and
// how many are High/Critical — the settled counts of every finished evidence file, summed. A finished
// file that returned no counts makes the total unknown: the message never states a silently low sum.
// Synthetic data only.

const UNAVAILABLE = "Event counts are not available for this import";
const THOR = (file: string) =>
  JSON.stringify({
    level: "Warning",
    module: "Filescan",
    message: "Suspicious file",
    time: "2026-05-02T10:00:00Z",
    file,
  });

function emptyTally(): SweepTally {
  return { imported: [], submitted: [], failed: [], warned: [], pendingRawInputs: [], counts: [] };
}

function sent(tally: Partial<SweepTally>): NotificationEvent {
  const out: NotificationEvent[] = [];
  notifyDropSweep((e) => void out.push(e), "c1", { ...emptyTally(), ...tally });
  return out[0];
}

describe("the sweep tally's counts (#2982)", () => {
  it("sums known counts, and one unknown makes the total unknown instead of reading it as zero", () => {
    const tally = emptyTally();
    tallyCounts(tally, { added: 3, highCritical: 1 });
    tallyCounts(tally, { added: 2, highCritical: 0, superAdded: 7 });
    expect(sweepCounts(tally.counts)).toEqual({ added: 5, highCritical: 1, superAdded: 7 });
    tallyCounts(tally, undefined);
    expect(sweepCounts(tally.counts)).toBeUndefined();
  });

  it("no finished import is no total", () => {
    expect(sweepCounts([])).toBeUndefined();
    expect(sweepCounts(undefined)).toBeUndefined();
  });

  it("counts a batch once, whatever its file count", () => {
    const tally = emptyTally();
    const ok = (relpath: string) => ({ relpath, ok: true });
    noteBatchCounts(tally, { results: [ok("a.gz"), ok("b.gz")], counts: { added: 4, highCritical: 2 } });
    expect(tally.counts).toEqual([{ added: 4, highCritical: 2 }]);
  });

  it("a batch whose settle returned no counts is unknown; one that imported nothing adds nothing", () => {
    const tally = emptyTally();
    noteBatchCounts(tally, { results: [{ relpath: "a.gz", ok: false, reason: "x" }] });
    expect(tally.counts).toEqual([]);
    noteBatchCounts(tally, { results: [{ relpath: "a.gz", ok: true }] });
    expect(tally.counts).toEqual([null]);
  });
});

describe("which outcomes the sweep counts (#2982)", () => {
  it("only a finished evidence file: not a screenshot, a submitted, deferred, pending or failed one", async () => {
    const outcomes: Record<string, DropOutcome> = {
      "a.json": { ok: true, counts: { added: 2, highCritical: 1 } },
      "shot.png": { ok: true },
      "cap.pcap": { ok: true, submitted: "handed to a tool" },
      "hunt.zip": { ok: false, deferred: "resumes next sweep" },
      "raw.evtx": { ok: false, pending: { relpath: "raw.evtx", ext: ".evtx", configured: false } as never },
      "bad.json": { ok: false, reason: "unrecognized" },
    };
    const files = Object.keys(outcomes).map((relpath): DropFileStat => ({ relpath, size: 10, mtimeMs: 1 }));
    const tally = await runDropSweep(files, {
      caseId: "c1",
      dropDir: "/nonexistent-drop",
      processFile: async (f) => outcomes[f.relpath],
      moveDropFile: async () => undefined,
      forget: () => undefined,
      progress: () => undefined,
      resolveImportKind: () => "unknown",
      recordImportFailure: () => undefined,
    });
    expect(tally.imported.sort()).toEqual(["a.json", "cap.pcap", "shot.png"]);
    expect(tally.counts).toEqual([{ added: 2, highCritical: 1 }]);
  });

  it("a finished evidence file without counts makes the sweep's total unknown", async () => {
    const files = ["a.json", "b.json"].map((relpath) => ({ relpath, size: 10, mtimeMs: 1 }));
    const tally = await runDropSweep(files, {
      caseId: "c1",
      dropDir: "/nonexistent-drop",
      processFile: async (f) =>
        f.relpath === "a.json" ? { ok: true, counts: { added: 2, highCritical: 0 } } : { ok: true },
      moveDropFile: async () => undefined,
      forget: () => undefined,
      progress: () => undefined,
      resolveImportKind: () => "unknown",
      recordImportFailure: () => undefined,
    });
    expect(sweepCounts(tally.counts)).toBeUndefined();
  });
});

describe("the drop-folder message (#2982)", () => {
  it("states the summed counts when every finished file returned them", () => {
    const counts = [
      { added: 3, highCritical: 2 },
      { added: 2, highCritical: 0 },
    ];
    const e = sent({ imported: ["a.json", "b.json"], counts });
    expect(e.lines).toContain("Forensic timeline: +5 events (2 High/Critical)");
    expect(e.lines).not.toContain(UNAVAILABLE);
    expect(e.severity).toBe("High");
  });

  it("keeps 'not available' when any finished file returned no counts", () => {
    const e = sent({ imported: ["a.json", "b.json"], counts: [{ added: 5, highCritical: 2 }, null] });
    expect(e.lines).toContain(UNAVAILABLE);
    expect(e.lines.some((l) => l.startsWith("Forensic timeline:"))).toBe(false);
  });

  it("sends nothing for a sweep that only submitted a file to an HTTP tool (#3004)", () => {
    expect(
      sent({ imported: ["cap.pcap"], submitted: [{ relpath: "cap.pcap", reason: "handed" }] }),
    ).toBeUndefined();
  });

  it("leaves a submitted file out of a mixed sweep's file count and counts (#3004)", () => {
    const e = sent({
      imported: ["a.json", "cap.pcap"],
      submitted: [{ relpath: "cap.pcap", reason: "handed" }],
      counts: [{ added: 4, highCritical: 1 }],
    });
    expect(e.title).toContain("(1 file)");
    expect(e.lines).toContain("Forensic timeline: +4 events (1 High/Critical)");
  });
});

describe("a drop sweep end to end (#2982)", () => {
  it("sums each dropped file's settled counts", async () => {
    const h = await makeHarness();
    await writeFile(join(h.dropDir, "thor-high.json"), THOR("C:\\Temp\\a.exe"));
    await writeFile(join(h.dropDir, "thor.json"), THOR("C:\\Temp\\b.exe"));
    await h.sweep();
    await h.sweep();
    expect(h.calls).toHaveLength(2);
    expect(h.notified).toHaveLength(1);
    expect(h.notified[0].lines).toContain("Forensic timeline: +2 events (1 High/Critical)");
  });

  it("a hunt zip reports the counts of every result file it imported", async () => {
    const h = await makeHarness();
    await writeFile(join(h.dropDir, "hunt.zip"), await buildZip(huntTree("perClientJson")));
    await h.sweep();
    await h.sweep();
    expect(h.calls).toHaveLength(9);
    expect(h.notified.at(-1)?.lines).toContain("Forensic timeline: +9 events (0 High/Critical)");
  });

  it("a hunt zip resumed after a crash still counts the files imported before it", async () => {
    const h = await makeHarness();
    await writeFile(join(h.dropDir, "hunt.zip"), await buildZip(huntTree("perClientJson")));
    await h.sweep();
    h.hangAfter = 4;
    await h.sweepUntilHang();
    h.restart();
    await h.sweep();
    await h.sweep();
    expect(h.notified.at(-1)?.lines).toContain("Forensic timeline: +9 events (0 High/Critical)");
  });

  it("a hunt zip resumed from a progress file with no counts reports them as not available", async () => {
    const h = await makeHarness();
    await writeFile(join(h.dropDir, "hunt.zip"), await buildZip(huntTree("perClientJson")));
    await h.sweep();
    h.hangAfter = 4;
    await h.sweepUntilHang();
    // A progress file written before #2982 records no counts for the members it names.
    const dir = join(h.store.stateDir("c1"), HUNT_ZIP_LEDGER_DIR);
    for (const name of await readdir(dir)) {
      const text = await readFile(join(dir, name), "utf8");
      const lines = text.split("\n").map((l) => {
        if (!l.trim()) return l;
        const { counts: _drop, ...rest } = JSON.parse(l) as Record<string, unknown>;
        return JSON.stringify(rest);
      });
      await writeFile(join(dir, name), lines.join("\n"));
    }
    h.restart();
    await h.sweep();
    await h.sweep();
    expect(h.calls).toHaveLength(9);
    expect(h.notified.at(-1)?.lines).toContain(UNAVAILABLE);
  });
});
