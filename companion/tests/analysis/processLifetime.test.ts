import { describe, it, expect } from "vitest";
import { readFileSync } from "node:fs";
import { join } from "node:path";
import {
  lifetimeMs,
  processIdentity,
  sacrificialSignal,
  repeatedShortLifetimes,
  unexpectedParentSignal,
  SHORT_LIFETIME_MS,
  markUnexpectedParents,
  type ProcessRecord,
} from "../../src/analysis/processLifetime.js";

const rec = (over: Partial<ProcessRecord> = {}): ProcessRecord => ({
  image: "C:\\Windows\\System32\\rundll32.exe",
  name: "rundll32.exe",
  pid: "4821",
  ppid: "900",
  parentName: "explorer.exe",
  start: "2026-01-01T10:00:00.000Z",
  exit: "2026-01-01T10:00:01.000Z",
  commandLine: "",
  commandLineCaptured: true,
  ...over,
});

describe("lifetimeMs", () => {
  it("measures a recorded lifetime", () => {
    expect(lifetimeMs({ start: "2026-01-01T10:00:00Z", exit: "2026-01-01T10:00:02Z" })).toBe(2000);
  });

  it("returns null when either end was not recorded", () => {
    expect(lifetimeMs({ start: "", exit: "2026-01-01T10:00:02Z" })).toBeNull();
    expect(lifetimeMs({ start: "2026-01-01T10:00:00Z", exit: "" })).toBeNull();
  });

  // Clock disagreement or swapped fields — not evidence of an instant exit.
  it("discards a negative lifetime rather than reporting an instant exit", () => {
    expect(lifetimeMs({ start: "2026-01-01T10:00:05Z", exit: "2026-01-01T10:00:00Z" })).toBeNull();
  });
});

describe("processIdentity — PID alone is not identity", () => {
  it("separates two processes that reused one PID", () => {
    const a = processIdentity({ name: "a.exe", pid: "4821", start: "2026-01-01T10:00:00Z" });
    const b = processIdentity({ name: "b.exe", pid: "4821", start: "2026-01-01T11:00:00Z" });
    expect(a).not.toBe(b);
  });

  it("gives one process the same identity across two tables", () => {
    const r = { name: "a.exe", pid: "4821", start: "2026-01-01T10:00:00Z" };
    expect(processIdentity(r)).toBe(processIdentity({ ...r }));
  });
});

// The distinction the sacrificial rule rests on.
describe("sacrificialSignal — captured-and-empty is not the same as never-captured", () => {
  it("stays silent when no command line was captured", () => {
    const r = rec({ commandLine: "", commandLineCaptured: false });
    expect(sacrificialSignal(r, { shortLived: true })).toBeNull();
  });

  it("reports an argument-free host when the command line WAS captured and something else is odd", () => {
    const s = sacrificialSignal(rec(), { shortLived: true });
    expect(s?.severity).toBe("Medium");
    expect(s?.note).toContain("no arguments");
    expect(s?.note).toContain("exited within seconds");
  });

  // Windows itself starts argument-free hosts. Alone this is a shape, not a lead.
  it("stays silent when nothing else about the process is odd", () => {
    expect(sacrificialSignal(rec(), {})).toBeNull();
  });

  it("treats a command line that only repeats the image as argument-free", () => {
    const r = rec({ commandLine: '"C:\\Windows\\System32\\rundll32.exe"' });
    expect(sacrificialSignal(r, { injectedInto: true })).not.toBeNull();
  });

  it("stays silent when the process actually had work to do", () => {
    const r = rec({ commandLine: "rundll32.exe shell32.dll,Control_RunDLL" });
    expect(sacrificialSignal(r, { shortLived: true, injectedInto: true })).toBeNull();
  });

  it("ignores images that do not need arguments to be useful", () => {
    const r = rec({ name: "notepad.exe", image: "C:\\Windows\\notepad.exe" });
    expect(sacrificialSignal(r, { shortLived: true })).toBeNull();
  });
});

describe("repeatedShortLifetimes", () => {
  const many = (n: number, over: Partial<ProcessRecord> = {}): ProcessRecord[] =>
    Array.from({ length: n }, (_v, i) =>
      rec({
        name: "beacon.exe",
        pid: String(1000 + i),
        start: new Date(Date.parse("2026-01-01T10:00:00Z") + i * 1000).toISOString(),
        exit: new Date(Date.parse("2026-01-01T10:00:00Z") + i * 1000 + 500).toISOString(),
        ...over,
      }),
    );

  it("reports an image spawned and gone repeatedly", () => {
    const [c] = repeatedShortLifetimes(many(15));
    expect(c.name).toBe("beacon.exe");
    expect(c.count).toBe(15);
    expect(c.note).toContain("consistent");
  });

  it("stays under the threshold for a handful of executions", () => {
    expect(repeatedShortLifetimes(many(4))).toEqual([]);
  });

  // Without both ends the lifetime is unknown, and counting those would just count executions.
  it("ignores records with no recorded exit", () => {
    expect(repeatedShortLifetimes(many(20, { exit: "" }))).toEqual([]);
  });

  it("ignores processes that lived longer than the window", () => {
    const long = many(20).map((r) => ({
      ...r,
      exit: new Date(Date.parse(r.start) + SHORT_LIFETIME_MS * 4).toISOString(),
    }));
    expect(repeatedShortLifetimes(long)).toEqual([]);
  });

  // The same process reported by two tables is one process.
  it("counts a duplicated record once", () => {
    const rows = many(15);
    expect(repeatedShortLifetimes([...rows, ...rows])[0].count).toBe(15);
  });
});

describe("unexpectedParentSignal", () => {
  const expected = new Map([["lsass.exe", new Set(["wininit.exe"])]]);

  it("reports a parent that does not ordinarily start this image", () => {
    const r = rec({ name: "lsass.exe", parentName: "winword.exe" });
    expect(unexpectedParentSignal(r, expected)?.note).toContain("started by winword.exe");
  });

  it("says nothing when the parent is the expected one", () => {
    expect(unexpectedParentSignal(rec({ name: "lsass.exe", parentName: "wininit.exe" }), expected)).toBeNull();
  });

  // A missing parent is missing evidence — a snapshot taken after the parent exited looks like this.
  it("does not treat an unrecorded parent as an orphan", () => {
    expect(unexpectedParentSignal(rec({ name: "lsass.exe", parentName: "" }), expected)).toBeNull();
  });

  it("does not flag the shells and service hosts that start almost anything", () => {
    for (const p of ["explorer.exe", "services.exe", "cmd.exe", "svchost.exe"]) {
      expect(unexpectedParentSignal(rec({ name: "lsass.exe", parentName: p }), expected)).toBeNull();
    }
  });

  it("says nothing about an image with no recorded expectation", () => {
    expect(unexpectedParentSignal(rec({ name: "unknown.exe", parentName: "winword.exe" }), expected)).toBeNull();
  });

  it("names no tool family from an executable name", () => {
    const s = unexpectedParentSignal(rec({ name: "lsass.exe", parentName: "winword.exe" }), expected);
    expect(s?.note ?? "").not.toMatch(/cobalt|metasploit|meterpreter|beacon/i);
  });
});

describe("markUnexpectedParents — the timeline pass", () => {
  const ev = (over: Record<string, unknown> = {}) => ({
    description: "Process created: lsass.exe",
    processName: "lsass.exe",
    parentName: "winword.exe",
    severity: "Info" as const,
    ...over,
  });

  it("raises an event whose parent is not the ordinary one", () => {
    const [e] = markUnexpectedParents([ev()]);
    expect(e.severity).toBe("Low");
    expect(e.description).toContain("[unexpected parent:");
    expect(e.description).toContain("winword.exe");
  });

  it("leaves the expected parentage alone", () => {
    const [e] = markUnexpectedParents([ev({ parentName: "wininit.exe" })]);
    expect(e.description).not.toContain("[unexpected parent:");
    expect(e.severity).toBe("Info");
  });

  it("is idempotent — re-running over a marked timeline changes nothing", () => {
    const once = markUnexpectedParents([ev()]);
    const twice = markUnexpectedParents(once);
    expect(twice[0].description).toBe(once[0].description);
    expect(twice[0].description.match(/\[unexpected parent:/g)).toHaveLength(1);
  });

  it("never lowers a severity the event already had", () => {
    const [e] = markUnexpectedParents([ev({ severity: "High" })]);
    expect(e.severity).toBe("High");
  });

  it("does not treat an unrecorded parent as an orphan", () => {
    const [e] = markUnexpectedParents([ev({ parentName: undefined })]);
    expect(e.description).not.toContain("[unexpected parent:");
  });
});

// The reachability check. Two of these three detections shipped as tested exports with no
// production caller at all — green suite, no runtime effect.
describe("reachability — every detection has a production caller", () => {
  const src = (p: string) => readFileSync(join(process.cwd(), p), "utf8");

  it("runs the parent and sacrificial rules from the merge", () => {
    const merge = src("src/analysis/stateMerge.ts");
    expect(merge).toContain("markProcessLifetimeSignals");
  });

  it("runs the repeated-short-lifetime rule from the memory importer", () => {
    // It can only run there: a memory image is the one source that records a process's exit.
    const mem = src("src/analysis/memoryImport.ts");
    expect(mem).toContain("repeatedShortLifetimes(");
  });

  it("strips both markers before correlation keys a duplicate", () => {
    const corr = src("src/analysis/correlate.ts");
    expect(corr).toContain("unexpected parent");
    expect(corr).toContain("sacrificial process");
  });
});
