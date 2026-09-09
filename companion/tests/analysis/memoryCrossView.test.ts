import { describe, it, expect } from "vitest";
import {
  psxviewSignal,
  ldrModulesSignal,
  triState,
  hasPsxviewColumns,
  hasLdrColumns,
} from "../../src/analysis/memoryCrossView.js";
import { parseMemory } from "../../src/analysis/memoryImport.js";

describe("triState — absent is not false", () => {
  it("reads the affirmative forms as true", () => {
    for (const v of [true, "True", "yes", "1", "present"]) expect(triState(v)).toBe(true);
  });

  it("reads the negative forms as false", () => {
    for (const v of [false, "False", "no", "0", "absent"]) expect(triState(v)).toBe(false);
  });

  // Reading an unreadable column as "absent from this list" manufactures the very discrepancy this
  // module exists to find.
  it("reads an unreported column as unknown, never as false", () => {
    for (const v of ["", "-", "N/A", "?", undefined, null]) expect(triState(v)).toBeNull();
  });
});

describe("psxviewSignal", () => {
  const row = (over: Record<string, unknown> = {}) => ({
    PID: 4321,
    Name: "evil.exe",
    pslist: true,
    psscan: true,
    thrdproc: true,
    csrss: true,
    session: true,
    deskthrd: true,
    ...over,
  });

  it("says nothing when every method agrees", () => {
    expect(psxviewSignal(row())).toBeNull();
  });

  it("grades a process missing from two independent methods", () => {
    const s = psxviewSignal(row({ pslist: false, csrss: false }));
    expect(s?.severity).toBe("Medium");
    expect(s?.mitre).toContain("T1014");
    expect(s?.absent).toEqual(["pslist", "csrss"]);
    expect(s?.note).toContain("not found by pslist, csrss");
  });

  it("grades a single dissenting method only as a weak lead", () => {
    expect(psxviewSignal(row({ pslist: false }))?.severity).toBe("Low");
  });

  // An exited process is expected to be gone from the live list and still found by a pool scan.
  it("stays silent for a process that had already exited", () => {
    expect(psxviewSignal(row({ pslist: false, csrss: false, ExitTime: "2026-01-01 10:00:00" }))).toBeNull();
  });

  it("stays silent for early-boot processes that legitimately fail several views", () => {
    expect(psxviewSignal(row({ Name: "System", csrss: false, session: false, deskthrd: false }))).toBeNull();
    expect(psxviewSignal(row({ Name: "smss.exe", csrss: false, deskthrd: false }))).toBeNull();
  });

  it("does not count unreadable columns as absent", () => {
    const s = psxviewSignal(row({ pslist: true, psscan: true, csrss: "-", session: "N/A", deskthrd: "" }));
    expect(s).toBeNull();
  });

  it("names the unreadable columns when it does report", () => {
    const s = psxviewSignal(row({ pslist: false, csrss: false, deskthrd: "-" }));
    expect(s?.unreadable).toContain("deskthrd");
    expect(s?.note).toContain("not reported");
  });

  it("says nothing when fewer than two columns could be read", () => {
    expect(psxviewSignal({ PID: 1, Name: "x.exe", pslist: true })).toBeNull();
  });
});

describe("ldrModulesSignal", () => {
  const row = (over: Record<string, unknown> = {}) => ({
    Pid: 3120,
    Process: "svchost.exe",
    MappedPath: "C:\\Windows\\System32\\ntdll.dll",
    InLoad: true,
    InInit: true,
    InMem: true,
    ...over,
  });

  it("says nothing when the module is in every list", () => {
    expect(ldrModulesSignal(row())).toBeNull();
  });

  it("grades a module mapped but in no loader list at all", () => {
    const s = ldrModulesSignal(row({ InLoad: false, InInit: false, InMem: false }));
    expect(s?.severity).toBe("Medium");
    expect(s?.mitre).toContain("T1055.001");
    expect(s?.note).toContain("none of the loader lists");
  });

  // A resource-only mapping is never initialised, so InInit alone is routine.
  it("stays silent when only InInit is missing", () => {
    expect(ldrModulesSignal(row({ InInit: false }))).toBeNull();
  });

  it("grades a partial membership mismatch as a weak lead", () => {
    const s = ldrModulesSignal(row({ InLoad: false }));
    expect(s?.severity).toBe("Low");
    expect(s?.present).toEqual(["InInit", "InMem"]);
  });

  it("does not count unreadable columns as absent", () => {
    expect(ldrModulesSignal(row({ InLoad: true, InInit: "-", InMem: "N/A" }))).toBeNull();
  });
});

describe("column detection", () => {
  it("recognises the tables it understands and ignores others", () => {
    expect(hasPsxviewColumns({ PID: 1, pslist: true, psscan: false })).toBe(true);
    expect(hasPsxviewColumns({ PID: 1, Name: "x" })).toBe(false);
    expect(hasLdrColumns({ Pid: 1, InLoad: true })).toBe(true);
    expect(hasLdrColumns({ Pid: 1, Base: "0x0" })).toBe(false);
  });
});

describe("wired into the memory importer", () => {
  it("raises a psxview row whose views disagree above the Info floor", () => {
    const rows = [
      { PID: 4321, Name: "evil.exe", pslist: false, psscan: true, thrdproc: true, csrss: false, session: true, deskthrd: true },
      { PID: 900, Name: "explorer.exe", pslist: true, psscan: true, thrdproc: true, csrss: true, session: true, deskthrd: true },
    ];
    const r = parseMemory(JSON.stringify({ "windows.malware.psxview.PsXView": rows }));
    const flagged = r.events.filter((e) => e.severity !== "Info");
    expect(flagged).toHaveLength(1);
    expect(flagged[0].description).toContain("evil.exe");
    expect(flagged[0].description).toContain("cross-view");
    expect(flagged[0].mitreTechniques).toContain("T1014");
  });

  it("surfaces an unlinked module from ldrmodules even though DLL rows are otherwise silent", () => {
    const rows = [
      { Pid: 3120, Process: "svchost.exe", Base: "0x7ffb00000000", InLoad: false, InInit: false, InMem: false, MappedPath: "C:\\Temp\\evil.dll" },
      { Pid: 3120, Process: "svchost.exe", Base: "0x7ffb10000000", InLoad: true, InInit: true, InMem: true, MappedPath: "C:\\Windows\\System32\\ntdll.dll" },
    ];
    const r = parseMemory(JSON.stringify({ "windows.ldrmodules.LdrModules": rows }));
    // The ordinary module stays telemetry; only the unlinked one becomes an event.
    expect(r.events).toHaveLength(1);
    expect(r.events[0].description).toContain("evil.dll");
    expect(r.events[0].severity).toBe("Medium");
  });
});
