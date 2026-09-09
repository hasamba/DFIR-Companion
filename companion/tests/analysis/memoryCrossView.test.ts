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

  // Published Volatility output shows ordinary lsass.exe / rundll32.exe / svchost.exe rows with
  // deskthrd alone false. Tagging each of those T1014 marks routine processes as rootkit leads.
  it("says nothing when only one method dissents", () => {
    expect(psxviewSignal(row({ pslist: false }))).toBeNull();
    expect(psxviewSignal(row({ deskthrd: false }))).toBeNull();
  });

  // An exited process is expected to be gone from the live list and still found by a pool scan.
  it("stays silent for a process that had already exited", () => {
    expect(psxviewSignal(row({ pslist: false, csrss: false, ExitTime: "2026-01-01 10:00:00" }))).toBeNull();
  });

  // Volatility 3 spells it with a space. Reading only the V2 name graded every terminated process
  // in a V3 capture as a hidden one.
  it("recognises the Volatility 3 spelling of the exit column", () => {
    expect(psxviewSignal(row({ pslist: false, csrss: false, "Exit Time": "2026-01-01 10:00:00" }))).toBeNull();
  });

  // Treating any non-empty value as proof of termination let junk suppress a real finding.
  it("does not accept a sentinel or unparsable exit value as proof of termination", () => {
    for (const v of ["N/A", "-", "0001-01-01 00:00:00", "1601-01-01 00:00:00", "garbage"]) {
      expect(psxviewSignal(row({ pslist: false, csrss: false, ExitTime: v }))).not.toBeNull();
    }
  });

  it("excuses only the views an early-boot process legitimately fails", () => {
    expect(psxviewSignal(row({ PID: 4, Name: "System", csrss: false, session: false, deskthrd: false }))).toBeNull();
    expect(psxviewSignal(row({ Name: "smss.exe", csrss: false, deskthrd: false }))).toBeNull();
  });

  // Exempting these names from the WHOLE detection was a one-line evasion: name a process
  // smss.exe, unlink it from pslist, and nothing is reported.
  it("still reports an early-boot name that is missing from views it cannot excuse", () => {
    const s = psxviewSignal(row({ Name: "smss.exe", pslist: false, psscan: false }));
    expect(s?.absent).toEqual(["pslist", "psscan"]);
  });

  it("gives the System name no exemption unless it is really PID 4", () => {
    expect(
      psxviewSignal(row({ PID: 6123, Name: "System", csrss: false, session: false, deskthrd: false })),
    ).not.toBeNull();
  });

  it("reads the Volatility 2 pspcid column", () => {
    const s = psxviewSignal(row({ pspcid: false, psscan: false }));
    expect(s?.absent).toContain("pspcid");
  });

  it("accepts Volatility 2 --apply-rules wording", () => {
    expect(triState("Okay")).toBe(true);
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

  it("grades an unbacked mapping in no loader list at all", () => {
    const s = ldrModulesSignal(row({ InLoad: false, InInit: false, InMem: false, MappedPath: "" }));
    expect(s?.severity).toBe("Medium");
    expect(s?.mitre).toContain("T1055.001");
    expect(s?.note).toContain("no backing file");
  });

  // A clean host maps localized .mui resources with LOAD_LIBRARY_AS_DATAFILE, so they are false in
  // all three lists. Grading those as injection tags routine localization as an attack.
  it("stays silent for a resource mapping that is false in every list", () => {
    const s = ldrModulesSignal(
      row({
        InLoad: false,
        InInit: false,
        InMem: false,
        MappedPath: "\\Windows\\System32\\pt-BR\\winsrv.dll.mui",
      }),
    );
    expect(s).toBeNull();
  });

  it("grades a file-backed module in no loader list only as a weak lead", () => {
    const s = ldrModulesSignal(row({ InLoad: false, InInit: false, InMem: false }));
    expect(s?.severity).toBe("Low");
  });

  // A resource-only mapping is never initialised, so InInit alone is routine.
  it("stays silent when only InInit is missing", () => {
    expect(ldrModulesSignal(row({ InInit: false }))).toBeNull();
  });

  it("says nothing when only one list dissents", () => {
    expect(ldrModulesSignal(row({ InLoad: false }))).toBeNull();
  });

  it("grades two dissenting lists as a weak lead", () => {
    const s = ldrModulesSignal(row({ InLoad: false, InMem: false }));
    expect(s?.severity).toBe("Low");
    expect(s?.present).toEqual(["InInit"]);
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
      { PID: 4321, Name: "evil.exe", pslist: false, psscan: true, thrdproc: true, pspcid: true, csrss: false, session: true, deskthrd: true },
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
      { Pid: 3120, Process: "svchost.exe", Base: "0x7ffb00000000", InLoad: false, InInit: false, InMem: false, MappedPath: "" },
      { Pid: 3120, Process: "svchost.exe", Base: "0x7ffb10000000", InLoad: true, InInit: true, InMem: true, MappedPath: "C:\\Windows\\System32\\ntdll.dll" },
    ];
    const r = parseMemory(JSON.stringify({ "windows.ldrmodules.LdrModules": rows }));
    // The ordinary module stays telemetry; only the unlinked one becomes an event.
    expect(r.events).toHaveLength(1);
    expect(r.events[0].description).toContain("no backing file");
    expect(r.events[0].severity).toBe("Medium");
  });
});

describe("repeated short lifetimes, end to end through the memory importer", () => {
  const burst = (n: number) =>
    Array.from({ length: n }, (_v, i) => ({
      PID: 1000 + i,
      ImageFileName: "beacon.exe",
      CreateTime: new Date(Date.parse("2026-01-01T10:00:00Z") + i * 1000).toISOString(),
      ExitTime: new Date(Date.parse("2026-01-01T10:00:00Z") + i * 1000 + 400).toISOString(),
      PPID: 900,
    }));

  it("emits one clustered event, not one per execution", () => {
    const r = parseMemory(JSON.stringify({ "windows.pslist.PsList": burst(15) }));
    const clusters = r.events.filter((e) => /started and exited within/.test(e.description));
    expect(clusters).toHaveLength(1);
    expect(clusters[0].description).toContain("beacon.exe");
    expect(clusters[0].description).toContain("15 times");
  });

  it("says nothing when the executions are too few", () => {
    const r = parseMemory(JSON.stringify({ "windows.pslist.PsList": burst(3) }));
    expect(r.events.some((e) => /started and exited within/.test(e.description))).toBe(false);
  });

  it("says nothing when the rows carry no exit time", () => {
    const rows = burst(20).map(({ ExitTime: _drop, ...rest }) => rest);
    const r = parseMemory(JSON.stringify({ "windows.pslist.PsList": rows }));
    expect(r.events.some((e) => /started and exited within/.test(e.description))).toBe(false);
  });
});
