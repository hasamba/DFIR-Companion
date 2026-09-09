import { describe, it, expect } from "vitest";
import {
  parseWerReport,
  werSignal,
  werDescription,
  werDedupKey,
  filetimeToIso,
  isWerReport,
} from "../../src/analysis/werImport.js";

// A realistic APPCRASH report. Note the signature block: the meaning of each index is assigned per
// EventType, which is why the parser resolves them by name.
const APPCRASH = `Version=1
EventType=APPCRASH
EventTime=133456789012345678
ReportType=2
Consent=1
ReportIdentifier=8f1c2b3d-4e5f-6789-abcd-ef0123456789
Sig[0].Name=Application Name
Sig[0].Value=rundll32.exe
Sig[1].Name=Application Version
Sig[1].Value=10.0.19041.1
Sig[2].Name=Application Timestamp
Sig[2].Value=5e0eb5c2
Sig[3].Name=Fault Module Name
Sig[3].Value=evil.dll
Sig[4].Name=Fault Module Version
Sig[4].Value=0.0.0.0
Sig[6].Name=Exception Code
Sig[6].Value=c0000005
Sig[7].Name=Exception Offset
Sig[7].Value=000000000004d4e2
LoadedModule[0]=C:\\Windows\\System32\\rundll32.exe
LoadedModule[1]=C:\\Windows\\SYSTEM32\\ntdll.dll
LoadedModule[2]=C:\\Users\\jdoe\\AppData\\Local\\Temp\\evil.dll
AppPath=C:\\Windows\\System32\\rundll32.exe
TargetProcessId=4821
`;

// A BEX report, where the SAME index carries a different parameter. Reading Sig[3] as "the faulting
// module" is correct for APPCRASH and wrong here.
const BEX = `Version=1
EventType=BEX
EventTime=133456789012345678
Sig[0].Name=Application Name
Sig[0].Value=iexplore.exe
Sig[3].Name=Fault Module Name
Sig[3].Value=flash.ocx
Sig[4].Name=Fault Module Version
Sig[4].Value=1.0.0.0
Sig[5].Name=Fault Module Offset
Sig[5].Value=0001b2c3
Sig[6].Name=Exception Offset
Sig[6].Value=0001b2c3
Sig[7].Name=Exception Code
Sig[7].Value=c0000409
AppPath=C:\\Program Files\\Internet Explorer\\iexplore.exe
`;

describe("filetimeToIso", () => {
  it("converts a FILETIME tick count", () => {
    // 133456789012345678 ticks since 1601.
    expect(filetimeToIso("133456789012345678")).toMatch(/^\d{4}-\d{2}-\d{2}T/);
  });

  it("rejects the zero date rather than emitting 1601", () => {
    expect(filetimeToIso("0")).toBe("");
    expect(filetimeToIso("000000000000000000")).toBe("");
  });

  it("rejects values that are not tick counts", () => {
    for (const v of ["", "N/A", "2026-01-01", "abc", "12345"]) expect(filetimeToIso(v)).toBe("");
  });
});

describe("parseWerReport", () => {
  it("reads an APPCRASH report", () => {
    const r = parseWerReport(APPCRASH)!;
    expect(r.eventType).toBe("APPCRASH");
    expect(r.appName).toBe("rundll32.exe");
    expect(r.appPath).toBe("C:\\Windows\\System32\\rundll32.exe");
    expect(r.faultModuleName).toBe("evil.dll");
    expect(r.exceptionCode).toBe("c0000005");
    expect(r.reportId).toBe("8f1c2b3d-4e5f-6789-abcd-ef0123456789");
    expect(r.processId).toBe("4821");
    expect(r.time).toMatch(/^\d{4}-/);
  });

  it("resolves the faulting module's full path from the loaded-module list", () => {
    const r = parseWerReport(APPCRASH)!;
    expect(r.faultModulePath).toBe("C:\\Users\\jdoe\\AppData\\Local\\Temp\\evil.dll");
    expect(r.loadedModules).toHaveLength(3);
  });

  // The whole reason parameters are resolved by name.
  it("reads the same parameters correctly when the EventType reorders them", () => {
    const r = parseWerReport(BEX)!;
    expect(r.eventType).toBe("BEX");
    expect(r.faultModuleName).toBe("flash.ocx");
    // In BEX the exception code is at index 7, not 6. Reading by index would have returned the offset.
    expect(r.exceptionCode).toBe("c0000409");
  });

  it("survives a UTF-16 byte-order mark on the first line", () => {
    expect(parseWerReport("\ufeff" + APPCRASH)?.eventType).toBe("APPCRASH");
  });

  it("reports no hashes when the report carried none", () => {
    expect(parseWerReport(APPCRASH)!.hashes).toEqual([]);
  });

  it("returns null for text that is not a report", () => {
    expect(parseWerReport("")).toBeNull();
    expect(parseWerReport("hello world")).toBeNull();
  });
});

describe("isWerReport", () => {
  it("recognises a report and ignores an unrelated ini file", () => {
    expect(isWerReport(APPCRASH)).toBe(true);
    expect(isWerReport("[Settings]\nVersion=1\nTheme=dark\n")).toBe(false);
  });
});

describe("werSignal — the crash is not the finding", () => {
  it("stays silent for an ordinary application crash", () => {
    const r = parseWerReport(BEX)!;
    expect(werSignal(r)).toBeNull();
  });

  it("grades a crash whose faulting module ran from a user-writable location", () => {
    const s = werSignal(parseWerReport(APPCRASH)!);
    expect(s?.severity).toBe("Medium");
    expect(s?.reason).toContain("faulting module");
    expect(s?.reason).toContain("does not show exploitation");
  });

  it("grades a crashed binary running from a temp directory", () => {
    const r = parseWerReport(
      APPCRASH.replace(
        "AppPath=C:\\Windows\\System32\\rundll32.exe",
        "AppPath=C:\\Windows\\Temp\\svchost.exe",
      ),
    )!;
    expect(werSignal(r)?.reason).toContain("crashed binary");
  });

  it("does not escalate a crash in Program Files", () => {
    expect(werSignal({ ...parseWerReport(APPCRASH)!, appPath: "C:\\Program Files\\App\\a.exe", faultModulePath: "C:\\Windows\\System32\\ntdll.dll" })).toBeNull();
  });
});

describe("werDescription", () => {
  it("names what crashed, where, and what faulted it", () => {
    const d = werDescription(parseWerReport(APPCRASH)!);
    expect(d).toContain("rundll32.exe");
    expect(d).toContain("faulted in evil.dll");
    expect(d).toContain("exception c0000005");
    expect(d).toContain("3 loaded module(s)");
  });
});

// Windows records one crash three times: Application Error 1000, WER 1001, and the report on disk.
describe("werDedupKey", () => {
  it("gives the same key to records sharing a report identifier", () => {
    const fromFile = werDedupKey(parseWerReport(APPCRASH)!);
    const fromEvent = werDedupKey({ reportId: "8F1C2B3D-4E5F-6789-ABCD-EF0123456789" });
    expect(fromEvent).toBe(fromFile);
  });

  it("falls back to application and time when no identifier was recorded", () => {
    const a = werDedupKey({ appName: "x.exe", time: "2026-01-01T00:00:00Z" });
    const b = werDedupKey({ appName: "X.EXE", time: "2026-01-01T00:00:00Z" });
    expect(a).toBe(b);
  });

  it("keeps two different crashes apart", () => {
    expect(werDedupKey({ reportId: "a" })).not.toBe(werDedupKey({ reportId: "b" }));
  });
});
