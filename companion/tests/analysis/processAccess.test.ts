// #932 item 9 — what one ProcessAccess / CreateRemoteThread / ProcessTampering record establishes.
import { describe, expect, it } from "vitest";
import {
  decodeAccessMask,
  GUIDS_NOTE,
  HANDLE_READ_NOTE,
  HANDLE_WRITE_NOTE,
  processOverlay,
  readCallTrace,
  readStart,
  type OverlayInput,
} from "../../src/analysis/processAccess.js";

const LSASS = "C:\\Windows\\System32\\lsass.exe";
const CHROME = "C:\\Program Files\\Google\\Chrome\\Application\\chrome.exe";
const MIMI = "C:\\Users\\bob\\AppData\\Local\\Temp\\mimikatz.exe";
const DEFENDER = "C:\\ProgramData\\Microsoft\\Windows Defender\\Platform\\4.18\\MsMpEng.exe";
const CSRSS = "C:\\Windows\\System32\\csrss.exe";
const MASQ = "C:\\Users\\Public\\csrss.exe";
const G1 = "{11111111-1111-1111-1111-111111111111}";
const G2 = "{22222222-2222-2222-2222-222222222222}";

function overlay(kind: OverlayInput["kind"], ed: Record<string, string>, over: Partial<OverlayInput> = {}) {
  return processOverlay({
    kind,
    field: (k) => ed[k] ?? "",
    has: (k) => k in ed,
    description: `Sysmon ${kind} (EID x)`,
    severity: kind === "tamper" ? "High" : kind === "thread" ? "Low" : "Info",
    mitre: kind === "tamper" ? ["T1055.012"] : [],
    recordId: "4242",
    row: 7,
    ...over,
  });
}
const access = (source: string, target: string, rights: string, extra: Record<string, string> = {}) =>
  overlay("procaccess", {
    SourceProcessGuid: G1,
    SourceProcessId: "1001",
    SourceImage: source,
    TargetProcessGuid: G2,
    TargetProcessId: "612",
    TargetImage: target,
    GrantedAccess: rights,
    ...extra,
  });
const thread = (source: string, target: string, extra: Record<string, string> = {}) =>
  overlay("thread", {
    SourceProcessGuid: G1,
    SourceProcessId: "1001",
    SourceImage: source,
    TargetProcessGuid: G2,
    TargetProcessId: "612",
    TargetImage: target,
    ...extra,
  });

describe("decodeAccessMask — the rights by bit, never by alias", () => {
  it("names the bits of the common masks; ALL_ACCESS is a display alias over expanded bits", () => {
    expect(decodeAccessMask("0x1010").rights).toEqual(["VM_READ", "QUERY_LIMITED_INFORMATION"]);
    expect(decodeAccessMask("0x1410").rights).toEqual([
      "VM_READ",
      "QUERY_INFORMATION",
      "QUERY_LIMITED_INFORMATION",
    ]);
    expect(decodeAccessMask("0x143A").rights).toEqual([
      "CREATE_THREAD",
      "VM_OPERATION",
      "VM_READ",
      "VM_WRITE",
      "QUERY_INFORMATION",
      "QUERY_LIMITED_INFORMATION",
    ]);
    expect(decodeAccessMask("0x40").rights).toEqual(["DUP_HANDLE"]);
    expect(decodeAccessMask("0x2").rights).toEqual(["CREATE_THREAD"]);
    const all = decodeAccessMask("0x1FFFFF");
    expect(all.rights).toContain("VM_WRITE");
    expect(all.rights).toContain("DUP_HANDLE");
    expect(all.rights).toContain("SYNCHRONIZE");
    expect(decodeAccessMask("0x1F0FFF").rights).toContain("VM_WRITE");
    expect(decodeAccessMask("4112")).toMatchObject({ bits: 0x1010, readable: true });
  });
  it("keeps a bit outside the table as hex and reports an unreadable value", () => {
    expect(decodeAccessMask("0x400010")).toMatchObject({ rights: ["VM_READ"], unknown: "0x400000" });
    for (const bad of ["0x", "garbage", "", "-1", "0x1FFFFFFFF"])
      expect(decodeAccessMask(bad), String(bad)).toMatchObject({ readable: false, state: "unreadable" });
    expect(decodeAccessMask(undefined)).toMatchObject({ readable: false, state: "absent" });
  });
});

describe("readCallTrace / readStart — tri-state fields", () => {
  it("a trace: absent, system-only, an UNKNOWN frame, a foreign module, bounded", () => {
    expect(readCallTrace(undefined).state).toBe("absent");
    const sys = readCallTrace(
      "C:\\Windows\\SYSTEM32\\ntdll.dll+9d5a4|C:\\Windows\\System32\\KERNELBASE.dll+2ac2e",
    );
    expect(sys).toMatchObject({ state: "value", unbacked: 0, firstForeign: "" });
    const unk = readCallTrace(
      "C:\\Windows\\SYSTEM32\\ntdll.dll+9d5a4|UNKNOWN(000001A2B3C4D5E6)|C:\\Windows\\System32\\KERNELBASE.dll+2ac2e",
    );
    expect(unk.unbacked).toBe(1);
    const foreign = readCallTrace("C:\\Windows\\SYSTEM32\\ntdll.dll+9d5a4|C:\\Users\\bob\\tool.dll+1234");
    expect(foreign.firstForeign).toBe("C:\\Users\\bob\\tool.dll");
    const many = readCallTrace(
      Array.from({ length: 40 }, (_, i) => `C:\\Windows\\System32\\m${i}.dll+1`).join("|"),
    );
    expect(many.frames).toHaveLength(32);
    // an UNKNOWN frame past the retained cap still counts — evidence is read over the whole trace
    const late = readCallTrace(
      `${Array.from({ length: 32 }, (_, i) => `C:\\Windows\\System32\\m${i}.dll+1`).join("|")}|UNKNOWN(0000000012345678)`,
    );
    expect(late.unbacked).toBe(1);
    expect(late.frames).toHaveLength(32);
  });
  it("a start: absent from the record, '-' / empty / UNKNOWN (outside any module), or a module", () => {
    expect(readStart({}).state).toBe("absent");
    expect(readStart({ module: "-", address: "0x1A2B" })).toMatchObject({
      state: "unbacked",
      address: "0x1A2B",
    });
    expect(readStart({ module: "" }).state).toBe("unbacked");
    expect(readStart({ module: "UNKNOWN" }).state).toBe("unbacked");
    expect(
      readStart({ module: "C:\\Windows\\System32\\KERNEL32.DLL", function: "LoadLibraryW" }),
    ).toMatchObject({
      state: "module",
      function: "LoadLibraryW",
    });
    expect(readStart({ module: "C:\\Windows\\System32\\ntdll.dll", function: "-" }).function).toBe("");
  });
});

describe("processOverlay — ProcessAccess (Sysmon 10): the record's own evidence first", () => {
  it("lsass read from a non-system path: High + T1003.001, the rights and the qualifier in words", () => {
    const o = access(MIMI, LSASS, "0x1010");
    expect(o.severity).toBe("High");
    expect(o.mitre).toEqual(["T1003.001"]);
    expect(o.description).toBe(
      `Sysmon procaccess (EID x) — opens lsass.exe with VM_READ|QUERY_LIMITED_INFORMATION (0x1010) from mimikatz.exe — ${HANDLE_READ_NOTE}`,
    );
    expect(o.type).toBe("access");
    expect(o.identity).toBe(
      "|access:vm_read,query_limited_information|src:11111111-1111-1111-1111-111111111111|dst:22222222-2222-2222-2222-222222222222|0:",
    );
  });
  it("the ONE trust exception: a benign accessor's routine read of lsass with a backed or absent trace → Low, no technique", () => {
    for (const src of [DEFENDER, CSRSS]) {
      expect(access(src, LSASS, "0x1010").severity, src).toBe("Low");
      expect(access(src, LSASS, "0x1010").mitre, src).toEqual([]);
      expect(access(src, LSASS, "0x1410").severity, src).toBe("Low");
      const backed = access(src, LSASS, "0x1010", { CallTrace: "C:\\Windows\\SYSTEM32\\ntdll.dll+9d5a4" });
      expect(backed.severity, src).toBe("Low");
      expect(backed.description).toContain("routine read by a system-path accessor");
    }
  });
  it("trust never lowers a capability: ALL_ACCESS, DUP_HANDLE, CREATE_THREAD, VM_WRITE, a stray bit or an unknown bit", () => {
    for (const src of [DEFENDER, CSRSS]) {
      expect(access(src, LSASS, "0x1FFFFF").severity, `${src} all`).toBe("High");
      expect(access(src, LSASS, "0x1FFFFF").mitre).toEqual(["T1003.001"]);
      expect(access(src, LSASS, "0x40").severity, `${src} dup`).toBe("High");
      expect(access(src, LSASS, "0x2").severity, `${src} thread`).toBe("High");
      expect(access(src, LSASS, "0x20").severity, `${src} write`).toBe("High");
      expect(access(src, LSASS, "0x11").severity, `${src} read+terminate`).toBe("High");
      expect(access(src, LSASS, "0x810").severity, `${src} read+suspend`).toBe("High");
      expect(access(src, LSASS, "0x40010").severity, `${src} read+write_dac`).toBe("High");
      expect(access(src, LSASS, "0x400010").severity, `${src} read+unknown`).toBe("High");
      expect(access(src, CHROME, "0x1FFFFF").severity, `${src} chrome all`).toBe("Medium");
      expect(access(src, CHROME, "0x40").severity, `${src} chrome dup`).toBe("Medium");
    }
  });
  it("an unbacked frame past the retained cap still grades a trusted lsass read High", () => {
    const trace = `${Array.from({ length: 32 }, (_, i) => `C:\\Windows\\System32\\m${i}.dll+1`).join("|")}|UNKNOWN(0000000012345678)`;
    expect(access(CSRSS, LSASS, "0x1010", { CallTrace: trace }).severity).toBe("High");
  });
  it("a nested lookalike of a system path, or a core name under Program Files, never borrows trust", () => {
    const nested = "C:\\Staging\\Windows\\System32\\svchost.exe";
    expect(access(nested, LSASS, "0x1010").severity).toBe("High");
    expect(thread(nested, CHROME, { StartModule: "C:\\Windows\\System32\\ntdll.dll" }).severity).toBe("High");
    const programFiles = "C:\\Program Files\\Acme\\svchost.exe";
    expect(access(programFiles, LSASS, "0x1010").severity).toBe("High");
    expect(access(programFiles, LSASS, "0x1010").mitre).toEqual(["T1003.001"]);
    expect(thread(programFiles, CHROME, { StartModule: "C:\\Windows\\System32\\ntdll.dll" }).severity).toBe(
      "Medium",
    );
    // …while Defender's own names keep their Program Files / ProgramData homes
    expect(access("C:\\Program Files\\Windows Defender\\MsMpEng.exe", LSASS, "0x1010").severity).toBe("Low");
  });
  it("the key carries the record's evidence: rights tri-state and the first foreign module, so distinct evidence never folds", () => {
    const base = {
      SourceProcessGuid: G1,
      SourceProcessId: "1001",
      SourceImage: MIMI,
      TargetProcessGuid: G2,
      TargetProcessId: "612",
      TargetImage: LSASS,
    };
    const absent = overlay("procaccess", base);
    const garbage = overlay("procaccess", { ...base, GrantedAccess: "garbage" });
    expect(absent.identity).toContain("|access:absent|");
    expect(garbage.identity).toContain("|access:unreadable|");
    const sys = access(MIMI, CHROME, "0x1010", { CallTrace: "C:\\Windows\\SYSTEM32\\ntdll.dll+9d5a4" });
    const evil = access(MIMI, CHROME, "0x1010", {
      CallTrace: "C:\\Windows\\SYSTEM32\\ntdll.dll+9d5a4|C:\\Users\\Public\\evil.dll+1",
    });
    expect(sys.identity).not.toBe(evil.identity);
    expect(evil.description).toContain("via evil.dll");
  });
  it("an unbacked frame in the call trace is High whatever the rights or the source", () => {
    const o = access(CSRSS, CHROME, "0x1000", {
      CallTrace: "C:\\Windows\\SYSTEM32\\ntdll.dll+9d5a4|UNKNOWN(00007FF6)",
    });
    expect(o.severity).toBe("High");
    expect(o.mitre).toEqual([]);
    expect(o.description).toContain("call trace has 1 unbacked frame");
    expect(o.identity).toMatch(/\|1:$/);
  });
  it("a masqueraded benign name from a user path is not trusted — and on another target it raises", () => {
    expect(access(MASQ, LSASS, "0x1010").severity).toBe("High");
    const m = access(MASQ, CHROME, "0x1010");
    expect(m.severity).toBe("High");
    expect(m.mitre).toEqual([]);
    expect(m.description).toContain("a system process name from a non-system path");
    expect(access(MASQ, CHROME, "0x1000").severity).toBe("Info"); // a query-only handle stays telemetry
  });
  it("lsass: unreadable rights → Medium no technique; rights absent → the source context decides; query-only → Low; other rights → Medium", () => {
    const unreadable = access(MIMI, LSASS, "garbage");
    expect(unreadable.severity).toBe("Medium");
    expect(unreadable.mitre).toEqual([]);
    expect(unreadable.description).toContain("rights not readable");
    // a feed that drops GrantedAccess: absence is not garbage — the source context decides
    const absentEvil = overlay("procaccess", { SourceImage: MIMI, TargetImage: LSASS });
    expect(absentEvil.severity).toBe("High");
    expect(absentEvil.mitre).toEqual(["T1003.001"]);
    expect(absentEvil.description).toContain("rights not in this record");
    const absentBenign = overlay("procaccess", { SourceImage: DEFENDER, TargetImage: LSASS });
    expect(absentBenign.severity).toBe("Low");
    expect(absentBenign.mitre).toEqual([]);
    expect(overlay("procaccess", { SourceImage: MIMI, TargetImage: CHROME }).severity).toBe("Info");
    const query = access(MIMI, LSASS, "0x1000");
    expect(query.severity).toBe("Low");
    expect(query.description).toContain("query-only handle");
    expect(access(MIMI, LSASS, "0x1").severity).toBe("Medium");
  });
  it("any target: write-capable / duplication / thread-creation rights are Medium with the write qualifier; the system path is said, never used", () => {
    const w = access(MIMI, CHROME, "0x3A");
    expect(w.severity).toBe("Medium");
    expect(w.mitre).toEqual([]);
    expect(w.description).toContain("write-capable handle");
    expect(w.description).toContain(HANDLE_WRITE_NOTE);
    const trusted = access(CSRSS, CHROME, "0x3A");
    expect(trusted.severity).toBe("Medium");
    expect(trusted.description).toContain("write-capable handle from a system-path source");
    expect(access(MIMI, CHROME, "0x40").description).toContain(
      "handle-duplication right (can yield full access)",
    );
    expect(access(MIMI, CHROME, "0x2").description).toContain("thread-creation right");
    expect(access(MIMI, CHROME, "0x20").description).toContain("write right");
  });
  it("a read of another process is a lead from a non-system path, telemetry from a system path; query-only is telemetry", () => {
    expect(access(MIMI, CHROME, "0x1010").severity).toBe("Low");
    expect(access(MIMI, CHROME, "0x1010").description).toContain(HANDLE_READ_NOTE);
    expect(access(CSRSS, CHROME, "0x1010").severity).toBe("Info");
    expect(access(MIMI, CHROME, "0x1000").severity).toBe("Info");
    expect(access(MIMI, CHROME, "0x1000").mitre).toEqual([]);
    // rights the table does not name were still granted: a lead, and a masquerade raises on them
    const unknownOnly = access(MIMI, CHROME, "0x40000000");
    expect(unknownOnly.severity).toBe("Low");
    expect(unknownOnly.description).toContain("rights outside the table (0x40000000)");
    expect(access(MASQ, CHROME, "0x40000000").severity).toBe("High");
  });
  it("carries both process identities as entities and in the key; two instances of one image are two", () => {
    const o = access(MIMI, LSASS, "0x1010");
    expect(o.entities.subject).toEqual({
      kind: "process",
      id: "11111111-1111-1111-1111-111111111111",
      name: "mimikatz.exe",
      pid: 1001,
    });
    expect(o.entities.object).toEqual({
      kind: "process",
      id: "22222222-2222-2222-2222-222222222222",
      name: "lsass.exe",
      pid: 612,
    });
    expect(o.process).toEqual({ pid: 612, name: "lsass.exe", executable: LSASS });
    expect(o.rawFields).toMatchObject({
      "subject.id": ["SourceProcessGuid"],
      "object.pid": ["TargetProcessId"],
      "process.pid": ["TargetProcessId"],
      "process.name": ["TargetImage"],
      "process.executable": ["TargetImage"],
    });
    const other = overlay("procaccess", {
      SourceProcessGuid: "{33333333-3333-3333-3333-333333333333}",
      SourceProcessId: "1001",
      SourceImage: MIMI,
      TargetProcessGuid: G2,
      TargetProcessId: "612",
      TargetImage: LSASS,
      GrantedAccess: "0x1010",
    });
    expect(other.identity).not.toBe(o.identity);
  });
  it("a placeholder GUID — all zeros, a dash, malformed — is no GUID: the record fallback keys the row", () => {
    const zero = {
      SourceProcessId: "1001",
      SourceImage: MIMI,
      TargetProcessId: "612",
      TargetImage: LSASS,
      GrantedAccess: "0x10",
      SourceProcessGuid: "{00000000-0000-0000-0000-000000000000}",
      TargetProcessGuid: "{00000000-0000-0000-0000-000000000000}",
    };
    const a = overlay("procaccess", zero, { recordId: "100", row: 1 });
    const b = overlay("procaccess", { ...zero, SourceProcessId: "1002" }, { recordId: "101", row: 2 });
    expect(a.identity).not.toBe(b.identity);
    expect(a.identity).toContain("|src:pid:1001|dst:pid:612|rec:100");
    expect(a.description).toContain(GUIDS_NOTE);
    expect(
      overlay("procaccess", { ...zero, SourceProcessGuid: "-", TargetProcessGuid: "not-a-guid" }).identity,
    ).toContain("|src:pid:1001|");
    // a half-braced GUID is malformed, not a GUID
    const half = overlay("procaccess", {
      ...zero,
      SourceProcessGuid: "{11111111-1111-1111-1111-111111111111",
      TargetProcessGuid: G2,
    });
    expect(half.identity).toContain("|src:pid:1001|");
    expect(half.identity).toContain("|rec:");
  });
  it("GUID-less records key on their own record — reused pids never fold — and say so", () => {
    const ed = {
      SourceProcessId: "1001",
      SourceImage: MIMI,
      TargetProcessId: "612",
      TargetImage: LSASS,
      GrantedAccess: "0x1010",
    };
    const a = overlay("procaccess", ed, { recordId: "100", row: 1 });
    const b = overlay("procaccess", ed, { recordId: "101", row: 2 });
    expect(a.identity).toContain("|src:pid:1001|dst:pid:612|rec:100");
    expect(a.identity).not.toBe(b.identity);
    expect(a.description).toContain(GUIDS_NOTE);
    expect(a.entities.subject).toEqual({ kind: "process", id: "pid:1001", name: "mimikatz.exe", pid: 1001 });
    // no EventRecordID either: the import-local row keys it
    const c = overlay("procaccess", ed, { recordId: "", row: 3 });
    const d = overlay("procaccess", ed, { recordId: "0", row: 4 });
    expect(c.identity).toContain("|rec:row:3");
    expect(d.identity).toContain("|rec:row:4");
    expect(c.identity).not.toBe(d.identity);
  });
});

describe("processOverlay — CreateRemoteThread (Sysmon 8)", () => {
  it("a start outside any module is High + T1055; LoadLibrary is the DLL-injection shape", () => {
    const unb = thread(MIMI, CHROME, { StartModule: "-", StartFunction: "-", StartAddress: "0x1A2B3C" });
    expect(unb.severity).toBe("High");
    expect(unb.mitre).toEqual(["T1055"]);
    expect(unb.description).toContain(
      "creates a thread in chrome.exe from mimikatz.exe starting at 0x1A2B3C — outside any module",
    );
    expect(unb.description).toContain("thread start outside any module");
    expect(unb.identity).toContain("|thread:0x1a2b3c|src:");
    const ll = thread(MIMI, CHROME, {
      StartModule: "C:\\Windows\\System32\\KERNEL32.DLL",
      StartFunction: "LoadLibraryW",
    });
    expect(ll.severity).toBe("High");
    expect(ll.mitre).toEqual(["T1055.001"]);
    expect(ll.description).toContain("starting at C:\\Windows\\System32\\KERNEL32.DLL!LoadLibraryW");
    expect(ll.type).toBe("remote_thread");
  });
  it("a module-backed start is Medium + T1055 from an untrusted source, Low with no technique from a benign one", () => {
    const m = thread("C:\\Users\\bob\\Documents\\tool.exe", CHROME, {
      StartModule: "C:\\Windows\\System32\\ntdll.dll",
      StartFunction: "RtlUserThreadStart",
    });
    expect(m.severity).toBe("Medium");
    expect(m.mitre).toEqual(["T1055"]);
    const b = thread(CSRSS, CHROME, {
      StartModule: "C:\\Windows\\System32\\ntdll.dll",
      StartFunction: "RtlUserThreadStart",
    });
    expect(b.severity).toBe("Low");
    expect(b.mitre).toEqual([]);
    expect(b.description).toContain("routine remote thread from a system-path source");
  });
  it("trust never lowers the record's own signal: a benign source with an unbacked or LoadLibrary start keeps High", () => {
    expect(thread(CSRSS, CHROME, { StartModule: "-" }).severity).toBe("High");
    expect(
      thread(DEFENDER, CHROME, {
        StartModule: "C:\\Windows\\System32\\KERNEL32.DLL",
        StartFunction: "LoadLibraryA",
      }).mitre,
    ).toEqual(["T1055.001"]);
    // …and a system NAME at a user path is the masquerade signal: High even with a module-backed
    // or absent start.
    expect(thread(MASQ, CHROME, { StartModule: "C:\\Windows\\System32\\ntdll.dll" }).severity).toBe("High");
    expect(thread(MASQ, CHROME).severity).toBe("High");
    expect(thread(MASQ, CHROME).description).toContain("a system process name from a non-system path");
  });
  it("a start absent from the record is not an unbacked claim: Medium + T1055 untrusted, Low trusted, with the words", () => {
    const a = thread("C:\\Users\\bob\\Documents\\tool.exe", CHROME);
    expect(a.severity).toBe("Medium");
    expect(a.mitre).toEqual(["T1055"]);
    expect(a.description).toContain("start module not in this record");
    // …a source at a suspicious path (Temp, AppData, Public) is the record's own signal: High
    const temp = thread(MIMI, CHROME);
    expect(temp.severity).toBe("High");
    expect(temp.description).toContain("source at a suspicious path");
    expect(a.identity).toContain("|thread:absent|");
    const b = thread(CSRSS, CHROME);
    expect(b.severity).toBe("Low");
    expect(b.mitre).toEqual([]);
  });
});

describe("processOverlay — ProcessTampering (Sysmon 25)", () => {
  it("keeps the sensor's verdict, names the type, keys on the process, and carries it as the object", () => {
    const o = overlay("tamper", {
      ProcessGuid: G1,
      ProcessId: "4400",
      Image: "C:\\Users\\bob\\AppData\\Local\\Temp\\svchost.exe",
      Type: "Image is replaced",
    });
    expect(o.severity).toBe("High");
    expect(o.mitre).toEqual(["T1055.012"]);
    expect(o.type).toBe("tamper");
    expect(o.description).toContain("svchost.exe: Image is replaced");
    expect(o.identity).toBe("|tamper:image is replaced|proc:11111111-1111-1111-1111-111111111111");
    expect(o.entities.object).toEqual({
      kind: "process",
      id: "11111111-1111-1111-1111-111111111111",
      name: "svchost.exe",
      pid: 4400,
    });
    expect(o.entities.subject).toBeUndefined();
    expect(o.process).toEqual({
      pid: 4400,
      name: "svchost.exe",
      executable: "C:\\Users\\bob\\AppData\\Local\\Temp\\svchost.exe",
    });
    // GUID-less: the record keys it
    const a = overlay(
      "tamper",
      { ProcessId: "4400", Image: "C:\\x.exe", Type: "Image is replaced" },
      { recordId: "9", row: 1 },
    );
    const b = overlay(
      "tamper",
      { ProcessId: "4400", Image: "C:\\x.exe", Type: "Image is replaced" },
      { recordId: "10", row: 2 },
    );
    expect(a.identity).not.toBe(b.identity);
  });
});
