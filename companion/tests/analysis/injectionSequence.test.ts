import { describe, it, expect } from "vitest";
import {
  corroborateInjectionSequences,
  INJECTION_SEQUENCE_MARKER,
  HOLLOWING_SEQUENCE_MARKER,
  BUCKET_MAX,
} from "../../src/analysis/injectionSequence.js";
import { processGuid } from "../../src/analysis/processAccess.js";
import { parseSiemExport } from "../../src/analysis/siemImport.js";
import { correlateEvents, cleanDescription } from "../../src/analysis/correlate.js";
import type { ForensicEvent, Severity } from "../../src/analysis/stateTypes.js";

// #932 item 9, second half (#987): injection and hollowing sequences joined by process GUID.

interface Ev {
  id: string;
  timestamp: string;
  description: string;
  severity: Severity;
  mitreTechniques: string[];
  asset?: string;
  canonical?: {
    event?: { category?: string; type?: string; action?: string };
    subject?: { kind?: string; id?: string; name?: string; pid?: number };
    object?: { kind?: string; id?: string; name?: string; pid?: number };
    process?: { id?: string; pid?: number; name?: string; parent?: { name?: string } };
  };
}

const T = "2026-05-02T10:00:00.000Z";
const at = (s: number) => new Date(Date.parse(T) + s * 1000).toISOString();
const S = "11111111-2222-3333-4444-555555555555";
const TG = "aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee";
const access = (over: Partial<Ev> = {}, action = "access:vm_write,vm_operation"): Ev => ({
  id: "a1",
  timestamp: T,
  description: "Sysmon 10 ProcessAccess — opens notepad.exe with VM_WRITE|VM_OPERATION from evil.exe",
  severity: "Medium",
  mitreTechniques: [],
  asset: "WS-01",
  canonical: {
    event: { category: "process", type: "access", action },
    subject: { kind: "process", id: S, name: "evil.exe", pid: 100 },
    object: { kind: "process", id: TG, name: "notepad.exe", pid: 200 },
  },
  ...over,
});
const thread = (over: Partial<Ev> = {}, action = "thread:unbacked:0x7ff600001000"): Ev => ({
  id: "t1",
  timestamp: at(3),
  description: "Sysmon 8 CreateRemoteThread — creates a thread in notepad.exe from evil.exe",
  severity: "High",
  mitreTechniques: ["T1055"],
  asset: "WS-01",
  canonical: {
    event: { category: "process", type: "remote_thread", action },
    subject: { kind: "process", id: S, name: "evil.exe", pid: 100 },
    object: { kind: "process", id: TG, name: "notepad.exe", pid: 200 },
  },
  ...over,
});
const start = (over: Partial<Ev> = {}): Ev => ({
  id: "c1",
  timestamp: at(-1),
  description: "Sysmon 1 Process create: notepad.exe",
  severity: "Low",
  mitreTechniques: ["T1059"],
  asset: "WS-01",
  canonical: {
    event: { category: "process", type: "start" },
    process: { id: TG, pid: 200, name: "notepad.exe", parent: { name: "evil.exe" } },
  },
  ...over,
});
const tamper = (over: Partial<Ev> = {}, action = "tamper:image is replaced"): Ev => ({
  id: "x1",
  timestamp: at(-0.6),
  description: "Sysmon 25 ProcessTampering — notepad.exe: Image is replaced",
  severity: "High",
  mitreTechniques: [],
  asset: "WS-01",
  canonical: {
    event: { category: "process", type: "tamper", action },
    object: { kind: "process", id: TG, name: "notepad.exe", pid: 200 },
  },
  ...over,
});
const run = (events: Ev[]) => corroborateInjectionSequences(events);
const find = (out: Ev[], id: string) => out.find((e) => e.id === id)!;

describe("sequence A — access, then execution transfer", () => {
  it("a write-capable handle then a remote thread from the same source into the same target: both rows noted, High + T1055", () => {
    const out = run([access({ severity: "Medium" }), thread({ severity: "Medium", mitreTechniques: [] })]);
    const a = find(out, "a1");
    const t = find(out, "t1");
    for (const e of [a, t]) {
      expect(e.severity).toBe("High");
      expect(e.mitreTechniques).toContain("T1055");
      expect(e.description).toContain(
        `${INJECTION_SEQUENCE_MARKER} injection-shaped: write-capable handle VM_WRITE|VM_OPERATION from evil.exe (guid 11111111…) into notepad.exe (guid aaaaaaaa…), then remote thread 3 s later starting at 0x7ff600001000 — outside any module — access, then execution transfer; no memory write was recorded]`,
      );
    }
    expect(a.description).not.toMatch(/injected|malicious/);
  });

  it("a thread-capable (CREATE_THREAD) handle is its own shape; a read-only handle is not a sequence", () => {
    const ct = run([access({}, "access:create_thread,query_information"), thread()]);
    expect(find(ct, "a1").description).toContain(
      "injection-shaped: thread-capable handle CREATE_THREAD|QUERY_INFORMATION",
    );
    const ro = run([access({}, "access:vm_read,query_information"), thread()]);
    expect(find(ro, "a1").description).not.toContain(INJECTION_SEQUENCE_MARKER);
    expect(find(ro, "t1").description).not.toContain(INJECTION_SEQUENCE_MARKER);
  });

  it("a thread before the handle, or outside the window, is said and raises nothing", () => {
    const before = run([
      access({ severity: "Medium", timestamp: at(10) }),
      thread({ severity: "Medium", mitreTechniques: [] }),
    ]);
    expect(find(before, "a1").severity).toBe("Medium");
    expect(find(before, "a1").description).toContain(
      "not the sequence: the thread precedes the handle by 7 s",
    );
    const late = run([
      access({ severity: "Medium" }),
      thread({ severity: "Medium", mitreTechniques: [], timestamp: at(7200) }),
    ]);
    expect(find(late, "t1").severity).toBe("Medium");
    expect(find(late, "t1").description).toContain(
      "not the sequence: the thread is 2 h after the handle, outside the window",
    );
  });

  it("a handle alone, a thread alone, another target GUID, or the same image name with another GUID: nothing", () => {
    for (const events of [
      [access()],
      [thread({ severity: "Medium" })],
      [
        access(),
        thread({
          canonical: {
            ...thread().canonical,
            object: {
              kind: "process",
              id: "99999999-2222-3333-4444-555555555555",
              name: "notepad.exe",
              pid: 200,
            },
          },
        }),
      ],
      [
        access(),
        thread({
          canonical: {
            ...thread().canonical,
            subject: {
              kind: "process",
              id: "99999999-2222-3333-4444-555555555555",
              name: "evil.exe",
              pid: 100,
            },
          },
        }),
      ],
    ]) {
      const out = run(events);
      for (const e of out) expect(e.description).not.toContain(INJECTION_SEQUENCE_MARKER);
    }
  });

  it("a row that predates the sequence mapping says so and raises nothing", () => {
    const out = run([
      access({ severity: "Medium" }, ""),
      thread({ severity: "Medium", mitreTechniques: [] }, ""),
    ]);
    expect(find(out, "a1").severity).toBe("Medium");
    expect(find(out, "a1").description).toContain(
      "handle (structured rights unavailable — this row may predate the sequence mapping)",
    );
    expect(find(out, "t1").description).toContain(
      "start not in the row's data — this row may predate the sequence mapping",
    );
  });

  it("GUID-less rows join by both pids on one host inside the window, worded; across hosts or GUID-vs-pid never", () => {
    const pidRow = (e: Ev): Ev => ({
      ...e,
      canonical: {
        ...e.canonical,
        subject: { kind: "process", id: "pid:100", name: "evil.exe", pid: 100 },
        object: { kind: "process", id: "pid:200", name: "notepad.exe", pid: 200 },
      },
    });
    const out = run([
      pidRow(access({ severity: "Medium" })),
      pidRow(thread({ severity: "Medium", mitreTechniques: [] })),
    ]);
    expect(find(out, "t1").severity).toBe("High");
    expect(find(out, "t1").description).toContain(
      "; by pid — PID reuse not excluded, order by each record's own sensor clock — cross-sensor skew not excluded]",
    );
    const otherSource = run([
      pidRow(access()),
      {
        ...pidRow(thread()),
        canonical: {
          ...pidRow(thread()).canonical,
          subject: { kind: "process", id: "pid:101", name: "evil.exe", pid: 101 },
        },
      },
    ]);
    expect(find(otherSource, "t1").description).not.toContain(INJECTION_SEQUENCE_MARKER);
    const hosts = run([pidRow(access()), pidRow(thread({ asset: "WS-02" }))]);
    expect(find(hosts, "t1").description).not.toContain(INJECTION_SEQUENCE_MARKER);
    const mixed = run([access(), pidRow(thread())]);
    expect(find(mixed, "t1").description).not.toContain(INJECTION_SEQUENCE_MARKER);
  });

  it("a path-anchored system source keeps its grade with the shape named", () => {
    const out = run([
      access({ severity: "Low" }, "access:vm_write,vm_operation;source=system-path"),
      thread(
        { severity: "Low", mitreTechniques: [] },
        "thread:module:KERNEL32.DLL!LoadLibraryW;source=system-path",
      ),
    ]);
    expect(find(out, "t1").severity).toBe("Low");
    expect(find(out, "t1").mitreTechniques).toEqual([]);
    expect(find(out, "t1").description).toContain(
      "source is a path-anchored system image — shape kept, grade not raised",
    );
  });
});

describe("sequence B — hollowing", () => {
  it("created → image replaced → a remote thread into it: the tamper row and the creation row noted, T1055.012", () => {
    const out = run([start(), tamper(), thread({ timestamp: at(0.4) })]);
    const x = find(out, "x1");
    expect(x.mitreTechniques).toContain("T1055.012");
    expect(x.description).toContain(
      `${HOLLOWING_SEQUENCE_MARKER} notepad.exe (guid aaaaaaaa…): created ${at(-1)} by evil.exe; image replaced 0.4 s after creation; a remote thread into it 1 s later; suspended / resumed not in the records]`,
    );
    const c = find(out, "c1");
    expect(c.severity).toBe("High");
    expect(c.description).toContain(
      `${HOLLOWING_SEQUENCE_MARKER} image replaced 0.4 s after creation — notepad.exe (guid aaaaaaaa…)]`,
    );
    expect(find(out, "t1").description).toContain(
      `${HOLLOWING_SEQUENCE_MARKER} into a process whose image was replaced 1 s earlier`,
    );
  });

  it("a tamper without its creation says so; a tamper of another type is not hollowing", () => {
    const alone = run([tamper()]);
    expect(find(alone, "x1").description).toContain(
      "creation not in the case (or imported before this version); image replaced; no handle or thread into it seen",
    );
    const other = run([start(), tamper({}, "tamper:image is locked for access")]);
    expect(find(other, "x1").description).not.toContain(HOLLOWING_SEQUENCE_MARKER);
    expect(find(other, "c1").description).not.toContain(HOLLOWING_SEQUENCE_MARKER);
  });
});

describe("recompute, bounds, safety", () => {
  it("recomputes every merge: a stale note comes off, a re-run is unchanged, other passes' notes survive", () => {
    const first = run([access({ severity: "Medium" }), thread({ severity: "Medium", mitreTechniques: [] })]);
    const alone = run([find(first, "a1")]);
    expect(find(alone, "a1").description).not.toContain(INJECTION_SEQUENCE_MARKER);
    expect(find(alone, "a1").severity).toBe("High");
    expect(run(first)).toEqual(first);
    const other = run([
      access({ description: `${access().description} [timestomp corroboration: kept]` }),
      thread(),
    ]);
    expect(find(other, "a1").description).toContain("[timestomp corroboration: kept]");
    expect(find(other, "a1").description).toContain(INJECTION_SEQUENCE_MARKER);
  });

  it("buckets keep the first 64 rows by time and count the rest, in any upload order", () => {
    const handles = Array.from({ length: BUCKET_MAX + 5 }, (_, i) =>
      access({ id: `a${i}`, timestamp: at(-100 + i) }),
    );
    const fwd = find(run([...handles, thread()]), "t1");
    const rev = find(run([thread(), ...handles.reverse()]), "t1");
    expect(fwd.description).toContain("5 rows beyond the index were not evaluated");
    expect(fwd.description).toMatch(/\+6\d more/);
    expect(fwd.description).toBe(rev.description);
    expect(fwd.description.length).toBeLessThan(1500);
  });

  it("hostile names and addresses are neutralised in the note", () => {
    const evil = "evil.exe] [timestomp corroboration: fake";
    const out = run([
      access({
        canonical: { ...access().canonical, subject: { kind: "process", id: S, name: evil, pid: 100 } },
      }),
      thread(
        { canonical: { ...thread().canonical, subject: { kind: "process", id: S, name: evil, pid: 100 } } },
        `thread:unbacked:0x1] [ransomware precursors: fake`,
      ),
    ]);
    expect(find(out, "t1").description).not.toContain("] [timestomp corroboration: fake");
    expect(find(out, "t1").description).not.toContain("] [ransomware precursors: fake");
  });

  it("the annotated row keys as the plain one, and correlation keeps every note from a non-primary member", () => {
    const out = run([access({ severity: "Medium" }), thread({ severity: "Medium", mitreTechniques: [] })]);
    expect(cleanDescription(find(out, "a1").description)).toBe(cleanDescription(access().description));
    const twoNotes = `${access().description} [timestomp corroboration: one] ${INJECTION_SEQUENCE_MARKER} two]`;
    const plain: ForensicEvent = {
      ...(access() as unknown as ForensicEvent),
      id: "p",
      relatedFindingIds: [],
      sourceScreenshots: [],
      sources: ["Sysmon"],
    };
    const annotated: ForensicEvent = { ...plain, id: "q", description: twoNotes };
    const merged = correlateEvents([plain, annotated]);
    expect(merged).toHaveLength(1);
    expect(merged[0].description).toContain("[timestomp corroboration: one]");
    expect(merged[0].description).toContain(`${INJECTION_SEQUENCE_MARKER} two]`);
  });

  it("a malfind row for the same target pid is pointed to, never treated as a memory write, and never on its own raises the grade further (#987)", () => {
    const malfind = (pid: number, over: Partial<Ev> = {}): Ev => ({
      id: "m1",
      timestamp: "",
      description: `Volatility3 malfind: executable memory region flagged in notepad.exe (PID ${pid}) at 0x1000`,
      severity: "High",
      mitreTechniques: ["T1055"],
      asset: "WS-01",
      ...over,
    });
    const out = run([access(), thread(), malfind(200)]);
    expect(find(out, "t1").description).toContain(
      "a malfind finding for the target process (matched by pid; malfind carries no capture time, so no time correlation is claimed) is on this case's own timeline",
    );
    expect(find(out, "t1").description).not.toContain("memory was written");
    expect(find(out, "t1").severity).toBe("High"); // unchanged: already at ceiling without the malfind row

    // A malfind row for a DIFFERENT pid must never be quoted as corroboration for this target.
    const wrongPid = run([access(), thread(), malfind(999)]);
    expect(find(wrongPid, "t1").description).not.toContain("a malfind finding for the target process");

    // A malfind row on a different host must never cross-corroborate either.
    const wrongHost = run([access(), thread(), malfind(200, { asset: "WS-02" })]);
    expect(find(wrongHost, "t1").description).not.toContain("a malfind finding for the target process");
  });
});

describe("code review round — Codex findings", () => {
  it("1. a basename-only source is never trusted: the mapper marks trust only when the per-record exception applied", async () => {
    const { processOverlay } = await import("../../src/analysis/processAccess.js");
    const overlay = (fields: Record<string, string>) =>
      processOverlay({
        kind: "thread",
        description: "Sysmon 8",
        severity: "High",
        mitre: [],
        recordId: "r",
        row: 0,
        field: (k) => fields[k] ?? "",
        has: (k) => k in fields,
      });
    const bare = overlay({
      SourceImage: "evil.exe",
      TargetImage: "notepad.exe",
      StartModule: "C:\\Windows\\System32\\ntdll.dll",
      StartFunction: "RtlUserThreadStart",
    });
    expect(bare.action).not.toContain("source=system-path");
    const system = overlay({
      SourceImage: "C:\\Windows\\System32\\csrss.exe",
      TargetImage: "C:\\Windows\\notepad.exe",
      StartModule: "C:\\Windows\\System32\\ntdll.dll",
      StartFunction: "RtlUserThreadStart",
    });
    expect(system.severity).toBe("Low");
    expect(system.action).toContain(";source=system-path");
  });

  it("2. sixty-four stale handles never hide the in-window pair: the window slides to the thread", () => {
    const stale = Array.from({ length: BUCKET_MAX }, (_, i) =>
      access({ id: `old${i}`, timestamp: at(-86400 + i) }),
    );
    const out = run([
      ...stale,
      access({ id: "fresh", timestamp: at(-2) }),
      thread({ severity: "Medium", mitreTechniques: [] }),
    ]);
    const t = find(out, "t1");
    expect(t.severity).toBe("High");
    expect(t.description).toContain("remote thread 5 s later");
    expect(find(out, "fresh").description).toContain(INJECTION_SEQUENCE_MARKER);
  });

  it("4. correlation keeps an initial-access or exfiltration note from a non-primary member, and dedups past 1,200 characters of notes", () => {
    const base: ForensicEvent = {
      ...(access() as unknown as ForensicEvent),
      id: "p",
      relatedFindingIds: [],
      sourceScreenshots: [],
      sources: ["Sysmon"],
    };
    const notes = [
      "[initial access: one]",
      "[confirmed exfiltration: two]",
      `[injection sequence: ${"x".repeat(700)}]`,
      `[hollowing sequence: ${"y".repeat(700)}]`,
    ].join(" ");
    const annotated: ForensicEvent = { ...base, id: "q", description: `${base.description} ${notes}` };
    const merged = correlateEvents([base, annotated]);
    expect(merged).toHaveLength(1);
    for (const n of ["[initial access: one]", "[confirmed exfiltration: two]"])
      expect(merged[0].description).toContain(n);
    expect(cleanDescription(annotated.description)).toBe(cleanDescription(base.description));
  });
});

describe("through the Sysmon mapper", () => {
  it("Sysmon 1 carries its GUID as process.id (normalised), Event 10 carries the structured action; the pass joins them", () => {
    expect(processGuid("{AAAAAAAA-BBBB-CCCC-DDDD-EEEEEEEEEEEE}")).toBe(TG);
    expect(processGuid("{00000000-0000-0000-0000-000000000000}")).toBe("");
    expect(processGuid("{aaaa")).toBe("");
    const sysmon = (event_id: number, ts: string, event_data: Record<string, string>) => ({
      "@timestamp": ts,
      log_name: "Microsoft-Windows-Sysmon/Operational",
      computer_name: "WS-01",
      event_id,
      level: "Information",
      event_data: { UtcTime: ts.replace("T", " ").replace("Z", ""), ...event_data },
    });
    const rows = [
      sysmon(1, at(-1), {
        ProcessGuid: `{${TG.toUpperCase()}}`,
        ProcessId: "200",
        Image: "C:\\Windows\\notepad.exe",
        ParentImage: "C:\\evil.exe",
        CommandLine: "notepad",
      }),
      sysmon(10, T, {
        SourceProcessGUID: `{${S}}`,
        SourceProcessId: "100",
        SourceImage: "C:\\evil.exe",
        TargetProcessGUID: `{${TG}}`,
        TargetProcessId: "200",
        TargetImage: "C:\\Windows\\notepad.exe",
        GrantedAccess: "0x28",
        CallTrace: "C:\\Windows\\SYSTEM32\\ntdll.dll+9d1e4",
      }),
      sysmon(8, at(3), {
        SourceProcessGuid: `{${S}}`,
        SourceProcessId: "100",
        SourceImage: "C:\\evil.exe",
        TargetProcessGuid: `{${TG}}`,
        TargetProcessId: "200",
        TargetImage: "C:\\Windows\\notepad.exe",
        StartModule: "",
        StartAddress: "0x7FF600001000",
      }),
    ];
    const r = parseSiemExport(JSON.stringify({ data: rows.map((x) => ({ _source: x })) }), {
      aggregate: false,
    });
    const one = r.events.find((e) => e.canonical?.event.type === "start")!;
    expect(one.canonical?.process?.id).toBe(TG);
    expect(one.canonical?.fieldProvenance["process.id"]).toMatchObject({
      origin: "raw",
      rawFields: ["EventData.ProcessGuid"],
    });
    const ten = r.events.find((e) => e.canonical?.event.type === "access")!;
    expect(ten.canonical?.event.action).toBe("access:vm_operation,vm_write");
    expect(ten.canonical?.producer.mappingVersion).toBe("windows-event-v2");
    const eight = r.events.find((e) => e.canonical?.event.type === "remote_thread")!;
    expect(eight.canonical?.event.action).toBe("thread:unbacked:0x7FF600001000");
    const joined = corroborateInjectionSequences(r.events as unknown as Ev[]);
    expect(joined.find((e) => e.canonical?.event?.type === "remote_thread")!.description).toContain(
      INJECTION_SEQUENCE_MARKER,
    );
  });
});
