import { describe, it, expect } from "vitest";
import {
  sharedResources,
  companionLeads,
  MAX_BREADTH,
  type PrefetchEntry,
} from "../../src/analysis/prefetchResources.js";
import { parseKapeCsv } from "../../src/analysis/kapeImport.js";

const entry = (executable: string, referenced: string[]): PrefetchEntry => ({
  executable,
  host: "WS-01",
  volumeSerial: "A1B2C3D4",
  runCount: 1,
  lastRun: "2026-01-01T10:00:00Z",
  referenced,
});

const SYSTEM = [
  "C:\\Windows\\System32\\ntdll.dll",
  "C:\\Windows\\System32\\kernel32.dll",
  "C:\\Program Files\\App\\app.dll",
];

describe("sharedResources — common libraries are excluded outright", () => {
  // Every process loads these. Scoring on them makes every pair look related, which looks like a
  // finding and is not one.
  it("ignores system libraries however many executables share them", () => {
    const r = sharedResources([entry("a.exe", SYSTEM), entry("b.exe", SYSTEM)]);
    expect(r).toEqual([]);
  });

  it("reports a resource shared by exactly two executables", () => {
    const r = sharedResources([
      entry("dropper.exe", [...SYSTEM, "C:\\Users\\jdoe\\AppData\\Local\\Temp\\helper.dll"]),
      entry("payload.exe", [...SYSTEM, "C:\\Users\\jdoe\\AppData\\Local\\Temp\\helper.dll"]),
    ]);
    expect(r).toHaveLength(1);
    expect(r[0].breadth).toBe(2);
    expect(r[0].executables).toEqual(["dropper.exe", "payload.exe"]);
  });

  it("ignores a resource only one executable referenced", () => {
    const r = sharedResources([entry("a.exe", ["C:\\Temp\\only.dll"]), entry("b.exe", SYSTEM)]);
    expect(r).toEqual([]);
  });

  // Referenced by many programs means ordinary, wherever it lives.
  it("ignores a resource referenced more widely than the breadth limit", () => {
    const shared = "C:\\Users\\jdoe\\AppData\\Local\\Temp\\common.dat";
    const many = Array.from({ length: MAX_BREADTH + 2 }, (_v, i) => entry(`p${i}.exe`, [shared]));
    expect(sharedResources(many)).toEqual([]);
  });

  it("normalizes the device-path form Prefetch records", () => {
    const r = sharedResources([
      entry("a.exe", ["\\DEVICE\\HARDDISKVOLUME3\\Users\\jdoe\\AppData\\Local\\Temp\\x.dll"]),
      entry("b.exe", ["C:\\Users\\jdoe\\AppData\\Local\\Temp\\x.dll".replace("C:", "")]),
    ]);
    expect(r).toHaveLength(1);
  });

  it("orders the rarest resource first", () => {
    const two = "C:\\Temp\\rare.dll";
    const three = "C:\\Temp\\less-rare.dll";
    const r = sharedResources([
      entry("a.exe", [two, three]),
      entry("b.exe", [two, three]),
      entry("c.exe", [three]),
    ]);
    expect(r[0].path).toContain("rare.dll");
    expect(r[0].breadth).toBe(2);
  });
});

describe("companionLeads", () => {
  const helper = "C:\\Users\\jdoe\\AppData\\Local\\Temp\\helper.dll";
  const entries = [
    entry("dropper.exe", [...SYSTEM, helper]),
    entry("svch0st.exe", [...SYSTEM, helper]),
    entry("unrelated.exe", SYSTEM),
  ];

  it("finds what else referenced the same unusual file", () => {
    const leads = companionLeads(entries, "dropper.exe");
    expect(leads).toHaveLength(1);
    expect(leads[0].companion).toBe("svch0st.exe");
    expect(leads[0].via).toEqual([helper.toLowerCase()]);
  });

  it("notes when the shared resource sits in user-writable space", () => {
    expect(companionLeads(entries, "dropper.exe")[0].inUserWritable).toBe(true);
  });

  it("returns nothing when the suspect is not in the collection", () => {
    expect(companionLeads(entries, "absent.exe")).toEqual([]);
  });

  it("does not link executables that share only system libraries", () => {
    expect(companionLeads(entries, "unrelated.exe")).toEqual([]);
  });

  it("orders the strongest link first", () => {
    const a = "C:\\Temp\\one.dll";
    const b = "C:\\Temp\\two.dll";
    const leads = companionLeads(
      [entry("s.exe", [a, b]), entry("strong.exe", [a, b]), entry("weak.exe", [a])],
      "s.exe",
    );
    expect(leads[0].companion).toBe("strong.exe");
    expect(leads[0].via).toHaveLength(2);
  });

  // What a reference is, and what it is not.
  it("states the limits of a Prefetch reference on every lead", () => {
    const note = companionLeads(entries, "dropper.exe")[0].note;
    expect(note).toContain("not that a DLL was loaded");
    expect(note).toContain("not that anyone opened a document");
    expect(note).toContain("does not explain them");
  });

  // rundll32.exe is signed by Microsoft and is how a great deal of malicious code runs.
  it("does not treat a trusted executable's references as vouched for", () => {
    const withTrusted = [
      entry("rundll32.exe", [...SYSTEM, helper]),
      entry("payload.exe", [...SYSTEM, helper]),
    ];
    const leads = companionLeads(withTrusted, "payload.exe");
    expect(leads).toHaveLength(1);
    expect(leads[0].companion).toBe("rundll32.exe");
  });
});

// Reachability: the module only matters if the importer feeds it real PECmd columns.
describe("wired into the KAPE Prefetch importer", () => {
  const header =
    "SourceFilename,ExecutableName,Hash,Size,Version,RunCount,LastRun,Volume0Serial,Directories,FilesLoaded";
  const row = (exe: string, loaded: string) =>
    `C:\\Windows\\Prefetch\\${exe}-1.pf,${exe},AB,10,,3,2026-01-01 10:00:00,A1B2C3D4,,"${loaded}"`;

  const helper = "C:\\Users\\jdoe\\AppData\\Local\\Temp\\helper.dll";
  const sys = "C:\\Windows\\System32\\ntdll.dll";

  it("links a graded executable to another that referenced the same unusual file", () => {
    const csv = [
      header,
      // mimikatz.exe is named offensive tooling, so prefetchExecution already grades it.
      row("MIMIKATZ.EXE", `${sys},${helper}`),
      row("SVCH0ST.EXE", `${sys},${helper}`),
    ].join("\n");
    const r = parseKapeCsv(csv);
    const lead = r.events.find((e) => /Prefetch companions/.test(e.description));
    expect(lead).toBeDefined();
    expect(lead!.description).toContain("svch0st.exe");
    expect(lead!.description).toContain("helper.dll");
    expect(lead!.severity).toBe("Low");
  });

  it("says nothing when the two executables share only system libraries", () => {
    const csv = [header, row("MIMIKATZ.EXE", sys), row("NOTEPAD.EXE", sys)].join("\n");
    expect(parseKapeCsv(csv).events.some((e) => /Prefetch companions/.test(e.description))).toBe(false);
  });

  it("says nothing when no executable in the collection is worth grading", () => {
    const csv = [header, row("NOTEPAD.EXE", `${sys},${helper}`), row("CALC.EXE", `${sys},${helper}`)].join(
      "\n",
    );
    expect(parseKapeCsv(csv).events.some((e) => /Prefetch companions/.test(e.description))).toBe(false);
  });

  it("still emits the ordinary execution events alongside the leads", () => {
    const csv = [
      header,
      row("MIMIKATZ.EXE", `${sys},${helper}`),
      row("SVCH0ST.EXE", `${sys},${helper}`),
    ].join("\n");
    const r = parseKapeCsv(csv);
    expect(r.events.some((e) => /executed/.test(e.description))).toBe(true);
  });
});
