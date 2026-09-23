import { describe, it, expect } from "vitest";
import {
  parseVelociraptorJson,
  parseVelociraptorJsonProgress,
} from "../../src/analysis/velociraptorImport.js";
import { SHARED_SOURCE_MTIME_MARKER, markSharedSourceMtime } from "../../src/analysis/mftTimeHints.js";
import { DERIVED_NOTE_NAMES } from "../../src/analysis/derivedNote.js";
import { promptDescription } from "../../src/analysis/ai/promptDescription.js";
import type { MappedEvent } from "../../src/analysis/siemImport.js";

// #1558. Scenario 019: five dropped tools were Copy-Item copies of cmd.exe, so all five kept cmd.exe's
// own $SI LastModified (2025-12-05T02:54:10Z). The model read the shared old date as "every tool was
// timestomped". The row shapes below are the DetectRaptor.Windows.Detection.MFT rows of that import,
// with the lab prefix trimmed from the paths; the real backdated ZIP keeps its timestomp label.

const CMD_MTIME = "2025-12-05T02:54:10.1128473Z";
const SUSPICIOUS_LOCATION = { Name: "Suspicious Location", StringHit: ".exe", Criticality: "High" };

function mftRow(path: string, siCreated: string, siModified: string, fnCreated: string, host: string) {
  return {
    _Source: "DetectRaptor.Windows.Detection.MFT",
    Detection: SUSPICIOUS_LOCATION,
    EntryNumber: 94943,
    InUse: true,
    OSPath: `\\\\.\\C:\\${path}`,
    FileSize: 344064,
    IsDir: false,
    SITimestamps: { Created0x10: siCreated, LastModified0x10: siModified },
    FNTimestamps: { Created0x30: fnCreated, LastModified0x30: fnCreated },
    Fqdn: `${host}.example.com`,
  };
}

// Five copies of one source file: $SI Created = $FN Created (the drop), $SI LastModified = cmd.exe's.
const copy = (path: string, created: string, host = "workstation01") =>
  mftRow(path, created, CMD_MTIME, created, host);

const COPIES = [
  copy("ProgramData\\scaner\\scaner\\netscan.exe", "2026-09-22T14:38:30.6864145Z"),
  copy("ProgramData\\VeeamHax.exe", "2026-09-22T14:38:34.1968708Z"),
  copy("ProgramData\\cloudflared\\cloudflared-windows-amd64.exe", "2026-09-22T14:38:40.9419086Z", "backup01"),
  copy("Users\\Recruiter\\AppData\\Roaming\\Microsoft\\ie4uinit.exe", "2026-09-22T14:37:49.8297958Z"),
  copy("ProgramData\\Microsoft\\msxsl.exe", "2026-09-22T14:37:51.8296767Z"),
];
// The real backdating: $SI Created two days before $FN Created.
const STOMPED_ZIP = mftRow(
  "Users\\Recruiter\\Downloads\\John Shimkus.zip",
  "2026-09-20T02:37:44.549319Z",
  "2026-09-20T02:38:44.549319Z",
  "2026-09-22T14:37:49.2150948Z",
  "workstation01",
);
// A lone copy from another source (its own modified second) — a copy, but nothing shares its date.
const LONE_COPY = mftRow(
  "Tools\\dd.exe",
  "2025-12-05T02:45:09.9011311Z",
  "2025-08-14T13:10:59.797023Z",
  "2025-12-05T02:45:09.9011311Z",
  "workstation01",
);

const ROWS = [...COPIES, STOMPED_ZIP, LONE_COPY];
const SHARED_NOTE = "[shared source mtime: 5 copies of one source file, not timestomping]";
const byPath = <T extends { description: string }>(events: T[], name: string): T | undefined =>
  events.find((e) => e.description.includes(name));

describe("shared source mtime — copies of one file are not five timestomps (#1558)", () => {
  it("notes every copy that shares the modified second, with the copy count", () => {
    const r = parseVelociraptorJson(JSON.stringify(ROWS));
    for (const name of [
      "netscan.exe",
      "VeeamHax.exe",
      "cloudflared-windows-amd64.exe",
      "ie4uinit.exe",
      "msxsl.exe",
    ]) {
      const e = byPath(r.events, name);
      expect(e?.description, name).toContain(SHARED_NOTE);
      expect(e?.description, name).toContain("copied file, not timestomp");
      expect(e?.mitreTechniques ?? [], name).not.toContain("T1070.006");
    }
  });

  it("leaves the backdated ZIP's timestomp label unchanged and adds no shared note", () => {
    const r = parseVelociraptorJson(JSON.stringify(ROWS));
    const zip = byPath(r.events, "John Shimkus.zip");
    expect(zip?.description).toMatch(/timestomping/i);
    expect(zip?.mitreTechniques).toContain("T1070.006");
    expect(zip?.description).not.toContain(SHARED_SOURCE_MTIME_MARKER);
    expect(zip?.description).not.toContain("not timestomp");
  });

  it("does not note a copy whose modified second no other copy shares", () => {
    const r = parseVelociraptorJson(JSON.stringify(ROWS));
    const dd = byPath(r.events, "dd.exe");
    expect(dd?.description).toContain("copied file, not timestomp");
    expect(dd?.description).not.toContain(SHARED_SOURCE_MTIME_MARKER);
  });

  it("does not note a single copy on its own", () => {
    const r = parseVelociraptorJson(JSON.stringify([COPIES[0]]));
    expect(r.events[0]?.description).not.toContain(SHARED_SOURCE_MTIME_MARKER);
  });

  it("the progress driver gives the same notes as the synchronous one", async () => {
    const sync = parseVelociraptorJson(JSON.stringify(ROWS));
    const prog = await parseVelociraptorJsonProgress(JSON.stringify(ROWS));
    expect(prog.events.map((e) => e.description)).toEqual(sync.events.map((e) => e.description));
  });

  it("registers the note, so the 240-character prompt clip keeps it whole", () => {
    expect(DERIVED_NOTE_NAMES).toContain("shared source mtime");
    const r = parseVelociraptorJson(JSON.stringify(ROWS));
    const e = byPath(r.events, "netscan.exe");
    const long = `${e?.description ?? ""} ${"x".repeat(400)}`.replace(SHARED_NOTE, "") + ` ${SHARED_NOTE}`;
    expect(long.length).toBeGreaterThan(240);
    const shown = promptDescription(long);
    expect(shown.length).toBeLessThanOrEqual(260);
    expect(shown).toContain(SHARED_NOTE);
  });

  it("returns events it did not mark as the same objects, and never mutates its input", () => {
    const plain: MappedEvent = {
      timestamp: "2026-09-22T14:38:30Z",
      description: "Velociraptor row",
      severity: "Info",
      mitre: [],
      aggKey: "k",
      sources: ["Velociraptor"],
    };
    const input = [plain];
    const out = markSharedSourceMtime(input);
    expect(out[0]).toBe(plain);
    expect(out).not.toBe(input);
  });
});
