import { describe, it, expect } from "vitest";
import { pickTime, vrTime } from "../../src/analysis/veloRowTime.js";
import { parseVelociraptorJson } from "../../src/analysis/velociraptorImport.js";

// #1415. A copied binary keeps the SOURCE file's $SI LastModified — cmd.exe's build date survives the
// copy, while every Created stamp records the drop. Dating a nested MFT row from LastModified0x10
// placed each decoy in case INC-2026-028 at 2025-12-05 instead of the 2026-09-19 drop, and the AI
// synthesized a staging wave and a 264-day dwell out of it. The nested block must rank the streams the
// way the top-level block already does: $FN Created, then $SI Created, then the modified/changed times.
describe("pickTime — nested MFT timestamp containers", () => {
  // Verbatim shape of the DetectRaptor.Windows.Detection.MFT row that misdated the decoys.
  const copiedCmd = {
    OSPath: "C:\\Users\\Public\\svchost.exe",
    SITimestamps: {
      Created0x10: "2026-09-19T11:28:24Z",
      LastModified0x10: "2025-12-05T02:54:10Z",
      LastRecordChange0x10: "2026-09-19T11:28:24Z",
    },
    FNTimestamps: {
      Created0x30: "2026-09-19T11:28:24Z",
      LastModified0x30: "2026-09-19T11:28:24Z",
    },
    _ts: 1_790_000_000,
  };

  it("dates a copied binary at its $FN Created, not the source file's $SI LastModified", () => {
    expect(pickTime(copiedCmd)).toMatch(/^2026-09-19T11:28:24/);
  });

  it("prefers $FN Created over $SI Created when the two differ (hardest to timestomp)", () => {
    const row = {
      SITimestamps: { Created0x10: "2009-07-14T01:14:24Z", LastModified0x10: "2009-07-14T01:14:24Z" },
      FNTimestamps: { Created0x30: "2026-09-19T11:28:24Z" },
    };
    expect(pickTime(row)).toMatch(/^2026-09-19T11:28:24/);
  });

  it("with only SITimestamps, uses Created0x10 before LastModified0x10", () => {
    const row = {
      SITimestamps: {
        Created0x10: "2026-09-19T11:28:24Z",
        LastModified0x10: "2025-12-05T02:54:10Z",
        LastRecordChange0x10: "2026-09-19T11:28:25Z",
      },
    };
    expect(pickTime(row)).toMatch(/^2026-09-19T11:28:24/);
  });

  it("still falls through to LastModified0x10, then LastRecordChange0x10, when no Created is present", () => {
    expect(
      pickTime({
        SITimestamps: {
          LastModified0x10: "2026-08-30T15:03:17Z",
          LastRecordChange0x10: "2026-08-31T00:00:00Z",
        },
      }),
    ).toMatch(/^2026-08-30T15:03:17/);
    expect(pickTime({ SITimestamps: { LastRecordChange0x10: "2026-08-31T00:00:00Z" } })).toMatch(
      /^2026-08-31T00:00:00/,
    );
  });

  it("keeps the same order for the top-level (un-nested) MFT columns", () => {
    const row = {
      Created0x10: "2026-09-19T11:28:24Z",
      LastModified0x10: "2025-12-05T02:54:10Z",
      Created0x30: "2026-09-19T11:28:25Z",
    };
    expect(pickTime(row)).toMatch(/^2026-09-19T11:28:25/);
  });
});

// #1603. A YARA file hit on a copied file carries the SOURCE file's Mtime. The mimikatz release
// binaries in the GoGoogle lab cases kept their 2013–2022 build times, while Btime recorded when
// each file was created on the host. Dated by Mtime, the hits formed "waves" across nine years.
describe("pickTime — a copied file is dated by its creation time (#1603)", () => {
  // Shape of the DetectRaptor.Generic.Detection.YaraFile row for mimidrv.sys, values sanitized.
  const copiedYaraHit = {
    OSPath: "C:\\e\\tools\\Win32\\mimidrv.sys",
    Size: 30552,
    Mtime: "2013-01-23T01:50:12Z",
    Atime: "2026-09-24T09:44:33.4520952Z",
    Ctime: "2013-01-23T01:50:12Z",
    Btime: "2026-09-24T08:58:30.6531008Z",
    Rule: "EXAMPLE_Hacktool_Mimikatz",
    Meta: { description: "example rule", date: "2017-08-11", modified: "2017-08-11" },
  };

  it("uses Btime when it is later than Mtime", () => {
    expect(pickTime(copiedYaraHit)).toBe("2026-09-24T08:58:30.6531008Z");
  });

  it("keeps Mtime for a normal edit — Btime earlier than Mtime", () => {
    const edited = { ...copiedYaraHit, Mtime: "2026-09-24T10:00:00Z", Btime: "2026-09-01T08:00:00Z" };
    expect(pickTime(edited)).toBe("2026-09-24T10:00:00Z");
  });

  it("keeps Mtime when the two are equal or Btime is later by under a second", () => {
    expect(pickTime({ ...copiedYaraHit, Mtime: "2026-09-24T08:00:00Z", Btime: "2026-09-24T08:00:00Z" })).toBe(
      "2026-09-24T08:00:00Z",
    );
    expect(
      pickTime({ ...copiedYaraHit, Mtime: "2026-09-24T08:00:00.1Z", Btime: "2026-09-24T08:00:00.9Z" }),
    ).toBe("2026-09-24T08:00:00.1Z");
  });

  it("keeps Mtime when Btime is absent or unparseable", () => {
    for (const Btime of [undefined, "", "not a date"]) {
      expect(pickTime({ ...copiedYaraHit, Btime })).toBe("2013-01-23T01:50:12Z");
    }
  });

  it("keeps Mtime on a row that names no file", () => {
    const { OSPath: _p, ...noPath } = copiedYaraHit;
    void _p;
    expect(pickTime(noPath)).toBe("2013-01-23T01:50:12Z");
  });

  it("recognises every path column the YARA mapper reads", () => {
    const { OSPath: p, ...rest } = copiedYaraHit;
    for (const key of ["FullPath", "_FullPath", "File", "FilePath", "Path"]) {
      expect(pickTime({ ...rest, [key]: p }), key).toBe("2026-09-24T08:58:30.6531008Z");
    }
  });

  it("leaves a row whose own event time outranks Mtime alone", () => {
    expect(pickTime({ ...copiedYaraHit, EventTime: "2026-09-20T00:00:00Z" })).toBe("2026-09-20T00:00:00Z");
  });
});

// #1603. A process-memory YARA hit has no time column of its own. The fallback scan read the
// RULE's metadata (Meta.date, the rule's authoring date) and dated the hit 2014.
describe("pickTime — a YARA rule's metadata is never the row's time (#1603)", () => {
  const processHit = {
    ProcessName: "powershell.exe",
    Pid: "6892",
    Rule: "EXAMPLE_Mimikatz_Memory_Rule",
    Meta: { description: "example", date: "2014-12-22", modified: "2014-12-22" },
    YaraString: "$s2",
  };

  it("does not date a process hit by Meta.date", () => {
    expect(pickTime(processHit)).toBe("");
  });

  it("falls to the collection time when that is all the row has", () => {
    expect(pickTime({ ...processHit, _ts: 1_790_000_000 })).toBe(new Date(1_790_000_000_000).toISOString());
  });

  it("ignores a Metadata container on a YARA row too", () => {
    const { Meta: _m, ...rest } = processHit;
    void _m;
    expect(pickTime({ ...rest, Metadata: { date: "2014-12-22" } })).toBe("");
  });

  it("still reads a Meta time on a row that is not a YARA hit", () => {
    expect(pickTime({ Name: "x", Meta: { LastVisited: "2026-09-01T10:00:00Z" } })).toMatch(
      /^2026-09-01T10:00:00/,
    );
  });
});

// #1618. autorunsc -t (which Windows.Sysinternals.Autoruns passes) prints its Time column in a compact
// "normalized UTC" form, YYYYMMDD-hhmmss. It is not ISO, so the raw string used to be stored as the
// event time: the row sorted as text and every time-based pass skipped or misplaced it.
describe("vrTime / pickTime — the Autoruns compact UTC time (#1618)", () => {
  it("reads YYYYMMDD-hhmmss as UTC ISO", () => {
    expect(vrTime("20190621-054222")).toBe("2019-06-21T05:42:22Z");
    expect(vrTime("  20190621-054222 ")).toBe("2019-06-21T05:42:22Z");
  });

  it("rejects a compact value that is not a real calendar time", () => {
    for (const bad of ["20191345-054222", "20190229-000000", "20190621-240000", "20190621-056099"]) {
      expect(vrTime(bad)).toBe("");
    }
    expect(vrTime("20200229-120000")).toBe("2020-02-29T12:00:00Z"); // leap day is real
  });

  it("dates an Autoruns row by its Time column", () => {
    const row = { Time: "20190621-054222", Entry: "OneDrive", Enabled: "enabled", _ts: 1_790_000_000 };
    expect(pickTime(row)).toBe("2019-06-21T05:42:22Z");
  });

  it("leaves a row with an unparseable compact time undated, never at collection time", () => {
    const row = { Time: "20191345-054222", Entry: "OneDrive", Enabled: "enabled", _ts: 1_790_000_000 };
    expect(pickTime(row)).toBe("");
  });

  it("still dates the row from a later valid time column when a compact one is invalid", () => {
    const row = { EventTime: "20191345-054222", Mtime: "2019-06-21T05:42:22Z", _ts: 1_790_000_000 };
    expect(pickTime(row)).toBe("2019-06-21T05:42:22Z");
  });

  it("stores the ISO time on an imported Windows.Sysinternals.Autoruns event", () => {
    const row = {
      _Source: "Windows.Sysinternals.Autoruns",
      Time: "20190621-054222",
      "Entry Location": "HKCU\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run",
      Entry: "OneDrive",
      Enabled: "enabled",
      Category: "Logon",
      "Image Path": "c:\\users\\alice\\appdata\\local\\microsoft\\onedrive\\onedrive.exe",
      "Launch String": '"C:\\Users\\alice\\AppData\\Local\\Microsoft\\OneDrive\\OneDrive.exe" /background',
      _ts: 1_790_000_000,
    };
    const events = parseVelociraptorJson(JSON.stringify([row])).events;
    expect(events.length).toBeGreaterThan(0);
    for (const e of events) expect(e.timestamp).toBe("2019-06-21T05:42:22Z");
  });
});
