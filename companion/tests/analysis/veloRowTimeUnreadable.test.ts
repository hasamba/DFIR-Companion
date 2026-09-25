import { describe, it, expect } from "vitest";
import { pickTime, usDateTime, vrTime } from "../../src/analysis/veloRowTime.js";
import { parseVelociraptorJson } from "../../src/analysis/velociraptorImport.js";

// #1631. vrTime passed any string it could not parse through unchanged, and pickTime took that
// non-empty string as a valid time. A column holding "unknown" or "N/A" became the event timestamp:
// the row sorted as text, and the gap, wave and scope passes skipped or misplaced it. An unreadable
// time column now counts as missing. The row is dated by its next valid artifact time, or left
// undated — never at the collection time `_ts`, which would put it inside the incident window.

const TS = 1_790_000_000; // collection time (epoch seconds)
const TS_ISO = new Date(TS * 1000).toISOString();
const JUNK = ["unknown", "N/A", "not a date", "1", "-1", "Mon Jan  2 15:04:05 2006", "2024-02-30T10:00:00Z"];

describe("vrTime — a string that is not a readable time is empty (#1631)", () => {
  it("returns empty for words, bare small numbers, and free-form dates", () => {
    for (const v of JUNK) expect(vrTime(v), v).toBe("");
    expect(vrTime("")).toBe("");
    expect(vrTime("   ")).toBe("");
  });

  it("rejects a canonical-looking time on a day or hour that does not exist", () => {
    for (const v of [
      "2024-02-30T10:00:00Z",
      "2023-02-29T10:00:00Z",
      "2024-13-01T10:00:00Z",
      "2024-01-01T24:00:00Z",
      "2024-01-01T10:60:00Z",
    ]) {
      expect(vrTime(v), v).toBe("");
    }
    expect(vrTime("2024-02-29T10:00:00Z")).toBe("2024-02-29T10:00:00Z"); // leap day is real
  });

  it("keeps an RFC3339 UTC time as written, fraction and all", () => {
    for (const v of [
      "2026-09-24T08:58:30Z",
      "2026-09-24T08:58:30.6Z",
      "2026-09-24T08:58:30.653Z",
      "2026-09-24T08:58:30.6531008Z",
      "2026-09-24T08:58:30.653100812Z",
    ]) {
      expect(vrTime(v), v).toBe(v);
    }
  });

  it("converts an offset time and a naive time to UTC", () => {
    expect(vrTime("2026-09-24T10:58:30+02:00")).toBe("2026-09-24T08:58:30.000Z");
    expect(vrTime("2026-09-24 08:58:30")).toBe("2026-09-24T08:58:30Z");
  });

  it("reads Go's time.String form, applying a non-zero offset", () => {
    expect(vrTime("2025-12-05 02:41:36 +0000 UTC")).toMatch(/^2025-12-05T02:41:36(\.000)?Z$/);
    expect(vrTime("2025-12-05 04:41:36 +0200 EET")).toMatch(/^2025-12-05T02:41:36(\.000)?Z$/);
    expect(vrTime("2025-12-05 00:41:36.5 -0200")).toMatch(/^2025-12-05T02:41:36\.500Z$/);
    expect(vrTime("2025-02-30 02:41:36 +0000 UTC")).toBe("");
  });

  it("reads epoch digits from a CSV export: 10 digits are seconds, 13 are milliseconds", () => {
    expect(vrTime(String(TS))).toBe(TS_ISO);
    expect(vrTime(`${TS}.5`)).toBe(new Date(TS * 1000 + 500).toISOString());
    expect(vrTime(String(TS * 1000))).toBe(TS_ISO);
    expect(vrTime("1000000000000")).toBe("2001-09-09T01:46:40.000Z");
    expect(vrTime("20260828")).toBe(""); // Windows.Sys.Programs YYYYMMDD — not an epoch
  });

  it("reads a date-only value as UTC midnight", () => {
    expect(vrTime("2024-01-15")).toBe("2024-01-15T00:00:00Z");
    expect(vrTime("2024-02-30")).toBe("");
  });

  it("still reads numbers and { SystemTime } objects", () => {
    expect(vrTime(TS)).toBe(TS_ISO);
    expect(vrTime({ SystemTime: 1764905204.7057536 })).toMatch(/^2025-12-05T03:26:44/);
    expect(vrTime(0)).toBe("");
  });
});

describe("usDateTime — the Amcache InstallDate form", () => {
  it("reads MM/DD/YYYY hh:mm:ss as UTC, from its parts", () => {
    expect(usDateTime("12/05/2025 00:00:00")).toBe("2025-12-05T00:00:00Z");
    expect(usDateTime("02/29/2024 13:14:15")).toBe("2024-02-29T13:14:15Z");
  });

  it("rejects a day that does not exist and anything else", () => {
    for (const v of ["02/29/2023 00:00:00", "13/05/2025 00:00:00", "12/05/2025", "unknown", null]) {
      expect(usDateTime(v), String(v)).toBe("");
    }
  });
});

describe("pickTime — an unreadable time column is missing, and blocks the collection time (#1631)", () => {
  it("moves on to the next valid time column", () => {
    expect(pickTime({ EventTime: "unknown", Mtime: "2026-09-01T10:00:00Z", _ts: TS })).toBe(
      "2026-09-01T10:00:00Z",
    );
  });

  it("uses a valid fallback-scanned artifact time after an unreadable known column", () => {
    expect(pickTime({ time: "N/A", _SourceLastModificationTimestamp: "2026-08-26T13:53:11Z", _ts: TS })).toBe(
      "2026-08-26T13:53:11Z",
    );
  });

  it("leaves the row undated when no other artifact time exists", () => {
    for (const v of JUNK) expect(pickTime({ time: v, Name: "x", _ts: TS }), v).toBe("");
  });

  it("an unreadable preferred column blocks the collection time too", () => {
    expect(pickTime({ ModTime: "unknown", _ts: TS }, ["ModTime"])).toBe("");
    expect(
      pickTime({ ModTime: "unknown", ModificationTime: "2026-01-02T03:04:05Z", _ts: TS }, [
        "ModTime",
        "ModificationTime",
      ]),
    ).toBe("2026-01-02T03:04:05Z");
  });

  it("reads the first element of an array column, and moves on when it is unreadable", () => {
    const row = { LastRunTimes: ["garbage", "2026-08-28T10:54:48Z"], CreationTime: "2026-08-28T10:54:53Z" };
    expect(pickTime(row, ["LastRunTimes", "CreationTime"])).toBe("2026-08-28T10:54:53Z");
    expect(pickTime({ LastRunTimes: [], _ts: TS }, ["LastRunTimes"])).toBe(TS_ISO);
  });

  it("does not treat a blank or all-zero unset value as unreadable", () => {
    for (const v of ["", "  ", "0", "0.0", "000"]) {
      expect(pickTime({ time: v, _ts: TS }), JSON.stringify(v)).toBe(TS_ISO);
    }
  });

  it("an unreadable value in a column that only looks time-named does not block the collection time", () => {
    // TIME_NAME_RE deliberately over-matches (AccessMask, visit_duration, DriverDate); those are not times.
    expect(
      pickTime({ AccessMask: "0x1", visit_duration: "00:00:00.000", DriverDate: "06/21/2006", _ts: TS }),
    ).toBe(TS_ISO);
  });
});

// Real-shaped rows (from the Velociraptor eval corpus, values sanitized) for each common artifact:
// the valid row keeps its time; the same row with "unknown" in its time column never gets `_ts`.
function importedTimes(row: Record<string, unknown>): string[] {
  return parseVelociraptorJson(JSON.stringify([{ ...row, _ts: TS }])).events.map((e) => e.timestamp);
}

const ARTIFACTS: { name: string; row: Record<string, unknown>; timeKey: string; want: RegExp }[] = [
  {
    name: "Windows.EventLogs.Evtx",
    row: {
      _Source: "Windows.EventLogs.Evtx",
      System: {
        Provider: { Name: "Microsoft-Windows-Search" },
        EventID: { Value: 1013 },
        TimeCreated: { SystemTime: 1764905204.7057536 },
        Channel: "Application",
      },
      EventData: { Data: { Name: "ExtraInfo", Value: "\n" } },
      Message: "Windows Search Service stopped normally.",
      TimeCreated: "2025-12-05T03:26:44Z",
      Channel: "Application",
      EventID: 1013,
    },
    timeKey: "TimeCreated",
    want: /^2025-12-05T03:26:44/,
  },
  {
    name: "Windows.Forensics.Prefetch",
    row: {
      _Source: "Windows.Forensics.Prefetch",
      Executable: "EXAMPLE.EXE",
      LastRunTimes: ["2026-08-28T10:54:48Z"],
      RunCount: 1,
      ExecutableDosPath: "C:\\Users\\Public\\EXAMPLE.EXE",
      OSPath: "C:\\Windows\\Prefetch\\EXAMPLE.EXE-FE51F0AA.pf",
      PrefetchFileName: "EXAMPLE.EXE-FE51F0AA.pf",
    },
    timeKey: "LastRunTimes",
    want: /^2026-08-28T10:54:48/,
  },
  {
    name: "Windows.Applications.Chrome.History",
    row: {
      _Source: "Windows.Applications.Chrome.History",
      User: "alice",
      visit_time: "2026-08-26T13:53:11Z",
      visited_url: "https://example.com/",
      title: "",
      visit_count: 1,
      visit_duration: "00:00:00.000",
      OSPath: "C:\\Users\\alice\\AppData\\Local\\Google\\Chrome\\User Data\\Default\\History",
    },
    timeKey: "visit_time",
    want: /^2026-08-26T13:53:11/,
  },
  {
    name: "Windows.Registry.UserAssist",
    row: {
      _Source: "Windows.Registry.UserAssist",
      Name: "C:\\Users\\Public\\example.exe",
      User: "alice",
      LastExecution: "2026-08-28T11:02:03Z",
      NumberOfExecutions: 2,
    },
    timeKey: "LastExecution",
    want: /^2026-08-28T11:02:03/,
  },
  {
    name: "Windows.Forensics.Shellbags",
    row: {
      _Source: "Windows.Forensics.Shellbags",
      KeyPath: "Local Settings\\Software\\Microsoft\\Windows\\Shell\\BagMRU",
      FullPath: "Downloads",
      _RawData: "OgAfAAU5jggjAwJLmCZdmUKOEV8mAAEAJgDvvhEAAAD",
      ModTime: "2026-08-28T11:10:18Z",
      Description: { LongName: "Downloads", Type: "Root" },
    },
    timeKey: "ModTime",
    want: /^2026-08-28T11:10:18/,
  },
  {
    name: "Windows.Registry.AppCompatCache",
    row: {
      _Source: "Windows.Registry.AppCompatCache",
      Position: 0,
      ModificationTime: "2025-12-05T02:54:10Z",
      Path: "C:\\WINDOWS\\system32\\compattelrunner.exe",
      ExecutionFlag: 0,
    },
    timeKey: "ModificationTime",
    want: /^2025-12-05T02:54:10/,
  },
  {
    name: "Windows.Forensics.Amcache/InventoryApplication",
    row: {
      _Source: "Windows.Forensics.Amcache/InventoryApplication",
      Timestamp: "2026-08-28T11:15:23Z",
      Name: "Example.App",
      Version: "1.0.0",
      Publisher: "CN=Example",
      InstallDate: null,
    },
    timeKey: "Timestamp",
    want: /^2026-08-28T11:15:23/,
  },
  {
    name: "Windows.Sys.Programs",
    row: {
      _Source: "Windows.Sys.Programs",
      KeyName: "ExampleApp",
      KeyLastWriteTimestamp: "2024-04-01T07:28:56.5698501Z",
      DisplayName: "Example App",
      InstallDate: "20260828",
      KeyPath: "HKEY_LOCAL_MACHINE\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Uninstall\\ExampleApp",
    },
    timeKey: "KeyLastWriteTimestamp",
    want: /^2024-04-01T07:28:56/,
  },
  {
    name: "Windows.Sysinternals.Autoruns",
    row: {
      _Source: "Windows.Sysinternals.Autoruns",
      Time: "20240401-072632",
      "Entry Location": "HKLM\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run",
      Entry: "Example",
      Enabled: "enabled",
      Category: "Logon",
      "Image Path": "c:\\users\\public\\example.exe",
    },
    timeKey: "Time",
    want: /^2024-04-01T07:26:32/,
  },
];

describe("imported Velociraptor rows — each common artifact (#1631)", () => {
  for (const { name, row, timeKey, want } of ARTIFACTS) {
    it(`${name}: a valid time dates the event`, () => {
      const times = importedTimes(row);
      expect(times.length).toBeGreaterThan(0);
      for (const t of times) expect(t).toMatch(want);
    });

    it(`${name}: an unreadable time is never stored, and never replaced by the collection time`, () => {
      const bad = { ...row, [timeKey]: Array.isArray(row[timeKey]) ? ["unknown"] : "unknown" };
      const times = importedTimes(bad);
      expect(times.length).toBeGreaterThan(0);
      for (const t of times) {
        expect(t).not.toContain("unknown");
        expect(t).not.toBe(TS_ISO);
        expect(t === "" || /^\d{4}-\d{2}-\d{2}T/.test(t)).toBe(true);
      }
    });
  }

  it("Amcache InventoryApplication: a US InstallDate dates the row when Timestamp is unreadable", () => {
    const row = { ...ARTIFACTS[6].row, Timestamp: "unknown", InstallDate: "12/05/2025 00:00:00" };
    expect(importedTimes(row)).toEqual(["2025-12-05T00:00:00Z"]);
  });

  it("Amcache InventoryApplication: an unreadable InstallDate with no Timestamp stays undated", () => {
    const { Timestamp: _t, ...rest } = ARTIFACTS[6].row;
    void _t;
    expect(importedTimes({ ...rest, InstallDate: "13/45/2025 00:00:00" })).toEqual([""]);
  });

  it("Windows.NTFS.MFT: an unreadable MACB column produces no event at that string", () => {
    const row = {
      _Source: "Windows.NTFS.MFT",
      EntryNumber: 42,
      OSPath: "\\\\.\\C:\\Users\\Public\\example.exe",
      FileName: "example.exe",
      Created0x10: "unknown",
      Created0x30: "2025-12-05T11:35:58.6292303Z",
      LastModified0x10: "2025-12-05T11:35:58.6292303Z",
    };
    const times = importedTimes(row);
    expect(times).toEqual(["2025-12-05T11:35:58.6292303Z"]);
  });
});

describe("vrTime — an offset time on a day that does not exist is not rolled over (#1631)", () => {
  it("rejects Feb 30 with an offset instead of reading it as March 1", () => {
    expect(vrTime("2024-02-30T10:00:00+02:00")).toBe("");
    expect(vrTime("2024-01-01T25:00:00+02:00")).toBe("");
  });
});

describe("vrTime — a year below 100 is read as written", () => {
  // Date.UTC maps years 0–99 to 19xx. Velociraptor prints Go's zero time for an unset time; that value
  // is a sentinel question, not a parse question, so it keeps reading exactly as it did before #1631.
  it("keeps Go's zero time unchanged", () => {
    expect(vrTime("0001-01-01T00:00:00Z")).toBe("0001-01-01T00:00:00Z");
  });
});

describe("pickTime — an unreadable structured or numeric time blocks the collection time (#1631)", () => {
  it("a { SystemTime } wrapper whose leaf is unreadable leaves the row undated", () => {
    expect(pickTime({ System: { TimeCreated: { SystemTime: "unknown" } }, _ts: TS })).toBe("");
    expect(pickTime({ System: { TimeCreated: { "#attributes": { SystemTime: "N/A" } } }, _ts: TS })).toBe("");
  });

  it("a positive epoch too large to be a date leaves the row undated", () => {
    expect(pickTime({ EventTime: 1e20, _ts: TS })).toBe("");
  });

  it("a zero epoch or an empty wrapper is unset, not unreadable", () => {
    expect(pickTime({ EventTime: 0, _ts: TS })).toBe(TS_ISO);
    expect(pickTime({ System: { TimeCreated: {} }, _ts: TS })).toBe(TS_ISO);
  });
});
