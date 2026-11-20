import { describe, it, expect } from "vitest";
import { parseVelociraptorJson } from "../../src/analysis/velociraptorImport.js";
import { huntFieldsOf, huntItemKey } from "../../src/analysis/huntArtifactFields.js";
import type { ForensicEvent } from "../../src/analysis/stateTypes.js";

// The hunt fields are read from what the REAL Velociraptor importer produces (#2670), not from
// hand-written descriptions: one item per program across hosts, whatever the host suffix looks like.
// The importer's events carry every field the merge copies onto a ForensicEvent; these two are added there.
const rows = (list: object[]): ForensicEvent[] =>
  parseVelociraptorJson(JSON.stringify(list), { aggregate: true }).events.map((e) => ({
    relatedFindingIds: [],
    sourceScreenshots: [],
    ...e,
  }));

describe("hunt fields from real importer rows (#2670)", () => {
  const hosts = ["WS-01", "WS-02.corp.test"];

  it("Prefetch: execution, one item across hosts", () => {
    const ev = rows(
      hosts.map((h) => ({
        _Source: "Windows.Forensics.Prefetch",
        Fqdn: h,
        Executable: "7Z.EXE",
        ExecutablePath: "C:\\Tools\\7z.exe",
        RunCount: 2,
        LastRunTimes: "2026-01-01T00:00:00Z",
      })),
    );
    const f = ev.map(huntFieldsOf);
    expect(f.every((x) => x?.evidence === "execution")).toBe(true);
    expect(new Set(f.map((x) => huntItemKey(x!))).size).toBe(1);
    expect(f[0]).toMatchObject({ program: "7z.exe", pathPattern: "\\tools" });
  });

  it("Prefetch device path and Amcache drive-letter path for one file give ONE item (#2749)", () => {
    // Win10/11 Prefetch (upstream Windows.Forensics.Prefetch): ExecutablePath is the NT device path.
    const ev = rows([
      {
        _Source: "Windows.Forensics.Prefetch",
        Fqdn: "WS-01",
        Executable: "FOO.EXE",
        ExecutablePath: "\\DEVICE\\HARDDISKVOLUME3\\PROGRAM FILES\\FOO\\FOO.EXE",
        ExecutableDosPath: "C:\\PROGRAM FILES\\FOO\\FOO.EXE",
        RunCount: 3,
        LastRunTimes: "2026-01-01T00:00:00Z",
      },
      {
        _Source: "Windows.Forensics.Amcache/InventoryApplicationFile",
        Fqdn: "WS-01",
        FullPath: "c:\\program files\\foo\\foo.exe",
        OriginalFileName: "foo.exe",
        SHA1: "0123456789abcdef0123456789abcdef01234567",
        Size: 12345,
        LastModified: "2026-01-01T00:00:00Z",
      },
    ]);
    const f = ev.map(huntFieldsOf);
    expect(f.map((x) => x?.evidence).sort()).toEqual(["execution", "presence"]);
    expect(new Set(f.map((x) => huntItemKey(x!)))).toEqual(new Set(["program|foo.exe|\\program files\\foo"]));
  });

  it("Amcache installed program with ' - ' in its name: one item, publisher unverified", () => {
    const ev = rows(
      hosts.map((h) => ({
        _Source: "Windows.Forensics.Amcache/InventoryApplication",
        Fqdn: h,
        Name: "Notepad++ - portable",
        Version: "8.6",
        Publisher: "Notepad++ Team",
        InstallDate: "01/01/2026",
        Timestamp: "2026-01-01T00:00:00Z",
      })),
    );
    const f = ev.map(huntFieldsOf);
    expect(f.every((x) => x?.evidence === "installed")).toBe(true);
    expect(new Set(f.map((x) => x!.program))).toEqual(new Set(["notepad++ - portable"]));
    expect(f[0]).toMatchObject({ publisher: "Notepad++ Team", publisherVerified: false });
  });

  it("ShimCache: presence", () => {
    const ev = rows([
      {
        _Source: "Windows.Registry.AppCompatCache",
        Fqdn: "WS-01",
        Path: "C:\\x\\y.exe",
        ExecutionFlag: "true",
        ModificationTime: "2026-01-01T00:00:00Z",
      },
    ]);
    expect(huntFieldsOf(ev[0])).toMatchObject({ evidence: "presence", program: "y.exe" });
  });

  it("Zone.Identifier download: source URL and file", () => {
    const ev = rows([
      {
        _Source: "Windows.Analysis.EvidenceOfDownload",
        Fqdn: "WS-01",
        DownloadedFilePath: "C:\\Users\\bob\\Downloads\\setup.exe",
        HostUrl: "https://dl.example.test/setup.exe",
        ZoneId: "3",
      },
    ]);
    expect(huntFieldsOf(ev[0])).toMatchObject({
      evidence: "download",
      program: "setup.exe",
      sourceUrl: "https://dl.example.test/setup.exe",
    });
  });
});
