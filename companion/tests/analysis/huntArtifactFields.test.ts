import { describe, it, expect } from "vitest";
import {
  huntFieldsOf,
  huntItemKey,
  normalisePathPattern,
  stripVolumePrefix,
} from "../../src/analysis/huntArtifactFields.js";
import { pathPatternMatches } from "../../src/analysis/huntApprovalMatch.js";
import type { ForensicEvent } from "../../src/analysis/stateTypes.js";

const row = (description: string, p: Partial<ForensicEvent> = {}): ForensicEvent => ({
  id: "e",
  timestamp: "2026-01-01T00:00:00Z",
  description,
  severity: "Info",
  mitreTechniques: [],
  relatedFindingIds: [],
  sourceScreenshots: [],
  asset: "WS-01",
  ...p,
});

describe("hunt artifact fields (#2670)", () => {
  it("labels Prefetch and UserAssist as execution", () => {
    const f = huntFieldsOf(
      row(
        "Velociraptor [Windows.Forensics.Prefetch]: Executed (prefetch): 7Z.EXE (C:\\Tools\\7z.exe) - @ WS-01",
        {
          path: "C:\\Tools\\7z.exe",
        },
      ),
    );
    expect(f).toMatchObject({ evidence: "execution", program: "7z.exe", pathPattern: "\\tools" });
    expect(
      huntFieldsOf(row("Velociraptor [X]: Ran (UserAssist) (3×): C:\\a\\b.exe", { path: "c:\\a\\b.exe" }))
        ?.evidence,
    ).toBe("execution");
  });

  it("labels ShimCache and Amcache file rows as presence, never execution", () => {
    const shim = huntFieldsOf(
      row(
        "Velociraptor [Windows.Registry.AppCompatCache]: Present in ShimCache, execution flag set (time shown is the file's modification time): C:\\x\\y.exe",
        { path: "C:\\x\\y.exe" },
      ),
    );
    expect(shim?.evidence).toBe("presence");
    const am = huntFieldsOf(
      row("Velociraptor [Windows.Forensics.Amcache]: Program file present (Amcache): C:\\x\\z.exe", {
        path: "C:\\x\\z.exe",
      }),
    );
    expect(am?.evidence).toBe("presence");
  });

  it("keeps the Amcache publisher as UNVERIFIED text and never as a signer", () => {
    const f = huntFieldsOf(
      row(
        "Velociraptor [Windows.Forensics.Amcache]: Installed program (Amcache): WinRAR v6.2 (win.rar GmbH) - @ WS-01",
      ),
    );
    expect(f).toMatchObject({
      evidence: "installed",
      program: "winrar",
      publisher: "win.rar GmbH",
      publisherVerified: false,
    });
    expect(f?.signer).toBeUndefined();
  });

  it("reads the download source URL and the downloaded file", () => {
    const f = huntFieldsOf(
      row(
        "Velociraptor: Downloaded setup.exe from https://dl.example.test/setup.exe (Internet zone) - @ WS-01",
        {
          path: "C:\\Users\\bob\\Downloads\\setup.exe",
        },
      ),
    );
    expect(f).toMatchObject({
      evidence: "download",
      program: "setup.exe",
      pathPattern: "\\users\\*\\downloads",
      sourceUrl: "https://dl.example.test/setup.exe",
    });
  });

  it("generalises the drive and the user folder, and keeps Temp apart from Program Files", () => {
    expect(normalisePathPattern("C:\\Users\\Alice\\AppData\\Local\\Temp\\chrome.exe")).toBe(
      "\\users\\*\\appdata\\local\\temp",
    );
    expect(normalisePathPattern("D:\\Program Files\\Google\\Chrome\\chrome.exe")).toBe(
      "\\program files\\google\\chrome",
    );
  });

  it("drops NT device, volume-GUID and Win32 namespace prefixes like a drive letter (#2749)", () => {
    for (const p of [
      "C:\\Program Files\\Foo\\foo.exe",
      "\\DEVICE\\HARDDISKVOLUME3\\PROGRAM FILES\\FOO\\FOO.EXE",
      "\\VOLUME{01d2a3b4-0000-0000-0000-100000000000}\\PROGRAM FILES\\FOO\\FOO.EXE",
      "\\\\?\\C:\\Program Files\\Foo\\foo.exe",
      "\\??\\C:\\Program Files\\Foo\\foo.exe",
      "\\\\.\\C:\\Program Files\\Foo\\foo.exe",
      "\\\\?\\Volume{01d2a3b4-0000-0000-0000-100000000000}\\Program Files\\Foo\\foo.exe",
    ])
      expect(normalisePathPattern(p), p).toBe("\\program files\\foo");
    expect(normalisePathPattern("\\Device\\HarddiskVolume12\\Users\\Bob\\AppData\\x.exe")).toBe(
      "\\users\\*\\appdata",
    );
  });

  it("stripVolumePrefix keeps the rest of the path and leaves look-alike folders alone (#2749)", () => {
    expect(stripVolumePrefix("\\device\\harddiskvolume3\\program files\\foo")).toBe("\\program files\\foo");
    expect(stripVolumePrefix("\\device\\harddiskvolume3")).toBe("");
    expect(stripVolumePrefix("\\program files\\foo")).toBe("\\program files\\foo");
    expect(stripVolumePrefix("\\device\\harddiskvolume3x\\foo")).toBe("\\device\\harddiskvolume3x\\foo");
    expect(stripVolumePrefix("\\tools\\device\\harddiskvolume3")).toBe("\\tools\\device\\harddiskvolume3");
  });

  it("maps a leading known-folder GUID to its folder, and leaves unknown GUIDs alone (#2750)", () => {
    const n = normalisePathPattern;
    expect(n("{6D809377-6AF0-444B-8957-A3773F02200E}\\Foo\\foo.exe")).toBe("\\program files\\foo");
    expect(n("{7c5a40ef-a0fb-4bfc-874a-c0f2e0b9fa8e}\\Foo\\foo.exe")).toBe("\\program files (x86)\\foo");
    expect(n("{F38BF404-1D43-42F2-9305-67DE0B28FC23}\\regedit.exe")).toBe("\\windows");
    expect(n("{1AC14E77-02E7-4E5D-B744-2EB1AE5198B7}\\cmd.exe")).toBe("\\windows\\system32");
    expect(n("{F1B32785-6FBA-4FCF-9D55-7B8E7F157091}\\Programs\\x.exe")).toBe(
      "\\users\\*\\appdata\\local\\programs",
    );
    expect(n("{3EB685DB-65F9-4CF6-A03A-E3EF65729F3D}\\x.exe")).toBe("\\users\\*\\appdata\\roaming");
    expect(n("{62AB5D82-FDC1-4DC3-A9DD-070D1D495D97}\\x\\y.exe")).toBe("\\programdata\\x");
    // FOLDERID_ProgramFiles resolves by the CALLING process's bitness: not mapped.
    expect(n("{905E63B6-C1BF-494E-B29C-65B732D3D21A}\\Foo\\foo.exe")).toBe(
      "{905e63b6-c1bf-494e-b29c-65b732d3d21a}\\foo",
    );
    expect(n("{00000000-0000-0000-0000-000000000000}\\x.exe")).toBe("{00000000-0000-0000-0000-000000000000}");
    // Only the whole FIRST segment: a GUID further down the path stays as it is.
    expect(n("C:\\Tools\\{F38BF404-1D43-42F2-9305-67DE0B28FC23}\\x.exe")).toBe(
      "\\tools\\{f38bf404-1d43-42f2-9305-67de0b28fc23}",
    );
    expect(n("{F38BF404-1D43-42F2-9305-67DE0B28FC23}x\\y.exe")).toBe(
      "{f38bf404-1d43-42f2-9305-67de0b28fc23}x",
    );
  });

  it("an approval saved on a GUID-keyed item still matches the folder form (#2750)", () => {
    expect(stripVolumePrefix("{6D809377-6AF0-444B-8957-A3773F02200E}\\Foo")).toBe("\\program files\\Foo");
    expect(pathPatternMatches("{6d809377-6af0-444b-8957-a3773f02200e}\\foo", "\\program files\\foo")).toBe(
      true,
    );
  });

  it("presence and execution of one program at one path are ONE item", () => {
    const a = huntItemKey({ evidence: "execution", program: "x.exe", pathPattern: "\\t" });
    const b = huntItemKey({ evidence: "presence", program: "x.exe", pathPattern: "\\t" });
    expect(a).toBe(b);
    expect(huntItemKey({ evidence: "download", program: "x.exe", pathPattern: "\\t" })).not.toBe(a);
  });

  it("ignores rows that are not Velociraptor hunt evidence, or name no host", () => {
    expect(huntFieldsOf(row("Sysmon process create: x.exe"))).toBeNull();
    expect(
      huntFieldsOf(
        row("Velociraptor [P]: Executed (prefetch): X.EXE", { asset: undefined, path: "c:\\x.exe" }),
      ),
    ).toBeNull();
  });
});
