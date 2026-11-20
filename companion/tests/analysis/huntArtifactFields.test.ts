import { describe, it, expect } from "vitest";
import {
  huntFieldsOf,
  huntItemKey,
  normalisePathPattern,
  stripVolumePrefix,
} from "../../src/analysis/huntArtifactFields.js";
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
