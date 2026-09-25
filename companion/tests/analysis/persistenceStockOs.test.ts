// #1665: on a clean Windows 11 image, PersistenceSniper graded three stock Store apps (App Paths under
// C:\Program Files\WindowsApps\, per-file NotSigned because MSIX files are catalog-signed) and the two
// stock per-user OneDrive tasks (OneDriveStandaloneUpdater.exe is a LOLBin outside System32) High.
// Fixtures follow the raw row shapes of that collection; SIDs and user names are synthetic.
import { describe, it, expect } from "vitest";
import { mapPersistenceSniper } from "../../src/analysis/persistenceSniperImport.js";
import { isMicrosoftStoreAppPath, isStockOneDriveTask } from "../../src/analysis/persistenceStockOs.js";

type Row = Record<string, unknown>;

const SID = "S-1-5-21-1111111111-2222222222-3333333333-1001";
const PAINT =
  "C:\\Program Files\\WindowsApps\\Microsoft.Paint_11.2302.20.0_x64__8wekyb3d8bbwe\\PaintApp\\mspaint.exe";
const NOTEPAD =
  "C:\\Program Files\\WindowsApps\\Microsoft.WindowsNotepad_11.2312.18.0_x64__8wekyb3d8bbwe\\Notepad\\Notepad.exe";
const SNIP =
  "C:\\Program Files\\WindowsApps\\Microsoft.ScreenSketch_11.2307.52.0_x64__8wekyb3d8bbwe\\SnippingTool\\SnippingTool.exe";
const UPDATER = "%localappdata%\\Microsoft\\OneDrive\\OneDriveStandaloneUpdater.exe";

function appPathsRow(value: string, over: Row = {}): Row {
  return {
    Technique: "App Paths",
    Classification: "MITRE ATT&CK T1546",
    Path: `HKEY_USERS\\${SID}\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\App Paths\\x.exe\\(Default)`,
    Value: value,
    "Access Gained": "System/User",
    Signature: "Status = NotSigned, Subject = ",
    IsLolbin: "False",
    IsBuiltinBinary: "False",
    ...over,
  };
}

function oneDriveRow(task: string, value: string, over: Row = {}): Row {
  return {
    Technique: "Scheduled Task",
    Classification: "MITRE ATT&CK T1053.005",
    Path: `\\${task}-${SID}`,
    Value: value,
    "Access Gained": "User",
    Signature: "Status = , Subject = ",
    IsLolbin: "True",
    IsBuiltinBinary: "False",
    ...over,
  };
}

const grade = (row: Row) => mapPersistenceSniper(row, "HOST1", new Map(), "2026-01-01T00:00:00Z");

describe("#1665 stock Store apps (App Paths under WindowsApps)", () => {
  it.each([PAINT, NOTEPAD, SNIP])("grades %s Info with no signature marker", (value) => {
    const ev = grade(appPathsRow(value));
    expect(ev.severity).toBe("Info");
    expect(ev.description).not.toContain("[signature:");
  });

  it("accepts the quoted form", () => {
    expect(grade(appPathsRow(`"${PAINT}"`)).severity).toBe("Info");
  });

  it("an unsigned binary in a user-writable path with System access still grades High", () => {
    for (const value of ["C:\\Users\\Public\\evil.exe", "C:\\ProgramData\\Vendor\\evil.exe"]) {
      expect(grade(appPathsRow(value, { "Access Gained": "System" })).severity).toBe("High");
    }
  });

  it.each([
    [
      "fake WindowsApps under Public",
      "C:\\Users\\Public\\WindowsApps\\Microsoft.Paint_11.2302.20.0_x64__8wekyb3d8bbwe\\PaintApp\\mspaint.exe",
    ],
    [
      "fake Program Files under ProgramData",
      "C:\\ProgramData\\Program Files\\WindowsApps\\Microsoft.Paint_11.2302.20.0_x64__8wekyb3d8bbwe\\PaintApp\\mspaint.exe",
    ],
    [
      "another drive",
      "D:\\Program Files\\WindowsApps\\Microsoft.Paint_11.2302.20.0_x64__8wekyb3d8bbwe\\PaintApp\\mspaint.exe",
    ],
    [
      "Program Files (x86)",
      "C:\\Program Files (x86)\\WindowsApps\\Microsoft.Paint_11.2302.20.0_x64__8wekyb3d8bbwe\\PaintApp\\mspaint.exe",
    ],
    [
      "WindowsApps with a trailing dot",
      "C:\\Program Files\\WindowsApps.\\Microsoft.Paint_11.2302.20.0_x64__8wekyb3d8bbwe\\PaintApp\\mspaint.exe",
    ],
    [
      "traversal out of the package",
      "C:\\Program Files\\WindowsApps\\Microsoft.Paint_11.2302.20.0_x64__8wekyb3d8bbwe\\..\\..\\..\\Users\\Public\\evil.exe",
    ],
    [
      "dot segment",
      "C:\\Program Files\\WindowsApps\\Microsoft.Paint_11.2302.20.0_x64__8wekyb3d8bbwe\\.\\evil.exe",
    ],
    [
      "trailing-dot segment",
      "C:\\Program Files\\WindowsApps\\Microsoft.Paint_11.2302.20.0_x64__8wekyb3d8bbwe\\PaintApp.\\evil.exe",
    ],
    [
      "forward slashes",
      "C:/Program Files/WindowsApps/Microsoft.Paint_11.2302.20.0_x64__8wekyb3d8bbwe/PaintApp/mspaint.exe",
    ],
    [
      "device prefix",
      "\\\\?\\C:\\Program Files\\WindowsApps\\Microsoft.Paint_11.2302.20.0_x64__8wekyb3d8bbwe\\PaintApp\\mspaint.exe",
    ],
    [
      "UNC path",
      "\\\\fileserver.example.com\\share\\WindowsApps\\Microsoft.Paint_11.2302.20.0_x64__8wekyb3d8bbwe\\mspaint.exe",
    ],
    [
      "alternate data stream",
      "C:\\Program Files\\WindowsApps\\Microsoft.Paint_11.2302.20.0_x64__8wekyb3d8bbwe\\PaintApp\\mspaint.exe:evil.exe",
    ],
    ["path plus a second payload", `${PAINT} C:\\Users\\Public\\evil.exe`],
    ["path plus arguments", `${PAINT} /s evil`],
    [
      "empty segment",
      "C:\\Program Files\\WindowsApps\\Microsoft.Paint_11.2302.20.0_x64__8wekyb3d8bbwe\\\\evil.exe",
    ],
    ["unbalanced quote", `"${PAINT}`],
    [
      "non-Microsoft publisher ID",
      "C:\\Program Files\\WindowsApps\\Contoso.App_1.0.0.0_x64__abcdefgh12345\\App\\app.exe",
    ],
    [
      "package folder without a version",
      "C:\\Program Files\\WindowsApps\\Microsoft.Paint_x64__8wekyb3d8bbwe\\PaintApp\\mspaint.exe",
    ],
    [
      "package folder with an unknown arch",
      "C:\\Program Files\\WindowsApps\\Microsoft.Paint_11.2302.20.0_mips__8wekyb3d8bbwe\\PaintApp\\mspaint.exe",
    ],
    [
      "not an executable",
      "C:\\Program Files\\WindowsApps\\Microsoft.Paint_11.2302.20.0_x64__8wekyb3d8bbwe\\PaintApp\\readme.txt",
    ],
    [
      "the package folder itself",
      "C:\\Program Files\\WindowsApps\\Microsoft.Paint_11.2302.20.0_x64__8wekyb3d8bbwe",
    ],
  ])("%s keeps today's High grade", (_label, value) => {
    expect(isMicrosoftStoreAppPath(value)).toBe(false);
    expect(grade(appPathsRow(value)).severity).toBe("High");
  });

  it("only NotSigned is expected for a Store file — HashMismatch and NotTrusted still grade High", () => {
    for (const status of ["HashMismatch", "NotTrusted", "UnknownError"]) {
      const ev = grade(appPathsRow(PAINT, { Signature: `Status = ${status}, Subject = ` }));
      expect(ev.severity).toBe("High");
      expect(ev.description).toContain(`[signature: ${status}]`);
    }
  });

  it("the same Store path under any technique other than App Paths keeps today's grade", () => {
    for (const technique of ["Service", "Scheduled Task", "Registry Run Key"]) {
      expect(grade(appPathsRow(PAINT, { Technique: technique })).severity).toBe("High");
    }
  });

  it("a Store app does not hide a LOLBin signal", () => {
    expect(grade(appPathsRow(PAINT, { IsLolbin: "True" })).severity).toBe("High");
  });

  it("matching is case-insensitive, like NTFS", () => {
    expect(isMicrosoftStoreAppPath(PAINT.toLowerCase())).toBe(true);
    expect(isMicrosoftStoreAppPath(PAINT.replace("8wekyb3d8bbwe", "8WEKYB3D8BBWE"))).toBe(true);
  });
});

describe("#1665 stock per-user OneDrive tasks", () => {
  const REPORTING = "OneDrive Reporting Task";
  const UPDATE = "OneDrive Standalone Update Task";

  it("the reporting task with /reporting grades Info", () => {
    const ev = grade(oneDriveRow(REPORTING, `${UPDATER} /reporting`));
    expect(ev.severity).toBe("Info");
    expect(ev.description).not.toContain("[lolbin]");
  });

  it("the update task with no argument grades Info (the collector leaves a trailing space)", () => {
    expect(grade(oneDriveRow(UPDATE, `${UPDATER} `)).severity).toBe("Info");
    expect(grade(oneDriveRow(UPDATE, UPDATER)).severity).toBe("Info");
  });

  it("accepts the resolved profile path and the quoted form", () => {
    const resolved = "C:\\Users\\analyst\\AppData\\Local\\Microsoft\\OneDrive\\OneDriveStandaloneUpdater.exe";
    expect(grade(oneDriveRow(UPDATE, resolved)).severity).toBe("Info");
    expect(grade(oneDriveRow(REPORTING, `"${resolved}" /reporting`)).severity).toBe("Info");
    expect(grade(oneDriveRow(REPORTING, `"${UPDATER}" /reporting`)).severity).toBe("Info");
  });

  it.each([
    ["the updater under %TEMP%", REPORTING, "%TEMP%\\OneDriveStandaloneUpdater.exe /reporting", {}],
    [
      "the updater staged in the Temp folder",
      REPORTING,
      "C:\\Users\\analyst\\AppData\\Local\\Temp\\OneDriveStandaloneUpdater.exe /reporting",
      {},
    ],
    ["an unknown argument", REPORTING, `${UPDATER} /reporting /url https://evil.example.com`, {}],
    ["an argument on the update task", UPDATE, `${UPDATER} /reporting`, {}],
    ["no argument on the reporting task", REPORTING, UPDATER, {}],
    ["another executable name", REPORTING, "%localappdata%\\Microsoft\\OneDrive\\evil.exe /reporting", {}],
    [
      "another folder",
      REPORTING,
      "%localappdata%\\Microsoft\\OneDriveX\\OneDriveStandaloneUpdater.exe /reporting",
      {},
    ],
    [
      "traversal in the profile path",
      UPDATE,
      "C:\\Users\\..\\ProgramData\\AppData\\Local\\Microsoft\\OneDrive\\OneDriveStandaloneUpdater.exe",
      {},
    ],
    ["a bad signature", REPORTING, `${UPDATER} /reporting`, { Signature: "Status = NotSigned, Subject = " }],
    ["System access", REPORTING, `${UPDATER} /reporting`, { "Access Gained": "System" }],
    ["missing access", REPORTING, `${UPDATER} /reporting`, { "Access Gained": "" }],
    [
      "a non-scheduled-task technique",
      REPORTING,
      `${UPDATER} /reporting`,
      { Technique: "Registry Run Key", Path: `\\${REPORTING}-${SID}` },
    ],
  ])("%s still grades High", (_label, task, value, over) => {
    expect(grade(oneDriveRow(task, value, over)).severity).toBe("High");
  });

  it.each([
    ["a non-stock task name", "\\OneDrive Updater Task-" + SID],
    ["a task in a subfolder", "\\Microsoft\\OneDrive Reporting Task-" + SID],
    ["a task name with no SID", "\\OneDrive Reporting Task"],
    ["a non-domain SID", "\\OneDrive Reporting Task-S-1-5-18"],
    ["a suffix after the SID", `\\OneDrive Reporting Task-${SID}-evil`],
  ])("%s still grades High", (_label, taskPath) => {
    expect(grade(oneDriveRow(REPORTING, `${UPDATER} /reporting`, { Path: taskPath })).severity).toBe("High");
  });

  it("the predicate itself refuses a staged path even with a stock task name", () => {
    expect(
      isStockOneDriveTask({
        technique: "Scheduled Task",
        path: `\\${UPDATE}-${SID}`,
        value: "%TEMP%\\OneDriveStandaloneUpdater.exe",
        accessGained: "User",
      }),
    ).toBe(false);
  });
});

describe("#1665 an empty signature status means unknown, not unsigned", () => {
  it("sets no signature marker and no Medium grade on its own", () => {
    const ev = grade({
      Technique: "Registry Run Key",
      Classification: "MITRE ATT&CK T1547.001",
      Path: "HKEY_LOCAL_MACHINE\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run\\Vendor",
      Value: "%ProgramFiles%\\Vendor\\agent.exe",
      "Access Gained": "System",
      Signature: "Status = , Subject = ",
      IsLolbin: "False",
      IsBuiltinBinary: "False",
    });
    expect(ev.severity).toBe("Info");
    expect(ev.description).not.toContain("[signature:");
  });
});
