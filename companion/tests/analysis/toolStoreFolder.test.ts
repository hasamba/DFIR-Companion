import { describe, it, expect } from "vitest";
import {
  linkToolStoreFolders,
  isToolStoreRow,
  toolFamilyOf,
  TOOL_STORE_MARKER,
  TOOL_STORE_MIN_TOOLS,
} from "../../src/analysis/toolStoreFolder.js";
import { AD_RECON_TOOLS, DUAL_USE } from "../../src/analysis/attackToolNames.js";
import { TRANSFER_TOOL_NAMES } from "../../src/analysis/transferToolStaging.js";
import { DERIVED_NOTE_NAMES } from "../../src/analysis/derivedNote.js";
import { mergeLoadAlways, mergeTrigger } from "../../src/analysis/mergeIndex.js";
import type { ForensicEvent } from "../../src/analysis/stateTypes.js";

// #1970 part 1: one user-writable folder on one host that holds three or more different attack
// tools (the lab case: PsExec, AdFind and WinRAR in C:\Users\Public\Music) is one Medium lead.

const T = "2026-05-02T10:00:00.000Z";
const at = (s: number) => new Date(Date.parse(T) + s * 1000).toISOString();
const DIR = "C:\\Users\\Public\\Music";

function ev(id: string, p: Partial<ForensicEvent> = {}): ForensicEvent {
  return {
    id,
    timestamp: T,
    description: `row ${id}`,
    severity: "Info",
    mitreTechniques: [],
    relatedFindingIds: [],
    sourceScreenshots: [],
    asset: "WS01",
    sources: ["MFT"],
    ...p,
  };
}

const file = (id: string, name: string, s = 0, p: Partial<ForensicEvent> = {}) =>
  ev(id, { path: `${DIR}\\${name}`, timestamp: at(s), description: `File created: ${name}`, ...p });
const trio = () => [file("ps", "PsExec.exe"), file("ad", "AdFind.exe", 30), file("rar", "WinRAR.exe", 60)];
const byId = (rows: ForensicEvent[], id: string) => rows.find((e) => e.id === id)!;

describe("linkToolStoreFolders", () => {
  it("raises one row per tool to Medium when three tools share a user-writable folder", () => {
    const out = linkToolStoreFolders(trio());
    for (const id of ["ps", "ad", "rar"]) {
      const e = byId(out, id);
      expect(e.severity).toBe("Medium");
      expect(e.description).toContain(TOOL_STORE_MARKER);
      expect(e.description.toLowerCase()).toContain("users\\public\\music");
      expect(e.description).toMatch(/psexec/i);
      expect(e.description).toMatch(/adfind/i);
      expect(e.description).toMatch(/winrar/i);
    }
    expect(TOOL_STORE_MIN_TOOLS).toBe(3);
  });

  it("leaves two tools alone", () => {
    const rows = [file("ps", "PsExec.exe"), file("ad", "AdFind.exe", 30)];
    expect(linkToolStoreFolders(rows)).toEqual(rows);
  });

  it("leaves three tools under Program Files alone", () => {
    const rows = ["PsExec.exe", "AdFind.exe", "WinRAR.exe"].map((n, i) =>
      ev(`p${i}`, { path: `C:\\Program Files\\Tools\\${n}`, description: `File created: ${n}` }),
    );
    expect(linkToolStoreFolders(rows)).toEqual(rows);
  });

  it("leaves three tools on three different hosts alone", () => {
    const rows = trio().map((e, i) => ({ ...e, asset: `WS0${i + 1}` }));
    expect(linkToolStoreFolders(rows)).toEqual(rows);
  });

  it("leaves three tools in three different user-writable folders alone", () => {
    const rows = trio().map((e, i) => ({
      ...e,
      path: `C:\\Users\\Public\\F${i}\\${e.path!.split("\\").pop()}`,
    }));
    expect(linkToolStoreFolders(rows)).toEqual(rows);
  });

  it("counts two binaries of one tool once (rar.exe and WinRAR.exe, 7z.exe and 7za.exe)", () => {
    const rows = [file("a", "rar.exe"), file("b", "WinRAR.exe"), file("c", "7z.exe"), file("d", "7za.exe")];
    expect(linkToolStoreFolders(rows)).toEqual(rows);
    expect(toolFamilyOf("rar.exe")).toBe(toolFamilyOf("winrar.exe"));
    expect(toolFamilyOf("7z.exe")).toBe(toolFamilyOf("7za.exe"));
  });

  it("counts an offensive tool by its name token, a recon script, and a transfer tool", () => {
    const rows = [file("m", "mimikatz_x64.exe"), file("s", "SharpHound.ps1"), file("r", "rclone.exe")];
    const out = linkToolStoreFolders(rows);
    for (const id of ["m", "s", "r"]) expect(byId(out, id).severity).toBe("Medium");
  });

  it("raises one row per tool, the earliest, and keeps a higher grade", () => {
    const rows = [
      ...trio(),
      file("ps2", "PsExec.exe", 300, { sources: ["Amcache"], description: "Amcache: PsExec.exe" }),
      file("mk", "mimikatz.exe", 90, { severity: "High" }),
    ];
    const out = linkToolStoreFolders(rows);
    expect(byId(out, "ps").severity).toBe("Medium");
    expect(byId(out, "ps2").severity).toBe("Info");
    expect(byId(out, "ps2").description).not.toContain(TOOL_STORE_MARKER);
    expect(byId(out, "mk").severity).toBe("High");
    expect(byId(out, "mk").description).toContain(TOOL_STORE_MARKER);
  });

  it("matches an MFT relative path and an NT device path in the same folder", () => {
    const rows = [
      ev("a", { path: ".\\Users\\Public\\Music\\PsExec.exe" }),
      ev("b", { path: "\\Device\\HarddiskVolume3\\Users\\Public\\Music\\ADFIND.EXE" }),
      ev("c", { path: "C:/Users/Public/Music/7z.exe" }),
    ];
    const out = linkToolStoreFolders(rows);
    for (const id of ["a", "b", "c"]) expect(byId(out, id).severity).toBe("Medium");
  });

  it("puts a \\\\.\\ or \\\\?\\ device path in the same folder as the plain path (one lead, not two)", () => {
    const rows = [
      file("a", "PsExec.exe"),
      file("b", "AdFind.exe"),
      file("c", "WinRAR.exe"),
      ev("d", { path: "\\\\.\\C:\\Users\\Public\\Music\\PsExec.exe" }),
      ev("e", { path: "\\\\.\\C:\\Users\\Public\\Music\\AdFind.exe" }),
      ev("f", { path: "\\\\.\\C:\\Users\\Public\\Music\\WinRAR.exe" }),
      ev("g", { path: "\\\\?\\C:\\Users\\Public\\Music\\7z.exe" }),
    ];
    const out = linkToolStoreFolders(rows);
    expect(out.filter((e) => e.description.includes(TOOL_STORE_MARKER)).map((e) => e.id)).toEqual([
      "a",
      "b",
      "c",
      "g",
    ]);
  });

  it("ignores a non-binary file named after a tool", () => {
    const rows = [file("ps", "PsExec.exe"), file("ad", "AdFind.exe", 30), file("log", "winrar.txt", 60)];
    expect(linkToolStoreFolders(rows)).toEqual(rows);
  });

  it("is idempotent", () => {
    const once = linkToolStoreFolders(trio());
    expect(linkToolStoreFolders(once)).toEqual(once);
  });

  it("takes its note off when the other tools have left the case, and keeps the severity", () => {
    const once = linkToolStoreFolders(trio());
    const out = linkToolStoreFolders([byId(once, "ps"), byId(once, "ad")]);
    expect(byId(out, "ps").description).not.toContain(TOOL_STORE_MARKER);
    expect(byId(out, "ps").severity).toBe("Medium");
  });

  it("keeps the raised row as the lead when an earlier Info row of the same tool arrives later", () => {
    const once = linkToolStoreFolders(trio());
    const out = linkToolStoreFolders([...once, file("ps0", "PsExec.exe", -600)]);
    expect(byId(out, "ps").description).toContain(TOOL_STORE_MARKER);
    expect(byId(out, "ps0").severity).toBe("Info");
  });

  it("returns the input untouched when no row names a tool", () => {
    const rows = [ev("a", { path: "C:\\x\\notepad.exe" }), ev("b")];
    expect(linkToolStoreFolders(rows)).toBe(rows);
  });

  it("registers its marker as a derived note", () => {
    expect(DERIVED_NOTE_NAMES).toContain(TOOL_STORE_MARKER.slice(1, -1));
  });
});

describe("the curated list reuses the project's name lists", () => {
  it("knows every remote-execution and transfer name of the Prefetch grader, every AD recon tool and the archivers", () => {
    const remote = Object.entries(DUAL_USE)
      .filter(([, ids]) => ids.some((t) => t === "T1569.002" || t === "T1567.002"))
      .map(([n]) => n);
    expect(remote).toEqual(expect.arrayContaining(["psexec.exe", "paexec.exe", "rclone.exe"]));
    for (const n of [...remote, ...TRANSFER_TOOL_NAMES, "rar.exe", "winrar.exe", "7z.exe", "7za.exe"])
      expect(toolFamilyOf(n), n).not.toBeNull();
    for (const n of AD_RECON_TOOLS) expect(toolFamilyOf(`${n}.exe`), n).not.toBeNull();
    expect(toolFamilyOf("certutil.exe")).toBeNull(); // a LOLBin is not a tool someone brings
    expect(toolFamilyOf("notepad.exe")).toBeNull();
  });
});

describe("the incremental merge reads every row this pass reads", () => {
  it("loads every tool row on every merge, and the note is inert", () => {
    const noted = linkToolStoreFolders(trio());
    for (const e of noted) expect(mergeTrigger(e)).toBeNull();
    expect(isToolStoreRow(file("x", "AdFind.exe"))).toBe(true);
    expect(mergeLoadAlways(file("x", "AdFind.exe"))).toBe(true);
    expect(mergeLoadAlways(file("x", "7z.exe"))).toBe(true);
    expect(mergeLoadAlways(file("x", "AdFind.exe", 0, { asset: undefined }))).toBe(false);
    expect(mergeLoadAlways(file("x", "PsExec.exe", 0, { path: "C:\\Program Files\\x\\PsExec.exe" }))).toBe(
      false,
    );
  });
});
