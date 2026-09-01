import { describe, it, expect } from "vitest";
import { ransomwareSignal, isRansomExtension } from "../../src/analysis/ransomwareDetect.js";
import { parseVelociraptorJson } from "../../src/analysis/velociraptorImport.js";

describe("ransomwareSignal — T1486 from a file name", () => {
  it("flags a file encrypted to a known family extension", () => {
    const s = ransomwareSignal("C:\\Users\\v\\Documents\\budget.xlsx.akira");
    expect(s?.severity).toBe("High");
    expect(s?.mitre).toContain("T1486");
  });

  it("flags a family ransom note (akira_readme.txt)", () => {
    const s = ransomwareSignal("C:\\Users\\v\\Desktop\\akira_readme.txt");
    expect(s?.severity).toBe("High");
    expect(s?.mitre).toContain("T1486");
  });

  it("flags a generic ransom note by its vocabulary", () => {
    expect(ransomwareSignal("how_to_decrypt_files.hta")?.mitre).toContain("T1486");
    expect(ransomwareSignal("RESTORE-MY-FILES.txt")?.mitre).toContain("T1486");
  });

  it("does NOT flag an ordinary project README or document", () => {
    expect(ransomwareSignal("C:\\src\\project\\README.md")).toBeNull();
    expect(ransomwareSignal("C:\\Users\\v\\notes.txt")).toBeNull();
    expect(ransomwareSignal("C:\\Windows\\System32\\kernel32.dll")).toBeNull();
  });

  // Lynx (the INC Ransom successor, The DFIR Report 2025-12-17) renames victim files to `.LYNX`.
  // `lynx` is an ordinary word, so it is carried in the word-collision set rather than the shared
  // family set: it must show the rename shape, it is refused under a protected OS directory, and it
  // never reaches the unscoped `<family>_readme` note matcher. All four halves are pinned here.
  it("flags a file encrypted to the .LYNX extension, in any case", () => {
    const s = ransomwareSignal(
      "C:\\Users\\Public\\LynxSim\\E-drive-canary\\FileServer\\Operations\\QuarterlyPlan_CANARY.docx.LYNX",
    );
    expect(s?.severity).toBe("High");
    expect(s?.mitre).toContain("T1486");
    expect(ransomwareSignal("C:\\Users\\v\\Documents\\ledger.csv.lynx")?.mitre).toContain("T1486");
  });

  it("flags a rename whose original extension is short or digit-led", () => {
    // `7z` is digit-led and `c` is a single character; both are ordinary victim files, and a 7-Zip
    // archive is a staple of the collection step that precedes encryption.
    for (const p of [
      "C:\\Users\\v\\Documents\\collected.7z.LYNX",
      "C:\\src\\app\\main.c.lynx",
      "C:\\Users\\v\\db.accdb.lynx",
      "C:\\Users\\v\\store.sqlite3.lynx",
      "C:\\Users\\v\\app.properties.lynx",
      "C:\\Users\\v\\archive.tar.gz.lynx",
    ]) {
      expect(ransomwareSignal(p)?.mitre, p).toContain("T1486");
    }
  });

  it("does NOT flag a .lynx name that is not a rename of an existing file", () => {
    // No original extension underneath — an ordinary file that happens to end in the word.
    expect(ransomwareSignal("C:\\Users\\v\\Documents\\notes.lynx")).toBeNull();
    // A version fragment is not an original extension — numeric or alphanumeric. A shape-based rule
    // cannot tell `x64` from `7z`, which is why the inner token is matched against real data types.
    for (const p of [
      "C:\\Program Files\\vendor\\lib-1.0.1.lynx",
      "C:\\Program Files\\vendor\\lib.v1.lynx",
      "C:\\Program Files\\vendor\\pkg.rc1.lynx",
      "C:\\Program Files\\vendor\\bin.x64.lynx",
      "C:\\Program Files\\vendor\\driver.amd64.lynx",
      "C:\\Program Files\\vendor\\build.beta2.lynx",
      "C:\\Program Files\\vendor\\core.win32.lynx",
    ]) {
      expect(ransomwareSignal(p), p).toBeNull();
    }
  });

  it("does NOT flag a .lynx component name under a protected OS directory", () => {
    expect(
      ransomwareSignal("C:\\Windows\\WinSxS\\amd64_microsoft-windows-mdac_31bf3856ad364e35_10.0.1.lynx"),
    ).toBeNull();
    expect(ransomwareSignal("C:\\Windows\\System32\\config\\component.lynx")).toBeNull();
  });

  it("does NOT give a word-collision tag the unscoped family-note match", () => {
    // `<family>_readme` fires anywhere for a distinctive tag; a word tag must not get that reach.
    expect(ransomwareSignal("C:\\Program Files\\browser\\lynx_readme.txt")).toBeNull();
    expect(ransomwareSignal("C:\\Program Files\\browser\\lynx_locker.dll")).toBeNull();
    expect(ransomwareSignal("C:\\Users\\v\\akira_readme.txt")?.mitre).toContain("T1486");
  });

  it("knows the simulated families", () => {
    for (const f of ["akira", "trigona", "gentlemen", "lockbit", "blacksuit", "lynx"]) {
      expect(isRansomExtension(f)).toBe(true);
    }
    expect(isRansomExtension("docx")).toBe(false);
  });
});

describe("MFT/USN ransomware grading survives the Info floor", () => {
  it("grades a USN rename-to-.akira row High + T1486 (not Info)", () => {
    const row = {
      _Source: "Windows.Forensics.Usn",
      OSPath: "C:\\Users\\v\\Documents\\q3.docx.akira",
      Reason: "RENAME_NEW_NAME|CLOSE",
      Usn: 12345,
    };
    const r = parseVelociraptorJson(JSON.stringify([row]));
    expect(r.events[0].severity).toBe("High");
    expect(r.events[0].mitreTechniques).toContain("T1486");
  });

  it("keeps an ordinary USN change at Info", () => {
    const row = {
      _Source: "Windows.Forensics.Usn",
      OSPath: "C:\\Windows\\Temp\\log.txt",
      Reason: "DATA_EXTEND|CLOSE",
      Usn: 12346,
    };
    const r = parseVelociraptorJson(JSON.stringify([row]));
    expect(r.events[0].severity).toBe("Info");
  });

  it("lifts one ransom-note MFT row above a flood of Info rows so the cap keeps it", () => {
    const rows: unknown[] = [];
    for (let i = 0; i < 50; i++) {
      rows.push({
        _Source: "Windows.NTFS.MFT",
        OSPath: `C:\\Windows\\Temp\\f${i}.tmp`,
        Created0x10: "2026-08-26T03:00:00Z",
      });
    }
    rows.push({
      _Source: "Windows.NTFS.MFT",
      OSPath: "C:\\Users\\v\\Desktop\\akira_readme.txt",
      Created0x10: "2026-08-26T03:05:00Z",
    });
    const r = parseVelociraptorJson(JSON.stringify(rows), { maxEvents: 5 });
    // Only 5 kept, sorted most-severe first — the High ransom note must be one of them.
    expect(r.events.some((e) => e.severity === "High" && e.mitreTechniques.includes("T1486"))).toBe(true);
  });
});
