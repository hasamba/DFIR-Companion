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

  it("knows the simulated families", () => {
    for (const f of ["akira", "trigona", "gentlemen", "lockbit", "blacksuit"]) {
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
