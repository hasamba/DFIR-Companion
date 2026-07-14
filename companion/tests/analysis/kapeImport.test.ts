import { describe, it, expect } from "vitest";
import { parseKapeCsv } from "../../src/analysis/kapeImport.js";

// Build CSV text from a header + rows (quoting cells that need it).
function csv(header: string[], rows: string[][]): string {
  const esc = (v: string): string => (/[",\n\r]/.test(v) ? `"${v.replace(/"/g, '""')}"` : v);
  return [header, ...rows].map((r) => r.map(esc).join(",")).join("\n");
}

describe("parseKapeCsv — artifact detection & mapping", () => {
  it("Prefetch (PECmd): execution event + process IOC, uses LastRun", () => {
    const text = csv(
      ["SourceFilename", "ExecutableName", "Hash", "Size", "RunCount", "LastRun", "PreviousRun0"],
      [["C:\\Windows\\Prefetch\\EVIL.EXE-1234.pf", "EVIL.EXE", "ABCD", "10000", "3", "2023-04-01 10:00:00", "2023-03-31 09:00:00"]],
    );
    const r = parseKapeCsv(text);
    expect(r.artifact).toBe("Prefetch");
    expect(r.events).toHaveLength(1);
    const e = r.events[0];
    expect(e.description).toContain("Prefetch: EVIL.EXE executed (run 3×)");
    expect(e.severity).toBe("Info");
    expect(e.timestamp).toBe("2023-04-01T10:00:00Z");
    expect(e.processName).toBe("EVIL.EXE"); // basename, case preserved
    expect(e.sources).toEqual(["Prefetch"]);
    expect(r.iocs.some((i) => i.type === "process" && i.value === "EVIL.EXE")).toBe(true);
  });

  it("Amcache: file + SHA1 hash IOC, FullPath as path", () => {
    const text = csv(
      ["ApplicationName", "FullPath", "FileKeyLastWriteTimestamp", "SHA1", "Size"],
      [["evil", "C:\\Temp\\evil.exe", "2023-04-01 09:30:00", "0000da39a3ee5e6b4b0d3255bfef95601890afd80709", "2048"]],
    );
    const r = parseKapeCsv(text);
    expect(r.artifact).toBe("Amcache");
    const e = r.events[0];
    expect(e.path).toBe("C:\\Temp\\evil.exe");
    expect(r.iocs.find((i) => i.type === "file")?.value).toBe("C:\\Temp\\evil.exe");
    // The 40-hex SHA1 is extracted even with the Amcache leading-zero prefix.
    expect(r.iocs.some((i) => i.type === "hash" && /^[a-f0-9]{40}$/.test(i.value))).toBe(true);
  });

  it("ShimCache (AppCompatCache): path + Executed flag", () => {
    const text = csv(
      ["ControlSet", "CacheEntryPosition", "Path", "LastModifiedTimeUTC", "Executed"],
      [["1", "0", "C:\\Windows\\Temp\\a.exe", "2023-04-01 08:00:00", "Yes"]],
    );
    const r = parseKapeCsv(text);
    expect(r.artifact).toBe("ShimCache");
    expect(r.events[0].description).toContain("ShimCache: C:\\Windows\\Temp\\a.exe (Executed)");
    expect(r.iocs.find((i) => i.type === "file")?.value).toBe("C:\\Windows\\Temp\\a.exe");
  });

  it("UsnJrnl ($J): aggregates same name+reason into a counted row", () => {
    const text = csv(
      ["Name", "Extension", "EntryNumber", "UpdateReasons", "UpdateTimestamp"],
      [
        ["evil.exe", ".exe", "5", "FileCreate", "2023-04-01 10:00:00"],
        ["evil.exe", ".exe", "5", "FileCreate", "2023-04-01 10:00:01"],
      ],
    );
    const r = parseKapeCsv(text);
    expect(r.artifact).toBe("UsnJrnl");
    expect(r.events).toHaveLength(1);
    expect(r.events[0].count).toBe(2);
    expect(r.events[0].description).toContain("UsnJrnl: evil.exe — FileCreate");
  });

  it("MFT: builds ParentPath\\FileName, skips directories", () => {
    const text = csv(
      ["EntryNumber", "InUse", "ParentPath", "FileName", "Extension", "FileSize", "IsDirectory", "Created0x10", "LastModified0x10"],
      [
        ["100", "True", ".\\Users\\bob\\Desktop", "evil.exe", ".exe", "4096", "False", "2023-04-01 07:00:00", "2023-04-01 07:00:00"],
        ["101", "True", ".\\Users\\bob", "Desktop", "", "0", "True", "2023-04-01 06:00:00", "2023-04-01 06:00:00"],
      ],
    );
    const r = parseKapeCsv(text);
    expect(r.artifact).toBe("MFT");
    expect(r.events).toHaveLength(1); // the directory row is skipped
    expect(r.events[0].path).toBe(".\\Users\\bob\\Desktop\\evil.exe");
  });

  it("MFT: flags timestomping when $SI (Created0x10) is backdated before $FN (Created0x30)", () => {
    const text = csv(
      ["EntryNumber", "InUse", "ParentPath", "FileName", "Extension", "FileSize", "IsDirectory", "Created0x10", "Created0x30", "LastModified0x10"],
      [
        // Backdated + zeroed-sub-second $SI vs full-precision recent $FN → timestomp.
        ["100", "True", ".\\Windows\\System32", "evil.exe", ".exe", "4096", "False", "2009-07-14 01:14:24.0000000", "2026-06-02 09:15:23.4821330", "2026-06-02 09:15:23.4821330"],
        // Normal file: $SI ≈ $FN → not flagged.
        ["101", "True", ".\\Users\\bob", "report.docx", ".docx", "8192", "False", "2026-06-02 09:15:20.1112223", "2026-06-02 09:15:20.1112223", "2026-06-02 09:20:00.0000000"],
      ],
    );
    const r = parseKapeCsv(text);
    expect(r.artifact).toBe("MFT");
    const stomped = r.events.find((e) => e.path?.toLowerCase().endsWith("evil.exe"));
    expect(stomped?.mitreTechniques).toContain("T1070.006");
    expect(stomped?.severity).toBe("Medium");
    expect(stomped?.description).toMatch(/timestomping/i);
    const clean = r.events.find((e) => e.path?.toLowerCase().endsWith("report.docx"));
    expect(clean?.mitreTechniques ?? []).not.toContain("T1070.006");
    expect(clean?.severity).toBe("Info");
  });

  it("RecycleBin (RBCmd): deletion event", () => {
    const text = csv(
      ["SourceName", "FileType", "FileName", "FileSize", "DeletedOn"],
      [["$IABC.exe", "$I", "C:\\Users\\bob\\secret.docx", "5120", "2023-04-02 12:00:00"]],
    );
    const r = parseKapeCsv(text);
    expect(r.artifact).toBe("RecycleBin");
    expect(r.events[0].description).toContain("RecycleBin: deleted C:\\Users\\bob\\secret.docx");
    expect(r.events[0].timestamp).toBe("2023-04-02T12:00:00Z");
  });
});

describe("parseKapeCsv — edges", () => {
  it("returns 'unknown' for a CSV that matches no EZ profile", () => {
    const text = csv(["colA", "colB"], [["1", "2"]]);
    const r = parseKapeCsv(text);
    expect(r.artifact).toBe("unknown");
    expect(r.events).toHaveLength(0);
  });

  it("drops the .NET min-date sentinel timestamps", () => {
    const text = csv(
      ["SourceFilename", "ExecutableName", "RunCount", "LastRun"],
      [["x.pf", "X.EXE", "1", "0001-01-01 00:00:00"]],
    );
    const r = parseKapeCsv(text);
    expect(r.events[0].timestamp).toBe(""); // sentinel dropped, not emitted as a real time
  });
});
