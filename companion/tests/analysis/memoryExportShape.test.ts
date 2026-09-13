// A memory export says what it holds — zero rows, an unread layout — never that a plugin completed
// (#933 item 12).
import { describe, it, expect } from "vitest";
import { parseMemory } from "../../src/analysis/memoryImport.js";
import { extractTables } from "../../src/analysis/memoryTables.js";
import { diagnosticLines, exportShapeNote } from "../../src/analysis/memoryExportShape.js";

const MALFIND_HEADER =
  "PID\tProcess\tStart VPN\tEnd VPN\tTag\tProtection\tCommitCharge\tPrivateMemory\tFile output\tNotes\tHexdump\tDisasm";

const pslistRows = () => [
  {
    __children: [],
    PID: 4,
    PPID: 0,
    ImageFileName: "System",
    Offset: "0x1",
    Threads: 100,
    Handles: 500,
    SessionId: "N/A",
    Wow64: false,
    CreateTime: "2012-07-22T02:42:31+00:00",
    ExitTime: null,
  },
];

describe("a zero-row export is a fact about the export, not about the host", () => {
  it("a text export with a header and no rows imports one Low row and no 400-shaped result", () => {
    const text = `Volatility 3 Framework 2.7.0\n${MALFIND_HEADER}\n`;
    const r = parseMemory(text, { filename: "windows.malfind.txt" });
    expect(r.format).toBe("volatility-text");
    expect(r.kept).toBe(1);
    const [e] = r.events;
    expect(e.severity).toBe("Low");
    expect(e.description).toContain("Memory export holds zero rows");
    expect(e.description).toContain("[label: windows.malfind (claimed by the export name)]");
    expect(e.description).toContain("completion of the search and the pages it covered are not established");
    expect(e.description).toContain("[undated: the export carries no time]");
    expect(e.timestamp).toBe("");
    expect(e.mitreTechniques ?? []).toEqual([]);
    expect(r.iocs).toEqual([]);
  });
  it("never says completed, clean, or no injection", () => {
    const r = parseMemory(`${MALFIND_HEADER}\n`, { filename: "windows.malfind.txt" });
    expect(r.events[0].description).not.toMatch(/completed|clean|no injection|nothing found/i);
  });
  it("a JSON [] export is the same row; without a name the label is none", () => {
    const named = parseMemory("[]", { filename: "windows.pslist.json" });
    expect(named.kept).toBe(1);
    expect(named.events[0].description).toContain("[label: windows.pslist (claimed by the export name)]");
    const anon = parseMemory("[]", { filename: "out.json" });
    expect(anon.events[0].description).toContain("[label: none]");
  });
  it("an empty array under a plugin-map key is one zero-row row beside the rows; a non-plugin key is ignored", () => {
    const r = parseMemory(
      JSON.stringify({ "windows.malfind.Malfind": [], "windows.pslist.PsList": pslistRows(), notes: [] }),
    );
    const zero = r.events.filter((e) => e.description.includes("Memory export holds zero rows"));
    expect(zero).toHaveLength(1);
    expect(zero[0].description).toContain("[label: windows.malfind.Malfind (claimed by the export key)]");
    expect(r.events.some((e) => /System/.test(e.description))).toBe(true);
  });
  it("an export nothing recognises stays empty (the route's 400)", () => {
    const r = parseMemory("just some prose\nwith no table", {});
    expect(r.format).toBe("empty");
    expect(r.kept).toBe(0);
  });
  it("extractTables reports zero-row labels without claiming a plugin", () => {
    const t = extractTables(`${MALFIND_HEADER}\n`, "windows.malfind.txt");
    expect(t.tables).toEqual([]);
    expect(t.empty).toEqual(["windows.malfind"]);
    expect(t.format).toBe("volatility-text");
  });
});

describe("a Volatility 2 export is not read, and says so", () => {
  it("imports one Low row that is about this importer, not the host", () => {
    const text = [
      "Volatility Foundation Volatility Framework 2.6.1",
      "Offset(V)          Name                    PID   PPID   Thds     Hnds   Sess  Wow64 Start",
      "0xfffffa8000ca0040 System                    4      0     80      570 ------      0 2012-07-22 02:42:31 UTC+0000",
    ].join("\n");
    const r = parseMemory(text, { filename: "pslist.txt" });
    expect(r.format).toBe("volatility2-text");
    expect(r.kept).toBe(1);
    expect(r.events[0].severity).toBe("Low");
    expect(r.events[0].description).toContain("Memory export not read [Volatility 2 text layout]");
    expect(r.events[0].description).toContain("re-run under Volatility 3");
    expect(r.events[0].description).not.toContain("System");
  });
});

describe("diagnostic-looking text is shown as unverified text, never as grounds", () => {
  it("lines outside the table reach the note, neutralised; a row VALUE does not", () => {
    const text = [
      "Volatility 3 Framework 2.7.0",
      "Unsatisfied requirement plugins.Malfind.kernel.symbol_table_name: ] [x d41d8cd98f00b204e9800998ecf8427e",
      "Traceback (most recent call last):",
      "  File x",
      "SomeError: boom",
    ].join("\n");
    const lines = diagnosticLines(text);
    expect(lines).toHaveLength(3);
    const note = exportShapeNote(text, "volatility-text", []);
    expect(note).toContain("3 diagnostic-looking line(s) outside the table (unverified text)");
    expect(note).not.toContain("] [x");
    expect(note).not.toMatch(/[0-9a-f]{32}/);
    // the same string inside a table row is a value, not a diagnostic
    const rowText = `${MALFIND_HEADER}\n4\tUnsatisfied requirement plugins.X\t0x1\t0x2\tVadS\tPAGE_EXECUTE_READWRITE\t1\t1\tDisabled\t\t\t\n`;
    expect(diagnosticLines(rowText)).toEqual([]);
  });
  it("a zero-row export's note says zero rows and completion not established; a Vol2 export's says not read", () => {
    expect(exportShapeNote("", "volatility-text", ["windows.malfind"])).toContain(
      "zero rows under label windows.malfind — completion not established",
    );
    expect(exportShapeNote("", "volatility2-text", [])).toContain("Volatility 2 layout not read");
  });
  it("a banner with no table after it is not 'zero rows': no row, and the note says nothing was read", () => {
    const text = [
      "Volatility 3 Framework 2.7.0",
      "Unsatisfied requirement plugins.Malfind.kernel.symbol_table_name: ",
      "A symbol table requirement was not fulfilled.",
    ].join("\n");
    const r = parseMemory(text, { filename: "windows.malfind.txt" });
    expect(r.format).toBe("volatility-text"); // recognised, so the route does not answer 400
    expect(r.kept).toBe(0);
    expect(r.note).toContain(
      "a Volatility banner with no table after it — nothing was read; completion not established",
    );
    expect(r.note).toContain("2 diagnostic-looking line(s)");
    expect(r.note).not.toContain("zero rows");
  });
});

describe("placeholders never become names or IOCs", () => {
  it("a '-' or 'N/A' process name is absent, not a process IOC", () => {
    const rows = [
      { ...pslistRows()[0], PID: 900, ImageFileName: "-" },
      { ...pslistRows()[0], PID: 901, ImageFileName: "N/A" },
    ];
    const r = parseMemory(JSON.stringify({ "windows.pslist.PsList": rows }));
    expect(r.iocs.filter((i) => i.type === "process").map((i) => i.value)).not.toContain("-");
    expect(r.iocs.filter((i) => i.type === "process").map((i) => i.value)).not.toContain("N/A");
  });
});
