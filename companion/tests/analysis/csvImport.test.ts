import { describe, it, expect } from "vitest";
import { parseCsv, chunk, chunkToCsvText } from "../../src/analysis/csvImport.js";

describe("parseCsv", () => {
  it("parses a simple header + rows", () => {
    const { headers, rows } = parseCsv("Time,Process,PID\n09:00,a.exe,12\n09:01,b.exe,34\n");
    expect(headers).toEqual(["Time", "Process", "PID"]);
    expect(rows).toEqual([["09:00", "a.exe", "12"], ["09:01", "b.exe", "34"]]);
  });

  it("handles quoted fields with embedded commas, newlines and escaped quotes", () => {
    const csv = 'Name,Cmd\n"a.exe","powershell -enc ""AAA"", -nop"\n"b,c.exe","line1\nline2"\n';
    const { headers, rows } = parseCsv(csv);
    expect(headers).toEqual(["Name", "Cmd"]);
    expect(rows[0]).toEqual(["a.exe", 'powershell -enc "AAA", -nop']);
    expect(rows[1]).toEqual(["b,c.exe", "line1\nline2"]);
  });

  it("tolerates CRLF line endings and a missing trailing newline", () => {
    const { rows } = parseCsv("a,b\r\n1,2\r\n3,4");
    expect(rows).toEqual([["1", "2"], ["3", "4"]]);
  });

  it("drops blank lines and returns no rows for a header-only file", () => {
    const { headers, rows } = parseCsv("a,b\n\n");
    expect(headers).toEqual(["a", "b"]);
    expect(rows).toEqual([]);
  });
});

describe("chunk", () => {
  it("splits into batches of the given size", () => {
    expect(chunk([1, 2, 3, 4, 5], 2)).toEqual([[1, 2], [3, 4], [5]]);
  });
  it("rejects a non-positive size", () => {
    expect(() => chunk([1], 0)).toThrow();
  });
});

describe("chunkToCsvText", () => {
  it("re-serializes header + rows, quoting fields that need it", () => {
    const text = chunkToCsvText(["Time", "Cmd"], [["09:00", "a,b"], ["09:01", 'say "hi"']]);
    expect(text).toBe('Time,Cmd\n09:00,"a,b"\n09:01,"say ""hi"""');
  });
  it("returns just the header when there are no rows", () => {
    expect(chunkToCsvText(["a", "b"], [])).toBe("a,b");
  });
});
