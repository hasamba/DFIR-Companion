import { describe, it, expect } from "vitest";
import { parseCsv, parseCsvRecords, parseCsvRecordsFromLines, chunk, chunkToCsvText } from "../../src/analysis/csvImport.js";

async function* asLines(arr: string[]): AsyncGenerator<string> { for (const l of arr) yield l; }
async function collect<T>(it: AsyncIterable<T>): Promise<T[]> { const out: T[] = []; for await (const x of it) out.push(x); return out; }

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

describe("parseCsvRecords (streaming)", () => {
  it("yields the same records parseCsv produces, header first", () => {
    const csv = 'Name,Cmd\n"a.exe","powershell -enc ""AAA"", -nop"\n"b,c.exe","line1\nline2"\n';
    const streamed = [...parseCsvRecords(csv)];
    const { headers, rows } = parseCsv(csv);
    expect(streamed[0]).toEqual(headers);
    expect(streamed.slice(1)).toEqual(rows);
  });

  it("skips fully-empty records so the first yield is the header", () => {
    const recs = [...parseCsvRecords("a,b\n\n1,2\n")];
    expect(recs).toEqual([["a", "b"], ["1", "2"]]);
  });

  it("is lazy — does not parse the whole file to read the first record", () => {
    // A header followed by a huge body; pulling only the first record must not touch the body.
    const big = "h1,h2\n" + "x,y\n".repeat(500_000);
    const it = parseCsvRecords(big);
    expect(it.next().value).toEqual(["h1", "h2"]);
    // If this were eager it would have already built a 500k-row array; here we just stop.
  });
});

describe("parseCsvRecordsFromLines (streaming from a line source)", () => {
  it("yields the same records as parseCsv for simple input", async () => {
    const recs = await collect(parseCsvRecordsFromLines(asLines(["Time,Process,PID", "09:00,a.exe,12", "09:01,b.exe,34"])));
    expect(recs).toEqual([["Time", "Process", "PID"], ["09:00", "a.exe", "12"], ["09:01", "b.exe", "34"]]);
  });

  it("joins a quoted field with an embedded newline that spans physical lines", async () => {
    // The "Cmd" field on the second record contains a literal newline → it arrives as two lines
    // with an unbalanced quote count; the joiner must stitch them back into one record.
    const lines = ['Name,Cmd', '"a.exe","line1', 'line2"', '"b.exe","ok"'];
    const recs = await collect(parseCsvRecordsFromLines(asLines(lines)));
    expect(recs).toEqual([["Name", "Cmd"], ["a.exe", "line1\nline2"], ["b.exe", "ok"]]);
  });

  it("force-flushes when a record exceeds the byte cap (runaway unbalanced quote can't OOM)", async () => {
    // A stray opening quote that never closes would otherwise swallow every following line; the cap
    // bounds the buffer instead. We just assert it terminates and produces bounded records.
    const lines = ['h1,h2', '"oops, never closed', 'aaaa', 'bbbb', 'cccc'];
    const recs = await collect(parseCsvRecordsFromLines(asLines(lines), { maxRecordChars: 12 }));
    expect(recs[0]).toEqual(["h1", "h2"]);
    expect(recs.length).toBeGreaterThan(1); // did not hang collecting one giant record
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
