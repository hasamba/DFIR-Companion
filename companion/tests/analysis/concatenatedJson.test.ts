import { describe, it, expect } from "vitest";
import { parseConcatenatedJson } from "../../src/analysis/concatenatedJson.js";
import { extractRecords } from "../../src/analysis/siemImport.js";
import { detectImportKind } from "../../src/analysis/importDetect.js";

// A Hayabusa json-timeline record — the shape the concatenated-JSON fallback exists for.
function hayabusaRecord(title: string): object {
  return {
    Timestamp: "2021-12-12 12:00:00.000 +00:00",
    Computer: "FS01.corp.local",
    Channel: "Sysmon",
    EventID: 1,
    Level: "high",
    MitreTactics: ["Execution"],
    MitreTags: ["t1059.001"],
    RuleTitle: title,
    Details: { Proc: "C:\\Windows\\System32\\cmd.exe", CmdLine: "cmd /c whoami" },
  };
}

const pretty = (v: unknown): string => JSON.stringify(v, null, 4);

describe("parseConcatenatedJson — resync after a broken chunk (#2064)", () => {
  it("recovers later records after an unterminated opener (issue repro, compact)", () => {
    expect(parseConcatenatedJson('{"a": {"b": 1}\n{"c":2}\n{"d":3}')).toEqual([{ c: 2 }, { d: 3 }]);
  });

  it("recovers later records when a pretty-printed first record is missing its closing brace", () => {
    const broken = pretty({ a: { b: 1 } }).replace(/\}$/, "");
    const text = `${broken}\n${pretty({ c: 2 })}\n${pretty({ d: 3 })}\n`;
    expect(parseConcatenatedJson(text)).toEqual([{ c: 2 }, { d: 3 }]);
  });

  it("recovers later records after an unterminated string in the first record", () => {
    const text = `{\n    "a": "never closed,\n    "b": 1\n}\n${pretty({ c: 2 })}\n${pretty({ d: 3 })}\n`;
    expect(parseConcatenatedJson(text)).toEqual([{ c: 2 }, { d: 3 }]);
  });

  it("recovers later records after a stray opener line at the top", () => {
    const text = `{\n${pretty({ c: 2 })}\n${pretty({ d: 3 })}\n`;
    expect(parseConcatenatedJson(text)).toEqual([{ c: 2 }, { d: 3 }]);
  });
});

describe("parseConcatenatedJson — valid shapes are unchanged", () => {
  it("parses a valid pretty-printed stream with nested arrays and braces inside strings", () => {
    const a = { x: [1, { y: [2, 3] }], s: '} { [ "quoted" ]' };
    const b = { list: [{ k: 1 }, { k: 2 }], esc: 'back\\slash"quote' };
    expect(parseConcatenatedJson(`${pretty(a)}\n${pretty(b)}\n`)).toEqual([a, b]);
  });

  it("keeps the records before a truncated tail", () => {
    const text = `${pretty({ c: 2 })}\n${pretty({ d: 3 })}\n{\n    "e": `;
    expect(parseConcatenatedJson(text)).toEqual([{ c: 2 }, { d: 3 }]);
  });

  it("skips a balanced-but-invalid chunk mid-file", () => {
    const text = `${pretty({ c: 2 })}\n{ "bad": , }\n${pretty({ d: 3 })}\n`;
    expect(parseConcatenatedJson(text)).toEqual([{ c: 2 }, { d: 3 }]);
  });

  it("skips a balanced-but-invalid chunk mid-line and keeps the value after it", () => {
    expect(parseConcatenatedJson('{"a":1} {bad} {"b":2}')).toEqual([{ a: 1 }, { b: 2 }]);
  });

  it("parses a Python indent=0 stream whose nested values sit at column 0", () => {
    const a = { n: { m: [1, 2] } };
    const b = { o: [{ p: 1 }] };
    const indent0 = (v: unknown): string => JSON.stringify(v, null, 1).replace(/\n +/g, "\n");
    expect(parseConcatenatedJson(`${indent0(a)}\n${indent0(b)}\n`)).toEqual([a, b]);
  });

  it("parses compact values separated by commas, and a top-level array", () => {
    expect(parseConcatenatedJson('{"a":1},{"b":2} [3,4]')).toEqual([{ a: 1 }, { b: 2 }, [3, 4]]);
  });

  it("returns an empty array for empty or non-JSON input without throwing", () => {
    expect(parseConcatenatedJson("")).toEqual([]);
    expect(parseConcatenatedJson("not json at all")).toEqual([]);
    expect(parseConcatenatedJson("{{{{")).toEqual([]);
  });
});

describe("import path — pretty-printed Hayabusa json-timeline with a broken first record", () => {
  const broken = pretty(hayabusaRecord("Broken")).replace(/\}$/, "");
  const text = `${broken}\n${pretty(hayabusaRecord("Second"))}\n${pretty(hayabusaRecord("Third"))}\n`;

  it("extractRecords recovers the remaining records via the concatenated-JSON fallback", () => {
    const r = extractRecords(text);
    expect(r.format).toBe("concatenated-json");
    expect(r.records.map((x) => x.RuleTitle)).toEqual(["Second", "Third"]);
  });

  it("format detection still recognises the file as Hayabusa", () => {
    expect(detectImportKind("hayabusa-timeline.json", text)).toBe("hayabusa");
  });
});
