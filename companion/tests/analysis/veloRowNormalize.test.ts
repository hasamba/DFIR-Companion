import { describe, it, expect } from "vitest";
import { normalizeRow } from "../../src/analysis/veloRowNormalize.js";

// The `Line` un-wrap. A Velociraptor source that streams a text file back emits one row per line as
// an opaque string — `Generic.Scanner.ThorZIP/ThorResultsJson` is exactly that — so a THOR finding
// arrives with no timestamp, host or severity of its own until the payload is opened.
describe("normalizeRow — Line payload", () => {
  const thor = {
    time: "2025-12-05T03:26:42Z",
    hostname: "WIN-UK1GV882OK6",
    level: "Alert",
    module: "Filescan",
    message: "Malware file found",
  };

  it("replaces a Line-wrapped JSON document with its own fields", () => {
    expect(normalizeRow({ Line: JSON.stringify(thor) })).toEqual(thor);
  });

  it("keeps the collection metadata a source-qualified read adds alongside the payload", () => {
    const out = normalizeRow({ Line: JSON.stringify(thor), _Source: "Generic.Scanner.ThorZIP", _ts: 1 });
    expect(out._Source).toBe("Generic.Scanner.ThorZIP"); // what names the artifact for classification
    expect(out.level).toBe("Alert");
  });

  it("lets the payload win over the collection metadata on a key clash", () => {
    const out = normalizeRow({ Line: JSON.stringify({ ...thor, _Source: "from-payload" }) });
    expect(out._Source).toBe("from-payload");
  });

  it("leaves a plain-text Line alone", () => {
    const row = { Line: "2025-12-05 scan started, 0 findings" };
    expect(normalizeRow(row)).toEqual(row);
  });

  it("leaves a Line that only looks like JSON alone", () => {
    const row = { Line: "{not really json}" };
    expect(normalizeRow(row)).toEqual(row);
  });

  it("leaves a JSON array or scalar in Line alone — only an object is a record", () => {
    expect(normalizeRow({ Line: "[1,2,3]" })).toEqual({ Line: "[1,2,3]" });
    expect(normalizeRow({ Line: "42" })).toEqual({ Line: "42" });
  });

  it("leaves a row that already has real columns of its own alone", () => {
    const row = { Line: JSON.stringify(thor), OSPath: "C:\\x.exe" };
    expect(normalizeRow(row)).toEqual(row); // structured already — reshaping would be guesswork
  });

  it("does not pollute Object.prototype through a payload key", () => {
    normalizeRow({ Line: '{"__proto__":{"polluted":true}}' });
    expect(({} as Record<string, unknown>).polluted).toBeUndefined();
  });

  it("passes a native Velociraptor row through untouched", () => {
    const row = { OSPath: "C:\\evil.exe", Detection: { Name: "T1055" } };
    expect(normalizeRow(row)).toEqual(row);
  });
});
