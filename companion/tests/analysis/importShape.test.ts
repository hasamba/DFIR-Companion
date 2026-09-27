import { describe, it, expect } from "vitest";
import {
  countNewlines,
  describeImportShape,
  KNOWN_COLUMN_NAMES,
  type ImportShape,
} from "../../src/analysis/importShape.js";

// Every cell below carries a marker a leak check can find: an opaque token, a person, a bare
// hostname, a project codename, an org. None of them may ever appear in a shape report (#1735).
const MARKERS = [
  "MRK_a1b2",
  "MRK_c3d4",
  "MRK_e5f6",
  "Alice Cohen",
  "Alice",
  "Cohen",
  "WKS-FIN-07",
  "ProjectFalcon",
  "Finance",
  "Bob",
  "EagleCorp",
  "10.1.2.3",
  "0x3e7",
  "2026-01-02",
  "6f9619ff",
  "alice",
];

function lines(text: string): { count: number; exact: boolean } {
  return { count: countNewlines(Buffer.from(text)), exact: true };
}

function shapeOf(text: string): ImportShape {
  const buf = Buffer.from(text, "utf8");
  return describeImportShape(buf, buf.length, lines(text));
}

function expectNoLeak(shape: ImportShape): void {
  const json = JSON.stringify(shape);
  for (const m of MARKERS) expect(json, `leaked ${m}`).not.toContain(m);
}

const GUID = "6f9619ff-8b86-d011-b42d-00c04fc964ff";

describe("describeImportShape — delimited text", () => {
  it("keeps allowlisted header names, hides the rest, and types the columns", () => {
    const text =
      "EventID,TimeCreated,Computer,IpAddress,ActivityID,AliceCohenNotes\n" +
      `4624,2026-01-02T03:04:05Z,WKS-FIN-07,10.1.2.3,${GUID},MRK_a1b2 Alice Cohen\n` +
      `4625,2026-01-02T03:05:05.123Z,WKS-FIN-07,10.1.2.4,{${GUID}},ProjectFalcon\n`;
    const s = shapeOf(text);
    expect(s.format).toBe("csv");
    expect(s.delimiter).toBe(",");
    expect(s.encoding).toBe("utf8");
    expect(s.lineEnding).toBe("lf");
    expect(s.columnCount).toBe(6);
    expect(s.headerRecognized).toBe(true);
    expect(s.columns).toEqual([
      { name: "EventID", type: "integer" },
      { name: "TimeCreated", type: "timestamp" },
      { name: "Computer", type: "text" },
      { name: "IpAddress", type: "ip" },
      { name: "ActivityID", type: "guid" },
      { name: "<unlisted>", type: "text" },
    ]);
    expect(s.rowsCounted).toBe(3);
    expect(s.rowCountExact).toBe(true);
    expect(s.fileBytes).toBe(Buffer.byteLength(text));
    expectNoLeak(s);
  });

  it("never shows a header-less first row, even when it is plausible short words", () => {
    const text = "Alice,Finance,ProjectFalcon\nBob,EagleCorp,MRK_a1b2\n";
    const s = shapeOf(text);
    expect(s.format).toBe("csv");
    expect(s.headerRecognized).toBe(false);
    expect(s.columns?.map((c) => c.name)).toEqual(["<unlisted>", "<unlisted>", "<unlisted>"]);
    expect(s.columns?.every((c) => c.type === "text")).toBe(true);
    expectNoLeak(s);
  });

  it("profiles line 1 as data when no header is recognized", () => {
    const s = shapeOf("12,MRK_a1b2\n13,MRK_c3d4\n");
    expect(s.headerRecognized).toBe(false);
    expect(s.columns?.[0]).toEqual({ name: "<unlisted>", type: "integer" });
    expectNoLeak(s);
  });

  it("detects TSV", () => {
    const text = "Timestamp\tRuleTitle\tLevel\n2026-01-02 03:04:05\tMRK_a1b2\thigh\n";
    const s = shapeOf(text);
    expect(s.format).toBe("tsv");
    expect(s.delimiter).toBe("\t");
    expect(s.columns?.map((c) => c.name)).toEqual(["Timestamp", "RuleTitle", "Level"]);
    expect(s.columns?.[0]?.type).toBe("timestamp");
    expectNoLeak(s);
  });

  it("detects a semicolon CSV", () => {
    const text = "date;user;host\n2026-01-02;Alice Cohen;WKS-FIN-07\n2026-01-03;Bob;WKS-FIN-07\n";
    const s = shapeOf(text);
    expect(s.format).toBe("csv");
    expect(s.delimiter).toBe(";");
    expect(s.columns?.map((c) => c.name)).toEqual(["date", "user", "host"]);
    expectNoLeak(s);
  });

  it("detects a pipe-separated file", () => {
    const s = shapeOf("EventID|Channel\n1|MRK_a1b2\n2|MRK_c3d4\n");
    expect(s.format).toBe("psv");
    expect(s.delimiter).toBe("|");
    expectNoLeak(s);
  });

  it("reports CRLF and mixed line endings", () => {
    const crlf = shapeOf("EventID,Message\r\n1,MRK_a1b2 Alice\r\n2,WKS-FIN-07\r\n");
    expect(crlf.lineEnding).toBe("crlf");
    expect(crlf.columns?.[1]).toEqual({ name: "Message", type: "text" });
    expectNoLeak(crlf);
    expect(shapeOf("EventID,Message\r\n1,a\n").lineEnding).toBe("mixed");
    expect(shapeOf("EventID,Message").lineEnding).toBe("none");
  });

  it("handles a UTF-8 BOM before the header", () => {
    const text = "\uFEFFEventID,Computer\n4624,WKS-FIN-07\n";
    const s = shapeOf(text);
    expect(s.encoding).toBe("utf8-bom");
    expect(s.columns?.[0]).toEqual({ name: "EventID", type: "integer" });
    expectNoLeak(s);
  });

  it("decodes UTF-16LE with a BOM", () => {
    const text = "EventID,Computer,UserName\r\n4624,WKS-FIN-07,Alice Cohen\r\n";
    const buf = Buffer.concat([Buffer.from([0xff, 0xfe]), Buffer.from(text, "utf16le")]);
    const s = describeImportShape(buf, buf.length, { count: 2, exact: true });
    expect(s.encoding).toBe("utf16le");
    expect(s.format).toBe("csv");
    expect(s.columns?.map((c) => c.name)).toEqual(["EventID", "Computer", "UserName"]);
    expect(s.columns?.[0]?.type).toBe("integer");
    expectNoLeak(s);
  });

  it("decodes UTF-16LE without a BOM", () => {
    const buf = Buffer.from("EventID,Channel\n1,MRK_a1b2\n", "utf16le");
    const s = describeImportShape(buf, buf.length, { count: 2, exact: true });
    expect(s.encoding).toBe("utf16le");
    expect(s.format).toBe("csv");
    expectNoLeak(s);
  });

  it("types quoted cells, hex, bool, number, empty and mixed", () => {
    const text =
      'Size,Mode,IsDirectory,Mtime,Notes,Extra\n"12.5",0x3e7,true,,MRK_a1b2,1\n' +
      '"7.25",0xff,false,,"MRK_c3d4, Alice",abc\n';
    const s = shapeOf(text);
    expect(s.columns?.map((c) => c.type)).toEqual(["number", "hex", "bool", "empty", "text", "mixed"]);
    expectNoLeak(s);
  });
});

describe("describeImportShape — JSON", () => {
  it("detects JSONL and types the first object's keys", () => {
    const text =
      `{"EventID":4624,"TimeCreated":"2026-01-02T03:04:05Z","SubjectUserName":"Alice Cohen","MRK_e5f6":1}\n` +
      `{"EventID":4625,"TimeCreated":"2026-01-02T03:04:06Z","SubjectUserName":"Bob"}\n`;
    const s = shapeOf(text);
    expect(s.format).toBe("jsonl");
    expect(s.jsonTopLevel).toBe("jsonl");
    expect(s.jsonKeys).toEqual([
      { name: "EventID", type: "integer" },
      { name: "TimeCreated", type: "timestamp" },
      { name: "SubjectUserName", type: "text" },
      { name: "<unlisted>", type: "integer" },
    ]);
    expectNoLeak(s);
  });

  it("detects a JSON array of objects", () => {
    const text = JSON.stringify([
      { src_ip: "10.1.2.3", Computer: "WKS-FIN-07", Enabled: true, Nested: { a: "MRK_a1b2" } },
      { src_ip: "10.1.2.4", Computer: "Alice" },
    ]);
    const s = shapeOf(text);
    expect(s.format).toBe("json");
    expect(s.jsonTopLevel).toBe("array");
    expect(s.jsonKeys?.[0]).toEqual({ name: "src_ip", type: "ip" });
    expect(s.jsonKeys?.[2]).toEqual({ name: "Enabled", type: "bool" });
    expectNoLeak(s);
  });

  it("reads the first object of a JSON array cut off by the head limit", () => {
    const full = JSON.stringify([
      { EventID: 1, Computer: "WKS-FIN-07" },
      { EventID: 2, Computer: "MRK_a1b2" },
    ]);
    const head = Buffer.from(full.slice(0, full.length - 10));
    const s = describeImportShape(head, full.length, { count: 0, exact: false });
    expect(s.jsonTopLevel).toBe("array");
    expect(s.jsonKeys?.map((k) => k.name)).toEqual(["EventID", "Computer"]);
    expect(s.rowCountExact).toBe(false);
    expectNoLeak(s);
  });

  it("hides JSON object keys that are data", () => {
    const s = shapeOf(JSON.stringify({ alice: 1, "WKS-FIN-07": "MRK_a1b2", ProjectFalcon: [1] }));
    expect(s.format).toBe("json");
    expect(s.jsonTopLevel).toBe("object");
    expect(s.jsonKeys?.map((k) => k.name)).toEqual(["<unlisted>", "<unlisted>", "<unlisted>"]);
    expectNoLeak(s);
  });
});

describe("describeImportShape — magic and odd input", () => {
  function magic(prefix: Buffer): ImportShape {
    const buf = Buffer.concat([prefix, Buffer.from("MRK_a1b2 Alice Cohen WKS-FIN-07")]);
    const s = describeImportShape(buf, buf.length, { count: 0, exact: true });
    expectNoLeak(s);
    return s;
  }

  it("recognises evtx, sqlite, zip, gzip and xml by their first bytes", () => {
    expect(magic(Buffer.from("ElfFile\0")).format).toBe("evtx");
    expect(magic(Buffer.from("SQLite format 3\0")).format).toBe("sqlite");
    expect(magic(Buffer.from([0x50, 0x4b, 0x03, 0x04])).format).toBe("zip");
    expect(magic(Buffer.from([0x1f, 0x8b, 0x08])).format).toBe("gzip");
    expect(magic(Buffer.from('<?xml version="1.0"?><Events>')).format).toBe("xml");
    expect(magic(Buffer.from("<Events>")).format).toBe("xml");
  });

  it("calls random bytes with NULs binary", () => {
    const bytes = Buffer.alloc(4096);
    let x = 12345;
    for (let i = 0; i < bytes.length; i++) {
      x = (x * 1103515245 + 12345) & 0x7fffffff;
      bytes[i] = x & 0xff;
    }
    const buf = Buffer.concat([bytes, Buffer.from("\0MRK_a1b2\0Alice Cohen")]);
    const s = describeImportShape(buf, buf.length, { count: 3, exact: true });
    expect(s.format).toBe("binary");
    expect(s.encoding).toBe("binary");
    expectNoLeak(s);
  });

  it("reports invalid UTF-8 as unknown encoding", () => {
    const buf = Buffer.concat([
      Buffer.from("EventID,Channel\n1,"),
      Buffer.from([0xc3, 0x28]),
      Buffer.from("x\n"),
    ]);
    const s = describeImportShape(buf, buf.length, { count: 2, exact: true });
    expect(s.encoding).toBe("unknown");
  });

  it("describes an empty file", () => {
    const s = describeImportShape(Buffer.alloc(0), 0, { count: 0, exact: true });
    expect(s).toEqual({
      fileBytes: 0,
      format: "empty",
      encoding: "unknown",
      lineEnding: "none",
      rowsCounted: 0,
      rowCountExact: true,
    });
  });

  it("stays fast and silent on a 5 MB single line", () => {
    const text = "MRK_a1b2 Alice Cohen, WKS-FIN-07;".repeat(160_000);
    const buf = Buffer.from(text);
    const t0 = Date.now();
    const s = describeImportShape(buf, buf.length, { count: 0, exact: true });
    expect(Date.now() - t0).toBeLessThan(2000);
    expect(["csv", "text"]).toContain(s.format);
    expectNoLeak(s);
  });

  it("describes free text with no delimiter as text", () => {
    const s = shapeOf("MRK_a1b2 Alice Cohen logged on\nWKS-FIN-07 rebooted today\n");
    expect(s.format).toBe("text");
    expect(s.columns).toBeUndefined();
    expectNoLeak(s);
  });

  it("never throws on truncated or malformed JSON", () => {
    for (const t of ["{", "[", '{"a":', "[{]", "{{{{", '["MRK_a1b2"]']) {
      const s = shapeOf(t);
      expectNoLeak(s);
    }
  });
});

describe("KNOWN_COLUMN_NAMES and countNewlines", () => {
  it("stores normalized names", () => {
    expect(KNOWN_COLUMN_NAMES.has("eventid")).toBe(true);
    expect(KNOWN_COLUMN_NAMES.has("timecreated")).toBe(true);
    expect(KNOWN_COLUMN_NAMES.has("srcip")).toBe(true);
    expect(KNOWN_COLUMN_NAMES.has("alice")).toBe(false);
    expect(KNOWN_COLUMN_NAMES.size).toBeGreaterThan(140);
  });

  it("counts LF bytes", () => {
    expect(countNewlines(Buffer.from("a\nb\r\nc"))).toBe(2);
    expect(countNewlines(Buffer.alloc(0))).toBe(0);
  });
});
