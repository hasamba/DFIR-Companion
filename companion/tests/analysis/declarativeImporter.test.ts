import { describe, it, expect } from "vitest";
import { buildImporter, type EngineDetectContext } from "../../src/analysis/declarativeImporter.js";
import { EXAMPLE_IMPORTER_SPEC, parseImporterSpec } from "../../src/analysis/importerSpec.js";

function spec() {
  const r = parseImporterSpec(EXAMPLE_IMPORTER_SPEC);
  if (!r.ok) throw new Error("example invalid");
  return r.spec;
}
const csvCtx = (headers: string[], filename = "x.csv"): EngineDetectContext => ({
  filename, text: "", root: undefined, sample: null,
  csvHeaders: new Set(headers.map((h) => h.toLowerCase())),
});

describe("declarativeImporter detect", () => {
  it("matches a CSV with the required + any headers", () => {
    const imp = buildImporter(spec());
    expect(imp.detect(csvCtx(["Timestamp", "DeviceName", "ActionType"]))).toBe(true);
  });
  it("rejects when a required header is missing", () => {
    const imp = buildImporter(spec());
    expect(imp.detect(csvCtx(["DeviceName", "ActionType"]))).toBe(false);
  });
  it("rejects a JSON sample when the spec wants CSV", () => {
    const imp = buildImporter(spec());
    expect(imp.detect({ filename: "x.json", text: "", root: {}, sample: { Timestamp: "t", DeviceName: "d" }, csvHeaders: null })).toBe(false);
  });
});

const MDE_CSV = [
  "Timestamp,DeviceName,ActionType,FileName,Severity,SHA256,RemoteIP,AccountDomain,AccountName,AttackTechniques",
  "2026-06-10T12:00:00Z,HOST01,ProcessCreated,evil.exe,High,abc123,9.9.9.9,CORP,jdoe,T1059.001",
  "2026-06-10T12:00:05Z,HOST01,ProcessCreated,evil.exe,High,abc123,9.9.9.9,CORP,jdoe,T1059.001",
].join("\n");

describe("declarativeImporter parse", () => {
  it("maps + aggregates MDE rows into events and IOCs", () => {
    const imp = buildImporter(spec());
    const r = imp.parse(MDE_CSV);
    expect(r.total).toBe(2);
    expect(r.events).toHaveLength(1);            // both rows aggregate (same severity|description)
    const e = r.events[0];
    expect(e.count).toBe(2);
    expect(e.severity).toBe("High");
    expect(e.asset).toBe("HOST01");
    expect(e.timestamp).toContain("2026-06-10T12:00:00"); // normalizeTime's exact suffix is not asserted
    expect(e.description).toContain("ProcessCreated on HOST01");
    expect(e.description).toContain("CORP\\jdoe");
    expect(e.mitreTechniques).toContain("T1059.001");
    expect(e.sha256).toBe("abc123");
    expect(r.iocs).toEqual(expect.arrayContaining([
      { type: "hash", value: "abc123" },
      { type: "ip", value: "9.9.9.9" },
    ]));
  });

  it("applies a severity map with default", () => {
    const imp = buildImporter(spec());
    const csv = "Timestamp,DeviceName,ActionType,FileName,Severity\n2026-06-10T12:00:00Z,H,A,f.exe,weird";
    expect(imp.parse(csv).events[0].severity).toBe("Medium"); // unmapped → default
  });
});
