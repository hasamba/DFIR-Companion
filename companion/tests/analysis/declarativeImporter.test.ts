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

  it("reports dropped=0 when all rows are represented via aggregation", () => {
    const imp = buildImporter(spec());
    const r = imp.parse(MDE_CSV); // 2 identical rows aggregate into 1 event with count 2
    expect(r.kept).toBe(1);
    expect(r.dropped).toBe(0);
  });
});

// A user regex reaches this code straight off POST /importers, so a ReDoS pattern is remotely
// triggerable: it would be persisted and then re-run on every detect() call for every upload.
describe("declarativeImporter — user regex is ReDoS-vetted (#249)", () => {
  const withMatch = (match: Record<string, unknown>) => ({
    ...EXAMPLE_IMPORTER_SPEC,
    id: "redos-probe",
    match: { format: "csv", priority: 50, ...match },
  });

  it("rejects a catastrophic filenamePattern at validation time, naming the field", () => {
    const r = parseImporterSpec(withMatch({ filenamePattern: "((a+))+$" }));
    expect(r.ok).toBe(false);
    if (r.ok) return;
    expect(r.errors).toContainEqual(expect.objectContaining({ path: "match.filenamePattern" }));
    expect(r.errors[0].message).toMatch(/ReDoS/);
  });

  it("rejects a catastrophic keyEquals pattern, naming the key", () => {
    const r = parseImporterSpec(withMatch({ requireHeaders: ["Timestamp"], keyEquals: { ActionType: "(a|a)+$" } }));
    expect(r.ok).toBe(false);
    if (r.ok) return;
    expect(r.errors).toContainEqual(expect.objectContaining({ path: "match.keyEquals.ActionType" }));
  });

  it("still accepts an ordinary filenamePattern", () => {
    expect(parseImporterSpec(withMatch({ filenamePattern: "^mde-.*\\.csv$" })).ok).toBe(true);
  });

  it("fails CLOSED when a filenamePattern could not be compiled", () => {
    // Skipping an uncompilable filename test would widen the importer instead of narrowing it:
    // filenamePattern is the only discriminator here, so every other check passes and the importer
    // would claim every upload.
    const imp = buildImporter({ ...spec(), match: { format: "auto", priority: 50, filenamePattern: "((a+))+$" } } as never);
    expect(imp.detect(csvCtx(["Timestamp", "DeviceName"], "anything.csv"))).toBe(false);
    expect(imp.detect({ filename: "a".repeat(64) + ".csv", text: "", root: {}, sample: { x: 1 }, csvHeaders: null })).toBe(false);
  });
});
