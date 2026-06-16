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
