import { describe, it, expect } from "vitest";
import { parseImporterSpec, EXAMPLE_IMPORTER_SPEC } from "../../src/analysis/importerSpec.js";

describe("parseImporterSpec", () => {
  it("accepts the bundled worked example", () => {
    const r = parseImporterSpec(EXAMPLE_IMPORTER_SPEC);
    expect(r.ok).toBe(true);
  });

  it("rejects an id that collides with a built-in kind, with a field path", () => {
    const r = parseImporterSpec({ ...EXAMPLE_IMPORTER_SPEC, id: "siem" });
    expect(r.ok).toBe(false);
    if (!r.ok) expect(r.errors.some((e) => e.path === "id")).toBe(true);
  });

  it("rejects a match with no discriminator", () => {
    const r = parseImporterSpec({ ...EXAMPLE_IMPORTER_SPEC, match: { format: "csv" } });
    expect(r.ok).toBe(false);
  });

  it("rejects a non-kebab id and missing required map fields", () => {
    expect(parseImporterSpec({ ...EXAMPLE_IMPORTER_SPEC, id: "Bad ID" }).ok).toBe(false);
    expect(parseImporterSpec({ ...EXAMPLE_IMPORTER_SPEC, map: { description: "x" } }).ok).toBe(false);
  });

  it("rejects unknown top-level keys (strict)", () => {
    expect(parseImporterSpec({ ...EXAMPLE_IMPORTER_SPEC, bogus: 1 }).ok).toBe(false);
  });
});
