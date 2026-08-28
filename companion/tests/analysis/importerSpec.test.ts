import { describe, it, expect } from "vitest";
import {
  parseImporterSpec,
  EXAMPLE_IMPORTER_SPEC,
  IMPORT_KINDS,
  BUILTIN_KINDS,
} from "../../src/analysis/importerSpec.js";
import { detectImportKind } from "../../src/analysis/importDetect.js";

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

  // BUILTIN_KINDS and the ImportKind union were two hand-maintained copies of one list, and they
  // drifted: six detector kinds were missing from the guard, so a custom spec could claim one of
  // those ids and displace the built-in importer for every file that detected as it — silently,
  // because the collision check passed. They are one array now; this pins that.
  it("forbids EVERY detector kind as a custom id, including the six that had drifted", () => {
    for (const kind of ["okta", "gws", "hindsight", "macos", "leapp", "yara"]) {
      const r = parseImporterSpec({ ...EXAMPLE_IMPORTER_SPEC, id: kind });
      expect(r.ok, `custom id "${kind}" must not shadow the built-in kind`).toBe(false);
      if (!r.ok) expect(r.errors.some((e) => e.path === "id")).toBe(true);
    }
    for (const kind of IMPORT_KINDS) expect(BUILTIN_KINDS.has(kind)).toBe(true);
  });

  it("keeps every kind the detector can actually return inside the guard", () => {
    // Detection is the other half of the contract: a kind reachable from detectImportKind but
    // absent from BUILTIN_KINDS is exactly the hole the drift left open.
    const reached = [
      detectImportKind("hashes.csv", ["sha256", ...Array.from({ length: 12 }, (_, i) => `${i}`)].join("\n")),
      detectImportKind("audit.log", "type=SYSCALL msg=audit(1490451217.272:270): arch=c000003e"),
      detectImportKind("data.csv", "colA,colB\n1,2"),
    ];
    for (const kind of reached) expect(BUILTIN_KINDS.has(kind)).toBe(true);
  });
});
