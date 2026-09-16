// #1108: isPersistenceSniperRow / persistenceEntryFact are the pure, side-effect-free primitives
// collectionGenerationStore.ts uses to freeze a generation's own persistence inventory — kept
// separate from mapPersistenceSniper's own MappedEvent/IOC/severity synthesis.
import { describe, it, expect } from "vitest";
import { isPersistenceSniperRow, persistenceEntryFact } from "../../src/analysis/persistenceSniperImport.js";

const REAL_ROW = {
  Technique: "Run Key",
  Classification: "Suspicious",
  Path: "HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Run\\Updater",
  Value: "C:\\Users\\a\\AppData\\Local\\Temp\\updater.exe",
  "Access Gained": "User",
};

describe("isPersistenceSniperRow", () => {
  it("matches the module's own real 3-column signature", () => {
    expect(isPersistenceSniperRow(REAL_ROW)).toBe(true);
  });

  it("requires all three columns — a row missing one is not claimed", () => {
    const { Classification: _drop, ...withoutClassification } = REAL_ROW;
    expect(isPersistenceSniperRow(withoutClassification)).toBe(false);
    expect(isPersistenceSniperRow({})).toBe(false);
  });
});

describe("persistenceEntryFact", () => {
  it("extracts the bare {technique, path, value} fact, trimmed", () => {
    const row = { ...REAL_ROW, Technique: "  Run Key  ", Value: "  C:\\x.exe  " };
    expect(persistenceEntryFact(row)).toEqual({
      technique: "Run Key",
      path: "HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Run\\Updater",
      value: "C:\\x.exe",
    });
  });

  it("never synthesizes severity, IOCs, or a subject — only the three raw fields", () => {
    const fact = persistenceEntryFact(REAL_ROW);
    expect(Object.keys(fact).sort()).toEqual(["path", "technique", "value"]);
  });

  it("an entry with no Value falls back to an empty string, never the Path (unlike the mapper's own subject fallback)", () => {
    const { Value: _drop, ...withoutValue } = REAL_ROW;
    expect(persistenceEntryFact(withoutValue).value).toBe("");
  });
});
