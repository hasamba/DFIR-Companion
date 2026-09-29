import { describe, it, expect } from "vitest";
import { createImportDebugRecorder, type ImportDebugRecorder } from "../../src/analysis/importDebug.js";
import {
  SIEM_FALLBACK_WARNING,
  importingDetail,
  isGuessedSiem,
  siemFallbackNotes,
  siemFallbackWarning,
} from "../../src/routes/importNotes.js";

// #1824: the #1795 warning, shared by every import path that detects a kind.
function detected(kind: string, confident: boolean): ImportDebugRecorder {
  const debug = createImportDebugRecorder();
  debug.detected(kind, { confident, decision: "test" });
  return debug;
}

describe("importNotes — the guessed-SIEM warning (#1824)", () => {
  it("flags only a non-confident siem detection", () => {
    expect(isGuessedSiem("siem", detected("siem", false))).toBe(true);
    expect(isGuessedSiem("siem", detected("siem", true))).toBe(false);
    expect(isGuessedSiem("thor", detected("thor", false))).toBe(false);
    expect(isGuessedSiem("siem", undefined)).toBe(false);
    expect(isGuessedSiem("siem", createImportDebugRecorder())).toBe(false); // no detection recorded
    expect(siemFallbackWarning("siem", detected("siem", false))).toEqual({ warning: SIEM_FALLBACK_WARNING });
  });

  it("appends the warning to the live status detail, which still starts with 'importing'", () => {
    const guessed = importingDetail("importing (siem)", "siem", detected("siem", false));
    expect(guessed).toBe(`importing (siem) — ${SIEM_FALLBACK_WARNING}`);
    expect(guessed).toMatch(/^importing\b/);
    expect(importingDetail("importing (siem)", "siem", detected("siem", true))).toBe("importing (siem)");
  });

  it("lists only the guessed files of a multi-file answer, and nothing when none was a guess", () => {
    const out = siemFallbackNotes([
      { file: "a.json", kind: "siem", debug: detected("siem", false) },
      { file: "b.json", kind: "siem", debug: detected("siem", true) },
      { file: "c.json", kind: "thor", debug: detected("thor", true) },
      { file: "d.json", kind: "siem", debug: detected("siem", false) },
    ]);
    expect(out).toEqual({
      warnings: [
        { file: "a.json", warning: SIEM_FALLBACK_WARNING },
        { file: "d.json", warning: SIEM_FALLBACK_WARNING },
      ],
    });
    expect(siemFallbackNotes([])).toEqual({});
    expect(siemFallbackNotes([{ file: "b.json", kind: "siem", debug: detected("siem", true) }])).toEqual({});
  });
});
