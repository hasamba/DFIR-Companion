import { describe, it, expect } from "vitest";
import { readFileSync, readdirSync } from "node:fs";
import { join } from "node:path";
import {
  appendDerivedNote,
  DERIVED_NOTE_NAMES,
  DESCRIPTION_BASE_MAX,
} from "../../src/analysis/derivedNote.js";

describe("appendDerivedNote", () => {
  it("clips the base text and appends the note after it, never inside the clip", () => {
    const out = appendDerivedNote("x".repeat(5000), "[confirmed exfiltration:", "preceded by staging on h1");
    expect(out.length).toBeLessThan(DESCRIPTION_BASE_MAX + 100);
    expect(out.endsWith("[confirmed exfiltration: preceded by staging on h1]")).toBe(true);
  });

  it("keeps an earlier pass's note intact when a later pass clips the same long event", () => {
    const first = appendDerivedNote(
      "x".repeat(5000),
      "[confirmed exfiltration:",
      "preceded by staging on h1",
    );
    const second = appendDerivedNote(first, "[unexpected parent:", "started by winword.exe");
    expect(second).toContain("[confirmed exfiltration: preceded by staging on h1]");
    expect(second.endsWith("[unexpected parent: started by winword.exe]")).toBe(true);
    // The base was clipped once; the second pass did not grow it and did not clip the first note.
    expect(second.length).toBeLessThan(DESCRIPTION_BASE_MAX + 200);
  });

  it("leaves a short description untouched apart from the note", () => {
    expect(appendDerivedNote("Process created: lsass.exe", "[unexpected parent:", "winword.exe")).toBe(
      "Process created: lsass.exe [unexpected parent: winword.exe]",
    );
  });

  it("treats an importer's own bracket, like [risk: high], as base text, not as a note", () => {
    const base = `Entra sign-in: a@b [risk: high] ${"y".repeat(2000)}`;
    const out = appendDerivedNote(base, "[initial access:", "host contacted x");
    expect(out.length).toBeLessThan(DESCRIPTION_BASE_MAX + 100);
  });
});

// Every marker a pass appends must be in the registry, or a later pass's clip removes it again —
// the bug this module exists to prevent. Read the constants from source so a new marker cannot be
// added without being registered.
describe("DERIVED_NOTE_NAMES registry", () => {
  it("contains every *_MARKER / MARKER constant defined under src/analysis", () => {
    const dir = join(__dirname, "../../src/analysis");
    const found = new Set<string>();
    for (const f of readdirSync(dir)) {
      if (!f.endsWith(".ts")) continue;
      const src = readFileSync(join(dir, f), "utf8");
      for (const m of src.matchAll(/(?:^|\s)(?:export )?const [A-Z_]*MARKER = "\[([^\]:]+):";/gm))
        found.add(m[1]);
    }
    expect(found.size).toBeGreaterThan(5);
    for (const name of found) expect(DERIVED_NOTE_NAMES).toContain(name);
  });
});
