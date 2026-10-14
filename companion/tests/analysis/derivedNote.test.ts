import { describe, it, expect } from "vitest";
import { readFileSync, readdirSync } from "node:fs";
import { join } from "node:path";
import {
  appendDerivedNote,
  DERIVED_NOTE_BASE_CLIPS,
  DERIVED_NOTE_NAMES,
  DESCRIPTION_BASE_MAX,
  WIDE_DESCRIPTION_BASE_MAX,
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

describe("persistence executed note (#2082)", () => {
  it("is registered, so a later pass's clip keeps it intact", () => {
    expect(DERIVED_NOTE_NAMES).toContain("persistence executed");
    const first = appendDerivedNote("x".repeat(5000), "[persistence executed:", "runs the Run value 'u'");
    const second = appendDerivedNote(first, "[unexpected parent:", "started by winword.exe");
    expect(second).toContain("[persistence executed: runs the Run value 'u']");
  });
});

// #2186: eventRevision recognises a re-import of a row whose base a pass clipped by clipping the raw
// text at each registered cap. A pass that clips at an unregistered cap makes every plain re-import
// of a long annotated row look like a change, and writes a false "changed after first recorded"
// entry into the forensic record. So every cap a timeline pass passes must be a shared constant.
const CAP_NAMES = ["DESCRIPTION_BASE_MAX", "WIDE_DESCRIPTION_BASE_MAX"];

/** The top-level comma-separated arguments of the call whose "(" is at `open`. */
function callArgs(src: string, open: number): string[] {
  const args: string[] = [];
  let depth = 0;
  let start = open + 1;
  for (let i = open; i < src.length; i++) {
    const ch = src[i];
    if (ch === "(" || ch === "[" || ch === "{") depth++;
    else if (ch === ")" || ch === "]" || ch === "}") {
      depth--;
      if (depth === 0) {
        args.push(src.slice(start, i).trim());
        break;
      }
    } else if (ch === "," && depth === 1) {
      args.push(src.slice(start, i).trim());
      start = i + 1;
    }
  }
  return args.filter(Boolean);
}

describe("DERIVED_NOTE_BASE_CLIPS registry (#2186)", () => {
  it("lists the default and the wide cap", () => {
    expect(DERIVED_NOTE_BASE_CLIPS).toEqual([DESCRIPTION_BASE_MAX, WIDE_DESCRIPTION_BASE_MAX]);
  });

  it("every appendDerivedNote cap under src/analysis is a registered shared constant", () => {
    const dir = join(__dirname, "../../src/analysis");
    // binaryRenameImport clips at 600 at import time: the incoming row already carries its note, so
    // eventRevision compares the text plainly, and its base is pre-sliced to 600, so the clip is
    // idempotent. Registering 600 would widen the restatement match and hide a real extension.
    const exempt = new Set(["derivedNote.ts", "binaryRenameImport.ts"]);
    const bad: string[] = [];
    let checked = 0;
    for (const f of readdirSync(dir)) {
      if (!f.endsWith(".ts") || exempt.has(f)) continue;
      const src = readFileSync(join(dir, f), "utf8");
      for (const m of src.matchAll(/appendDerivedNote\(/g)) {
        const args = callArgs(src, m.index + m[0].length - 1);
        if (args.length < 4) continue;
        checked++;
        const cap = args[3];
        const shared = CAP_NAMES.includes(cap) && !new RegExp(`const ${cap}\\b`).test(src);
        if (!shared) bad.push(`${f}: ${cap}`);
      }
    }
    expect(checked).toBeGreaterThan(0);
    expect(bad).toEqual([]);
  });
});
