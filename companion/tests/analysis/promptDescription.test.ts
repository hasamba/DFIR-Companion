import { describe, it, expect } from "vitest";
import { readFileSync, readdirSync } from "node:fs";
import { join } from "node:path";
import {
  promptDescription,
  PROMPT_DESCRIPTION_MAX,
  PROMPT_DESCRIPTION_TAIL,
} from "../../src/analysis/ai/promptDescription.js";
import { boundedTextTo } from "../../src/analysis/aggKey.js";
import { appendDerivedNote } from "../../src/analysis/derivedNote.js";

// The one description renderer every model-facing event row goes through (#959). Importers put
// their discriminators at the END of a long description — the bounded-key digest tail (#955), the
// derived note a correlation pass appends after up to 700 base characters (#939) — and a head-only
// slice showed the model two identical rows where storage held two distinct ones.

const LONG_PREFIX = "M365 FileDownloaded by user@x — /sites/Finance/Shared Documents/" + "Sub/".repeat(80);

describe("promptDescription", () => {
  it("leaves a description that fits the budget untouched", () => {
    expect(promptDescription("prefetch: EVIL.EXE")).toBe("prefetch: EVIL.EXE");
    const exact = "x".repeat(PROMPT_DESCRIPTION_MAX);
    expect(promptDescription(exact)).toBe(exact);
  });

  it("renders an empty or missing description as empty", () => {
    expect(promptDescription("")).toBe("");
    expect(promptDescription(undefined)).toBe("");
  });

  it("keeps the head AND the tail of a long description inside the same budget", () => {
    const text = "H".repeat(400) + "T".repeat(60);
    const out = promptDescription(text);
    expect(out.length).toBeLessThanOrEqual(PROMPT_DESCRIPTION_MAX);
    expect(out.startsWith("HHHH")).toBe(true);
    expect(out.endsWith("T".repeat(PROMPT_DESCRIPTION_TAIL))).toBe(true);
    expect(out).toContain(" … ");
  });

  it("carries a 17-char digest tail plus context (tail ≥ 36)", () => {
    expect(PROMPT_DESCRIPTION_TAIL).toBeGreaterThanOrEqual(36);
    const a = boundedTextTo(LONG_PREFIX + "Q3-forecast.xlsx", 600);
    const b = boundedTextTo(LONG_PREFIX + "Q4-forecast.xlsx", 600);
    expect(a).not.toBe(b); // storage keeps them apart …
    expect(promptDescription(a)).not.toBe(promptDescription(b)); // … and so does the model
    expect(promptDescription(a)).toContain(a.slice(-17));
  });

  it("honours a caller-chosen budget", () => {
    const text = "H".repeat(400) + "T".repeat(60);
    expect(promptDescription(text, 300).length).toBeLessThanOrEqual(300);
    expect(promptDescription(text, 300).length).toBeGreaterThan(PROMPT_DESCRIPTION_MAX);
  });

  it("keeps a derived note whole after a long base — a raised event always states its reason", () => {
    const raised = appendDerivedNote(
      LONG_PREFIX,
      "[confirmed exfiltration:",
      "staged 2 files then uploaded to mega.nz",
    );
    const out = promptDescription(raised);
    expect(out).toContain("[confirmed exfiltration: staged 2 files then uploaded to mega.nz]");
    expect(out.startsWith("M365 FileDownloaded")).toBe(true);
    expect(out.length).toBeLessThanOrEqual(PROMPT_DESCRIPTION_MAX);
  });

  it("keeps every earlier pass's note too", () => {
    const twice = appendDerivedNote(
      appendDerivedNote(LONG_PREFIX, "[initial access:", "phish landed 2m earlier"),
      "[confirmed exfiltration:",
      "upload followed",
    );
    const out = promptDescription(twice);
    expect(out).toContain("[initial access: phish landed 2m earlier]");
    expect(out).toContain("[confirmed exfiltration: upload followed]");
  });

  it("does not let an importer's own bracket pass as a note", () => {
    const text = "H".repeat(400) + " [risk: high]";
    const out = promptDescription(text);
    expect(out.length).toBeLessThanOrEqual(PROMPT_DESCRIPTION_MAX);
    expect(out.endsWith("[risk: high]")).toBe(true); // it is just the tail, kept as tail
  });
});

describe("no model-facing renderer keeps a private slice (#959 AC1)", () => {
  it("src/analysis/ai has no `description.slice(0, N)` left", () => {
    const dir = join(__dirname, "..", "..", "src", "analysis", "ai");
    const offenders = readdirSync(dir)
      .filter((f) => f.endsWith(".ts"))
      .flatMap((f) => {
        const lines = readFileSync(join(dir, f), "utf8").split("\n");
        return lines.flatMap((line, i) =>
          /description[^\n]*\.slice\(0,\s*\d+\)/.test(line) ? [`${f}:${i + 1}`] : [],
        );
      });
    expect(offenders).toEqual([]);
  });
});
