import { describe, it, expect } from "vitest";
import { remainderNote, REMAINDER_VALUE_BUDGET } from "../../src/analysis/truncatedRemainder.js";

describe("remainderNote", () => {
  it("returns nothing when there is no dropped text", () => {
    expect(remainderNote("")).toBe("");
  });

  it("states the size of the cut even when the remainder holds no indicators", () => {
    // Silence would read as "nothing was lost". The analyst has to be able to tell an empty
    // remainder apart from one that was never looked at.
    const note = remainderNote("x".repeat(500));
    expect(note).toContain("500 more characters");
    expect(note).toContain("no indicators");
  });

  it("names the indicators the cut removed, grouped by type", () => {
    const note = remainderNote("beacon to c2-alpha.example.net and 203.0.113.77 every 60s");
    expect(note).toContain("c2-alpha.example.net");
    expect(note).toContain("203.0.113.77");
    expect(note).toContain("domain:");
    expect(note).toContain("ip:");
  });

  it("leads with network infrastructure, not with whatever the text mentioned first", () => {
    // The reported failure was a case with no C2 host in any readable event, so domains and IPs
    // must win the budget over hashes when the list has to be cut short.
    const note = remainderNote(`hash ${"a".repeat(64)} then c2-beta.example.net`);
    expect(note.indexOf("c2-beta.example.net")).toBeLessThan(note.indexOf("a".repeat(64)));
  });

  it("bounds the list and says how many values it did not print", () => {
    const many = Array.from({ length: 400 }, (_, i) => `host${i}.example.net`).join(" ");
    const note = remainderNote(many);
    expect(note.length).toBeLessThan(REMAINDER_VALUE_BUDGET + 200);
    expect(note).toMatch(/\+\d+ more/);
  });

  it("de-duplicates a value the remainder repeats", () => {
    const note = remainderNote("c2-gamma.example.net ... c2-gamma.example.net ... c2-gamma.example.net");
    expect(note.match(/c2-gamma\.example\.net/g)).toHaveLength(1);
  });
});
