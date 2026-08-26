import { describe, it, expect } from "vitest";
import {
  remainderNote,
  REMAINDER_VALUE_BUDGET,
  REMAINDER_OVERLAP,
} from "../../src/analysis/truncatedRemainder.js";

describe("remainderNote", () => {
  it("returns nothing when there is no dropped text", () => {
    expect(remainderNote("kept", "")).toBe("");
  });

  it("states the size of the cut even when the remainder holds no indicators", () => {
    // Silence would read as "nothing was lost". The analyst has to be able to tell an empty
    // remainder apart from one that was never looked at.
    const note = remainderNote("", "x".repeat(500));
    expect(note).toContain("500 more characters");
    expect(note).toContain("no indicators");
  });

  it("names the indicators the cut removed, grouped by type", () => {
    const note = remainderNote("", "beacon to c2-alpha.example.net and 203.0.113.77 every 60s");
    expect(note).toContain("c2-alpha.example.net");
    expect(note).toContain("203.0.113.77");
    expect(note).toContain("domain:");
    expect(note).toContain("ip:");
  });

  it("leads with network infrastructure, not with whatever the text mentioned first", () => {
    // The reported failure was a case with no C2 host in any readable event, so domains and IPs
    // must win the budget over hashes when the list has to be cut short.
    const note = remainderNote("", `hash ${"a".repeat(64)} then c2-beta.example.net`);
    expect(note.indexOf("c2-beta.example.net")).toBeLessThan(note.indexOf("a".repeat(64)));
  });

  it("bounds the list and says how many values it did not print", () => {
    const many = Array.from({ length: 400 }, (_, i) => `host${i}.example.net`).join(" ");
    const note = remainderNote("", many);
    expect(note.length).toBeLessThan(REMAINDER_VALUE_BUDGET + 200);
    expect(note).toMatch(/\+\d+ more/);
  });

  it("de-duplicates a value the remainder repeats", () => {
    const note = remainderNote("", "c2-gamma.example.net ... c2-gamma.example.net ... c2-gamma.example.net");
    expect(note.match(/c2-gamma\.example\.net/g)).toHaveLength(1);
  });

  // ── The cut lands mid-token. Neither side then holds the whole value: the kept text ends with a
  // dangling prefix, and scanning the dropped text alone yields a plausible-looking SUFFIX
  // ("dler.example.net") that never existed. A wrong indicator is worse than a missing one — an
  // analyst can pivot on it and find nothing, with no sign the value was ever cut in half.
  it("recovers an indicator the cut split in half", () => {
    const kept = `${"filler ".repeat(20)}c2-strad`;
    const dropped = "dler.example.net was the beacon target";
    const note = remainderNote(kept, dropped);
    expect(note).toContain("c2-straddler.example.net");
    expect(note).not.toContain("dler.example.net was"); // and not the bogus suffix on its own
  });

  it("does not invent a suffix when the cut splits an address", () => {
    const note = remainderNote(`${"filler ".repeat(20)}203.0.`, "113.77 was the exfil endpoint");
    expect(note).toContain("203.0.113.77");
  });

  it("does not repeat an indicator the kept text already shows in full", () => {
    // Budget spent on what the analyst can already read is budget stolen from what they cannot.
    const kept = `${"filler ".repeat(20)}already-visible.example.net`;
    const note = remainderNote(kept, " already-visible.example.net and only-cut.example.net");
    expect(note).not.toContain("already-visible.example.net");
    expect(note).toContain("only-cut.example.net");
  });

  it("looks back no further than the overlap window", () => {
    // The look-back exists to rejoin a split token, not to re-scan the whole kept message: a long
    // message would otherwise be scanned twice on every truncated row.
    const kept = `far-behind.example.net ${"x ".repeat(REMAINDER_OVERLAP)}`;
    const note = remainderNote(kept, " only-cut.example.net");
    expect(note).not.toContain("far-behind.example.net");
    expect(note).toContain("only-cut.example.net");
  });

  // ── The budget is a ceiling on the note, not a stop signal. A run of long URLs must not silence
  // every two-word domain behind it, or the note reports the least useful thing it found.
  function longUrls(n: number): string {
    return Array.from({ length: n }, (_, i) => `https://long${i}.example.com/${"p".repeat(240)}`).join(" ");
  }

  it("keeps listing shorter values after one too long to fit", () => {
    const note = remainderNote("", `${longUrls(4)} and c2-delta.example.net and 203.0.113.77`);
    expect(note).toContain("c2-delta.example.net");
    expect(note).toContain("203.0.113.77");
    expect(note.length).toBeLessThan(REMAINDER_VALUE_BUDGET + 200);
  });

  it("counts every value it skipped for size in the +N more tally", () => {
    const note = remainderNote("", `${longUrls(4)} and c2-delta.example.net`);
    expect(note).toContain("c2-delta.example.net");
    // Four long URLs cannot all fit in the budget, so at least one was skipped and must be counted.
    const more = Number(/\+(\d+) more/.exec(note)?.[1]);
    expect(more).toBeGreaterThan(0);
  });
});
