import { describe, it, expect } from "vitest";
import {
  isMentionedIoc,
  mentionedNote,
  mentionedSuffix,
  MENTIONED_NOTE,
  mentionedLabel,
  iocValueLabel,
} from "../../src/analysis/iocMentioned.js";
import type { IOC } from "../../src/analysis/stateTypes.js";

// #1461. A network IOC whose value came from FREE TEXT (a command line, a script block, a message)
// is a lead the loader was TOLD about, not an address the host CONTACTED. Every network consumer
// that renders such an IOC goes through these helpers so the wording lives in one place.

function ioc(over: Partial<IOC>): IOC {
  return { id: "i1", type: "ip", value: "91.191.209.46", firstSeen: "", ...over };
}

describe("iocMentioned (#1461)", () => {
  it("isMentionedIoc is true only for a network IOC with the exact `mentioned` provenance", () => {
    expect(isMentionedIoc(ioc({ provenance: "mentioned" }))).toBe(true);
    expect(isMentionedIoc(ioc({ type: "domain", value: "evil.example", provenance: "mentioned" }))).toBe(
      true,
    );
    expect(
      isMentionedIoc(ioc({ type: "url", value: "http://evil.example/x", provenance: "mentioned" })),
    ).toBe(true);
    // A mentioned hash has its own words (iocMentionedHash.ts, #1459) — never "no network record".
    expect(isMentionedIoc(ioc({ type: "hash", value: "a".repeat(64), provenance: "mentioned" }))).toBe(false);
    expect(isMentionedIoc(ioc({}))).toBe(false);
    expect(isMentionedIoc(ioc({ provenance: "client-reported" }))).toBe(false);
    expect(isMentionedIoc(undefined)).toBe(false);
  });

  it("the note says what the IOC is and what it is not", () => {
    expect(MENTIONED_NOTE).toBe("referenced in free text; no network record");
    expect(mentionedNote(ioc({ provenance: "mentioned" }))).toBe(MENTIONED_NOTE);
    expect(mentionedNote(ioc({}))).toBe("");
  });

  it("the suffix is the parenthesised note for a table cell, empty otherwise", () => {
    expect(mentionedSuffix(ioc({ provenance: "mentioned" }))).toBe(` (${MENTIONED_NOTE})`);
    expect(mentionedSuffix(ioc({}))).toBe("");
    expect(mentionedSuffix(ioc({ provenance: "client-reported" }))).toBe("");
  });
});

describe("iocMentioned labels (#1461)", () => {
  it("mentionedLabel appends the note only when the derived flag is set", () => {
    expect(mentionedLabel("91.191.209.46", true)).toBe(`91.191.209.46 (${MENTIONED_NOTE})`);
    expect(mentionedLabel("203.0.113.5", undefined)).toBe("203.0.113.5");
    expect(mentionedLabel("203.0.113.5", false)).toBe("203.0.113.5");
  });

  it("iocValueLabel keeps the #1266 client-reported suffix and adds the #1461 note", () => {
    expect(iocValueLabel({ type: "ip", value: "1.2.3.4", provenance: "client-reported" })).toBe(
      "1.2.3.4 (client-reported)",
    );
    expect(iocValueLabel({ type: "ip", value: "1.2.3.4", provenance: "mentioned" })).toBe(
      `1.2.3.4 (${MENTIONED_NOTE})`,
    );
    expect(iocValueLabel({ type: "ip", value: "1.2.3.4" })).toBe("1.2.3.4");
    expect(iocValueLabel({ type: "hash", value: "abc", provenance: "mentioned" })).toBe("abc");
  });
});
