// #2912: a YARA hit's "Matched text" showed `%!s(uint8=000…)` — Velociraptor spread the matched
// bytes into one format argument each. New runs send hex; older rows are decoded from the debris.
// Redaction runs on the plain text, before invisible characters are escaped for display.
import { describe, expect, it } from "vitest";
import {
  bytesToText,
  escapeInvisible,
  legacyDebrisToBytes,
  matchedSnippet,
} from "../../src/analysis/aiAgentMatchedText.js";
import { yaraScopeVql } from "../../src/integrations/velociraptor/aiAgentArtifactVql.js";

const hex = (s: string) => Buffer.from(s, "utf8").toString("hex");
const pad = (n: number) => `${"0".repeat(200 - String(n).length)}${n}`;
// The exact shape Velociraptor 0.75.6 printed for a match (reproduced locally).
const debris = (text: string) => {
  const b = [...Buffer.from(text, "utf8")];
  const rest = b.slice(1).map((v) => `uint8=${v}`);
  return `%!s(uint8=${pad(b[0])})${rest.length ? `%!(EXTRA ${rest.join(", ")})` : ""}`;
};

describe("the run sends the matched bytes as hex", () => {
  it("formats String.Data as hex with its full length, never with %s", () => {
    const { hits } = yaraScopeVql("S0");
    expect(hits).toContain('format(format="%.200x", args=[str(str=String.Data)]) AS MatchedHex');
    expect(hits).toContain("len(list=String.Data) AS MatchedLength");
    expect(hits).not.toContain("args=[String.Data]");
  });
});

describe("matchedSnippet", () => {
  it("shows the matched text of a new row", () => {
    expect(matchedSnippet({ MatchedHex: hex("ignore previous"), MatchedLength: 15 })).toBe("ignore previous");
  });

  it("marks a match longer than the 200 bytes sent", () => {
    expect(matchedSnippet({ MatchedHex: hex("abc"), MatchedLength: 900 })).toBe("abc…");
  });

  it("makes invisible characters visible: bidi override, tag characters, NUL, newline", () => {
    expect(matchedSnippet({ MatchedHex: hex("a‮b\u{e0041}\u0000\n"), MatchedLength: 9 })).toBe(
      "a\\u{202e}b\\u{e0041}\\u{0}\\n",
    );
  });

  it("keeps a byte that is not valid UTF-8 instead of replacing it", () => {
    expect(bytesToText([0x61, 0xff, 0xe2, 0x80])).toBe("a\\x{ff}\\x{e2}\\x{80}");
  });

  it("decodes an older run's debris back to the text that matched", () => {
    expect(matchedSnippet({ MatchedText: debris("ignore previous") })).toBe("ignore previous");
    expect(matchedSnippet({ MatchedText: debris("‮") })).toBe("\\u{202e}");
    expect(matchedSnippet({ MatchedText: debris("x") })).toBe("x");
  });

  it("reads only whole tokens from debris the row cap cut off, and says it is partial", () => {
    const full = debris("ignore previous");
    const cutInToken = full.slice(0, full.indexOf("uint8=111") + "uint8=1".length); // inside "111"
    expect(legacyDebrisToBytes(cutInToken)).toEqual({ bytes: [105, 103, 110], partial: true });
    expect(matchedSnippet({ MatchedText: cutInToken })).toBe("ign…");
    // the cap cut inside the "%!(EXTRA " marker, right after the padded first byte
    expect(matchedSnippet({ MatchedText: full.slice(0, full.indexOf(")") + 4) })).toBe("i…");
  });

  it("refuses debris that breaks the grammar or names a byte over 255", () => {
    expect(legacyDebrisToBytes(`%!s(uint8=${pad(105)})%!(EXTRA uint8=300)`)).toBeUndefined();
    expect(legacyDebrisToBytes(`%!s(uint8=${pad(105)})garbage`)).toBeUndefined();
    expect(matchedSnippet({ MatchedText: `%!s(uint8=${pad(999)})` })).toBe(
      "matched bytes could not be read from this row",
    );
  });

  it("redacts secrets in the plain text, before escaping, in new and older rows", () => {
    const secret = 'cfg {"password": "hunter2hunter2"} end';
    expect(matchedSnippet({ MatchedHex: hex(secret), MatchedLength: secret.length })).toBe(
      'cfg {"password": "[redacted]"} end',
    );
    expect(matchedSnippet({ MatchedText: debris('token="abcdefghijkl"') })).toBe('token="[redacted]"');
  });

  it("redacts a secret cut off at the end of a partial match, whatever its length", () => {
    expect(matchedSnippet({ MatchedHex: hex("x password=abc"), MatchedLength: 400 })).toBe(
      "x password=[redacted]…",
    );
    expect(matchedSnippet({ MatchedHex: hex("x sk-ab"), MatchedLength: 400 })).toBe("x [redacted]…");
  });

  it("never cuts an escape in half when capping the display", () => {
    const s = matchedSnippet({ MatchedHex: hex("‮".repeat(60)), MatchedLength: 180 });
    expect(s.endsWith("…")).toBe(true);
    expect(s.slice(0, -1)).toMatch(/^(\\u\{202e\})+$/);
  });

  it("leaves a row with no match empty, and plain older text as it was", () => {
    expect(matchedSnippet({})).toBe("");
    expect(matchedSnippet({ MatchedText: "plain words" })).toBe("plain words");
    expect(escapeInvisible("tab\there")).toBe("tab\\there");
  });
});
