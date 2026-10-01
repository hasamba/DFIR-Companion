import { describe, it, expect } from "vitest";
import { trimSentencePunctuation } from "../../src/ingest/textUriTrim.js";

// The match sits alone in its text unless a test says otherwise.
const trim = (m: string): string => trimSentencePunctuation(m, m, 0);

describe("trimSentencePunctuation: behaviour", () => {
  it("drops trailing prose punctuation", () => {
    expect(trim("http://a.example.com/x.,;:")).toBe("http://a.example.com/x");
  });

  it("keeps a trailing slash", () => {
    expect(trim("s3://bucket/prefix/")).toBe("s3://bucket/prefix/");
  });

  it("keeps a balanced IPv6 bracket and a balanced path parenthesis", () => {
    expect(trim("http://[2001:db8::1]")).toBe("http://[2001:db8::1]");
    expect(trim("http://a.example.com/a(foo)")).toBe("http://a.example.com/a(foo)");
  });

  it("drops an unbalanced closer and the punctuation around it", () => {
    expect(trim("http://a.example.com/a).")).toBe("http://a.example.com/a");
    expect(trim("http://a.example.com/a]")).toBe("http://a.example.com/a");
  });

  it("strips interleaved closers and punctuation of both kinds", () => {
    expect(trim("http://a.example.com/x).].);")).toBe("http://a.example.com/x");
  });

  it("stops at the first balanced closer after stripping unbalanced ones", () => {
    // The path opens one '(' — so after two extra ')' come off, the third is the URI's own.
    expect(trim("http://a.example.com/a(b)))")).toBe("http://a.example.com/a(b)");
    expect(trim("http://[2001:db8::1]]].")).toBe("http://[2001:db8::1]");
  });

  it("keeps everything when the URI is quote-delimited", () => {
    const text = "cp x 's3://bucket/evidence.)'";
    const m = "s3://bucket/evidence.)";
    expect(trimSentencePunctuation(m, text, text.indexOf(m))).toBe(m);
  });

  it("returns an empty match unchanged", () => {
    expect(trim("")).toBe("");
  });
});

describe("trimSentencePunctuation: linear time (#1908)", () => {
  // A hostile log line: a URL followed by tens of KB of closers. The old loop recounted the whole
  // string per stripped character — 40 K took ~8 s. Linear work finishes in milliseconds.
  for (const ch of [")", "]"]) {
    it(`strips 40 000 trailing '${ch}' well under a second`, () => {
      const url = "http://a.example.com/";
      const m = url + ch.repeat(40_000);
      const t0 = performance.now();
      const out = trim(m);
      const ms = performance.now() - t0;
      expect(out).toBe(url);
      expect(ms).toBeLessThan(1000);
    });
  }

  it("strips a long mixed run of closers and punctuation well under a second", () => {
    const url = "http://a.example.com/";
    const m = url + ").]".repeat(30_000);
    const t0 = performance.now();
    expect(trim(m)).toBe(url);
    expect(performance.now() - t0).toBeLessThan(1000);
  });
});
