import { describe, expect, it } from "vitest";
import { loadDashboardModule } from "../helpers/dashboardModule.js";

// public/js/dashboard-ioc.js — IOC verdicts, de-duplication, display order and ATT&CK links (#415).

const ioc = loadDashboardModule("dashboard-ioc.js", ["dashboard-escape.js"]);

// "We looked and found nothing" and "we never looked" are different answers, and callers rely on
// the difference: `undefined` means unenriched, "unknown" means enriched-but-inconclusive.
describe("worstIocVerdict", () => {
  it("returns the worst verdict present, malicious first", () => {
    const enrichments = [{ verdict: "harmless" }, { verdict: "malicious" }, { verdict: "suspicious" }];
    expect(ioc.worstIocVerdict({ enrichments })).toBe("malicious");
    expect(ioc.worstIocVerdict({ enrichments: [{ verdict: "harmless" }, { verdict: "suspicious" }] })).toBe(
      "suspicious",
    );
  });

  it("distinguishes never-enriched from enriched-and-inconclusive", () => {
    expect(ioc.worstIocVerdict({})).toBeUndefined();
    expect(ioc.worstIocVerdict({ enrichments: [] })).toBeUndefined();
    expect(ioc.worstIocVerdict({ enrichments: [{ verdict: "unknown" }] })).toBe("unknown");
  });

  // indexOf returns -1 for a verdict outside the ranking, which sorts it ABOVE malicious. Recorded
  // because it means a provider inventing a new verdict string wins every comparison.
  it("ranks an unrecognised verdict above malicious", () => {
    expect(
      ioc.worstIocVerdict({ enrichments: [{ verdict: "malicious" }, { verdict: "catastrophic" }] }),
    ).toBe("catastrophic");
  });
});

describe("iocFlagged", () => {
  it("is true for malicious or suspicious, false otherwise", () => {
    expect(ioc.iocFlagged({ enrichments: [{ verdict: "malicious" }] })).toBe(true);
    expect(ioc.iocFlagged({ enrichments: [{ verdict: "suspicious" }] })).toBe(true);
    expect(ioc.iocFlagged({ enrichments: [{ verdict: "harmless" }, { verdict: "unknown" }] })).toBe(false);
    expect(ioc.iocFlagged({})).toBe(false);
  });
});

// The key falls back to type:value when there is no id, which is what makes two independently
// imported copies of the same indicator collapse into one row.
describe("dedupeIocsById", () => {
  it("keeps the first of each id, then of each type:value", () => {
    const out = ioc.dedupeIocsById([
      { id: "1", value: "a" },
      { id: "1", value: "b" },
      { type: "ip", value: "10.0.0.1" },
      { type: "ip", value: "10.0.0.1" },
    ]);
    expect(out).toHaveLength(2);
    expect(out[0].value).toBe("a");
  });

  it("treats the same value under different types as distinct", () => {
    expect(
      ioc.dedupeIocsById([
        { type: "domain", value: "x" },
        { type: "url", value: "x" },
      ]),
    ).toHaveLength(2);
  });

  it("returns a new array and leaves the input alone", () => {
    const input = [{ id: "1" }];
    expect(ioc.dedupeIocsById(input)).not.toBe(input);
  });
});

describe("sortIocsForDisplay", () => {
  it("sorts by type, then value case-insensitively", () => {
    const sorted = ioc.sortIocsForDisplay([
      { type: "ip", value: "b" },
      { type: "domain", value: "z" },
      { type: "ip", value: "A" },
    ]);
    expect(sorted.map((i: { type: string; value: string }) => `${i.type}:${i.value}`)).toEqual([
      "domain:z",
      "ip:A",
      "ip:b",
    ]);
  });

  it("does not mutate its input", () => {
    const input = [{ type: "b" }, { type: "a" }];
    expect(ioc.sortIocsForDisplay(input)).not.toBe(input);
    expect(input[0].type).toBe("b");
  });
});

describe("attackUrl", () => {
  it("builds a technique URL, and a sub-technique URL when given one", () => {
    expect(ioc.attackUrl("T1059")).toBe("https://attack.mitre.org/techniques/T1059/");
    expect(ioc.attackUrl("T1059.001")).toBe("https://attack.mitre.org/techniques/T1059/001/");
  });

  it("normalises case and surrounding whitespace", () => {
    expect(ioc.attackUrl("  t1059.001 ")).toBe("https://attack.mitre.org/techniques/T1059/001/");
  });

  it("returns null for anything that is not a technique id", () => {
    for (const bad of ["T105", "T10590", "TA0001", "1059", "", null]) expect(ioc.attackUrl(bad)).toBeNull();
  });
});

describe("mitreLinks", () => {
  it("links what it can and renders the rest as escaped text", () => {
    const html = ioc.mitreLinks(["T1059.001", "not-a-technique"]);
    expect(html).toContain('href="https://attack.mitre.org/techniques/T1059/001/"');
    expect(html).toContain('rel="noopener"');
    expect(html).toContain("not-a-technique");
    expect(html).not.toContain('href="https://attack.mitre.org/techniques/not');
  });

  it("escapes an id that is not a technique, since it reaches the page as text", () => {
    expect(ioc.mitreLinks(["<img src=x>"])).toBe("&lt;img src=x&gt;");
  });

  it("renders an empty string for no techniques", () => {
    expect(ioc.mitreLinks([])).toBe("");
    expect(ioc.mitreLinks(null)).toBe("");
  });
});

// Word-boundary matching against a free-text score, so "t1059" does not match inside "T10590".
// The tag is regex-escaped first, which matters because tags contain dots.
describe("scoreCoversTag", () => {
  it("matches on a word boundary, case-insensitively", () => {
    expect(ioc.scoreCoversTag("covers T1059 and more", "t1059")).toBe(true);
    expect(ioc.scoreCoversTag("T1059.001 specifically", "t1059.001")).toBe(true);
  });

  it("does not match inside a longer token", () => {
    expect(ioc.scoreCoversTag("T10590", "t1059")).toBe(false);
  });

  it("escapes regex metacharacters in the tag rather than interpreting them", () => {
    expect(ioc.scoreCoversTag("a.c", "a.c")).toBe(true);
    expect(ioc.scoreCoversTag("abc", "a.c")).toBe(false);
  });

  it("treats an empty tag as covered, so an untagged score is not reported as a gap", () => {
    expect(ioc.scoreCoversTag("anything", "")).toBe(true);
    expect(ioc.scoreCoversTag("anything", null)).toBe(true);
  });
});

describe("verdictColor", () => {
  it.each([
    ["malicious", "#ff6b6b"],
    ["suspicious", "#ffd93b"],
    ["harmless", "#6bcB77"],
    ["unknown", "#9aa4b2"],
    [undefined, "#9aa4b2"],
  ])("%s -> %s", (verdict, colour) => expect(ioc.verdictColor(verdict)).toBe(colour));
});

describe("enrichBadges", () => {
  const withEnrichment = (e: Record<string, unknown>) => ioc.enrichBadges({ enrichments: [e] });

  it("colours a badge by verdict and names the source", () => {
    const html = withEnrichment({ source: "virustotal", verdict: "malicious" });
    expect(html).toContain("virustotal");
    expect(html).toContain("#ff6b6b");
  });

  it("escapes a source name, which comes from provider configuration", () => {
    expect(withEnrichment({ source: '<img src=x onerror="x">', verdict: "unknown" })).not.toContain("<img");
  });

  // The same three-state distinction worstIocVerdict makes, rendered: absent means "not enriched
  // yet" and shows nothing, an empty array means "we asked and the providers had nothing" and says
  // so. Collapsing the two would tell an analyst an unchecked indicator was clean.
  it("separates not-yet-enriched from checked-and-empty", () => {
    expect(ioc.enrichBadges({})).toBe("");
    expect(ioc.enrichBadges({ enrichments: [] })).toContain("checked, no intel");
  });

  // The IP-context providers (reverse DNS, WHOIS, GeoIP, Shodan) all report verdict "unknown"
  // because they supply context rather than a threat call. When they returned data, the literal
  // word "unknown" is dropped so the badge reads as information and not as a failed lookup.
  it("omits the word unknown when an unknown-verdict provider returned data", () => {
    expect(withEnrichment({ source: "whois", verdict: "unknown", score: "AS13335" })).not.toContain(
      "unknown",
    );
    expect(withEnrichment({ source: "whois", verdict: "unknown", score: "AS13335" })).toContain(
      "whois: AS13335",
    );
    expect(withEnrichment({ source: "whois", verdict: "unknown" })).toContain("whois: unknown");
  });

  it("wraps the badge in a link when the provider gave one, escaping the URL", () => {
    const html = withEnrichment({ source: "vt", verdict: "malicious", link: 'https://x/"onmouseover=y' });
    expect(html).toContain('href="https://x/&quot;onmouseover=y"');
    expect(html).toContain('rel="noopener"');
  });

  // Tags already named in the score would read as duplicated, so they are dropped — and at most
  // three survive, which is a display cap rather than a data one.
  it("drops tags the score already covers and caps the rest at three", () => {
    const covered = withEnrichment({ source: "s", verdict: "malicious", score: "T1059", tags: ["T1059"] });
    expect(covered).not.toContain("—");
    const many = withEnrichment({ source: "s", verdict: "malicious", tags: ["t1", "t2", "t3", "t4"] });
    expect(many).toContain("— t1, t2, t3</span>");
    expect(many).not.toContain("t4");
  });
});
