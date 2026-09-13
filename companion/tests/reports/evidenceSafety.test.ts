import { describe, it, expect } from "vitest";
import {
  checkEvidenceSafety,
  evidenceSafetyActivity,
  evidenceSafetyLines,
  withEvidenceSafetyHtmlBanner,
  withEvidenceSafetyMarkdownBanner,
  EVIDENCE_SAFETY_BANNER_MAX,
} from "../../src/reports/evidenceSafety.js";
import { emptyState, type ForensicEvent, type InvestigationState } from "../../src/analysis/stateTypes.js";
import { CSP_NONCE_PLACEHOLDER } from "../../src/http/securityHeaders.js";

// #1006: the last check at the door of a human-readable export. It asks the finished output only
// about the case's own recorded values, so a template's legitimate link never trips it.

function ev(id: string, description: string, asset?: string): ForensicEvent {
  return {
    id,
    timestamp: "2026-05-01T00:00:00Z",
    description,
    severity: "High",
    asset,
    mitreTechniques: [],
    relatedFindingIds: [],
    sourceScreenshots: [],
  };
}

function caseWithIocs(): InvestigationState {
  const state = emptyState("c1");
  state.iocs.push(
    { id: "i1", type: "ip", value: "203.0.113.9", firstSeen: "2026-05-01T00:00:00Z" },
    { id: "i2", type: "domain", value: "evil.example", firstSeen: "2026-05-01T00:00:00Z" },
    { id: "i3", type: "url", value: "https://evil.example/drop.ps1", firstSeen: "2026-05-01T00:00:00Z" },
    { id: "i4", type: "other", value: "actor@evil.example", firstSeen: "2026-05-01T00:00:00Z" },
    { id: "i5", type: "hash", value: "d41d8cd98f00b204e9800998ecf8427e", firstSeen: "2026-05-01T00:00:00Z" },
  );
  return state;
}

describe("checkEvidenceSafety — live indicators", () => {
  it("passes a correctly defanged document", () => {
    const out =
      "Beacon to 203[.]0[.]113[.]9 then hxxps://evil[.]example/drop.ps1 from actor[@]evil[.]example; hash d41d8cd98f00b204e9800998ecf8427e";
    expect(checkEvidenceSafety(caseWithIocs(), out)).toEqual([]);
  });

  it("names every case IOC that reaches the output live", () => {
    const out = "Beacon to 203.0.113.9 then https://evil.example/drop.ps1 from actor@evil.example";
    const values = checkEvidenceSafety(caseWithIocs(), out).map((f) => f.value);
    expect(values).toEqual(
      expect.arrayContaining([
        "203.0.113.9",
        "evil.example",
        "https://evil.example/drop.ps1",
        "actor@evil.example",
      ]),
    );
    expect(values).not.toContain("d41d8cd98f00b204e9800998ecf8427e"); // a hash is not clickable
  });

  it("does not match an IP or a domain inside a longer token", () => {
    const state = emptyState("c1");
    state.iocs.push(
      { id: "i1", type: "ip", value: "10.0.0.1", firstSeen: "2026-05-01T00:00:00Z" },
      { id: "i2", type: "domain", value: "evil.example", firstSeen: "2026-05-01T00:00:00Z" },
    );
    expect(
      checkEvidenceSafety(state, "host 10.0.0.10 and 110.0.0.1; notevil.example; evil.example.net"),
    ).toEqual([]);
    // ...but a sentence-ending dot after the value is not part of it.
    expect(checkEvidenceSafety(state, "It called evil.example.").map((f) => f.value)).toEqual([
      "evil.example",
    ]);
  });

  it("reports each value once however often it appears", () => {
    const out = "203.0.113.9 203.0.113.9 203.0.113.9";
    expect(checkEvidenceSafety(caseWithIocs(), out)).toHaveLength(1);
  });
});

describe("checkEvidenceSafety — unescaped evidence", () => {
  it("passes when case markup is escaped or unicode-escaped", () => {
    const state = emptyState("c1");
    state.forensicTimeline.push(
      ev("e1", 'attack </script><script>alert(1)</script> <img src=x onerror="alert(2)">'),
    );
    const escaped =
      "attack &lt;/script&gt;&lt;script&gt;alert(1)&lt;/script&gt; &lt;img src=x onerror=&quot;alert(2)&quot;&gt;";
    const jsonEmbed =
      'attack \\u003c/script>\\u003cscript>alert(1)\\u003c/script> \\u003cimg src=x onerror="alert(2)">';
    expect(
      checkEvidenceSafety(state, `<html><script nonce="n">var x=1;</script>${escaped}${jsonEmbed}</html>`),
    ).toEqual([]);
  });

  it("names the raw script tag, handler and javascript: URL that survived", () => {
    const state = emptyState("c1");
    state.forensicTimeline.push(ev("e1", "attack <script>alert(1)</script>", "WIN-01"));
    state.findings.push({
      id: "f1",
      title: '<img src=x onerror="alert(2)">',
      description: "see javascript:alert(3) in the link",
      severity: "High",
      confidence: 50,
      mitreTechniques: [],
      relatedEventIds: [],
      relatedIocs: [],
      sourceScreenshots: [],
      firstSeen: "2026-05-01T00:00:00Z",
      lastUpdated: "2026-05-01T00:00:00Z",
      status: "open",
    });
    state.findings[0].description = 'see <a href="javascript:alert(3)">the link</a>';
    const out =
      '<p>attack <script>alert(1)</script></p><p><img src=x onerror="alert(2)"></p><a href="javascript:alert(3)">the link</a>';
    const found = checkEvidenceSafety(state, out);
    expect(found.every((f) => f.kind === "unescaped-evidence")).toBe(true);
    expect(found.map((f) => f.value)).toEqual(
      expect.arrayContaining([
        "<script>alert(1)",
        '<img src=x onerror="alert(2)">',
        '<a href="javascript:alert(3)">the link',
      ]),
    );
  });

  it("is not tripped by the template's own script tag or by plain evidence text", () => {
    const state = emptyState("c1");
    state.forensicTimeline.push(ev("e1", "powershell -enc AAAA ran on WIN-01"));
    const out = `<html><script nonce="${CSP_NONCE_PLACEHOLDER}">window.onload=function(){}</script><p>powershell -enc AAAA ran on WIN-01</p></html>`;
    expect(checkEvidenceSafety(state, out)).toEqual([]);
  });

  it("can be switched off for a plain-text format", () => {
    const state = emptyState("c1");
    state.forensicTimeline.push(ev("e1", "attack <script>alert(1)</script>"));
    expect(checkEvidenceSafety(state, "attack <script>alert(1)</script>", { unescaped: false })).toEqual([]);
    expect(checkEvidenceSafety(state, "attack <script>alert(1)</script>")).not.toEqual([]);
  });
});

describe("the warning", () => {
  const findings = checkEvidenceSafety(
    caseWithIocs(),
    "203.0.113.9 https://evil.example/drop.ps1 evil.example actor@evil.example",
  );

  it("names the values defanged, so the warning is not itself the leak", () => {
    const lines = evidenceSafetyLines(findings);
    expect(lines).toHaveLength(1);
    expect(lines[0]).toMatch(/^4 live indicator\(s\) not defanged: /);
    expect(lines[0]).toContain("203[.]0[.]113[.]9");
    expect(lines[0]).toContain("hxxps://evil[.]example/drop.ps1");
    expect(lines[0]).not.toContain("203.0.113.9");
    expect(lines[0]).not.toContain("https://");
  });

  it("caps the values it lists and counts the rest", () => {
    const state = emptyState("c1");
    const out: string[] = [];
    for (let i = 0; i < EVIDENCE_SAFETY_BANNER_MAX + 3; i++) {
      state.iocs.push({
        id: `i${i}`,
        type: "ip",
        value: `198.51.100.${i + 1}`,
        firstSeen: "2026-05-01T00:00:00Z",
      });
      out.push(`198.51.100.${i + 1}`);
    }
    const [line] = evidenceSafetyLines(checkEvidenceSafety(state, out.join(" ")));
    expect(line).toContain(`${EVIDENCE_SAFETY_BANNER_MAX + 3} live indicator(s)`);
    expect(line).toContain(", and 3 more");
  });

  it("stamps an HTML banner first under <body>, styled through the CSP nonce, and leaves a clean document alone", () => {
    const html = "<!doctype html>\n<html><head></head>\n<body>\n<main>x</main></body></html>";
    const stamped = withEvidenceSafetyHtmlBanner(html, findings);
    expect(stamped.indexOf('class="evidence-safety"')).toBeGreaterThan(stamped.indexOf("<body>"));
    expect(stamped.indexOf('class="evidence-safety"')).toBeLessThan(stamped.indexOf("<main>"));
    expect(stamped).toContain(`<style nonce="${CSP_NONCE_PLACEHOLDER}">`);
    expect(stamped).not.toMatch(/\sstyle\s*=/i);
    expect(stamped).toContain("Evidence-safety warning");
    expect(stamped).toContain("203[.]0[.]113[.]9");
    expect(withEvidenceSafetyHtmlBanner(html, [])).toBe(html);
  });

  it("escapes a raw markup fragment inside the HTML banner", () => {
    const state = emptyState("c1");
    state.forensicTimeline.push(ev("e1", "attack <script>alert(1)</script>"));
    const raw = "<body><p>attack <script>alert(1)</script></p></body>";
    const stamped = withEvidenceSafetyHtmlBanner(raw, checkEvidenceSafety(state, raw));
    const banner = stamped.slice(stamped.indexOf('class="evidence-safety"'), stamped.indexOf("</div>"));
    expect(banner).toContain("&lt;script&gt;alert(1)");
    expect(banner).not.toContain("<script>");
  });

  it("prepends a Markdown blockquote with each line as inline code, and leaves a clean document alone", () => {
    const md = "# Incident Report\n\nBody.";
    const stamped = withEvidenceSafetyMarkdownBanner(md, findings);
    expect(stamped.startsWith("> **")).toBe(true);
    expect(stamped).toContain("> - `4 live indicator(s) not defanged: ");
    expect(stamped.endsWith(md)).toBe(true);
    expect(withEvidenceSafetyMarkdownBanner(md, [])).toBe(md);
  });

  it("writes one activity line naming the format", () => {
    const entry = evidenceSafetyActivity("docx", evidenceSafetyLines(findings));
    expect(entry.category).toBe("export");
    expect(entry.action).toBe("evidence-safety-warning");
    expect(entry.detail).toMatch(/^docx export produced with a warning — 4 live indicator/);
  });
});
