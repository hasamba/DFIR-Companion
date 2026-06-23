import { describe, it, expect } from "vitest";
import {
  ALL_SECTION_KEYS,
  BUILT_IN_REPORT_TEMPLATES,
  DEFAULT_ACCENT,
  DEFAULT_COVER_TITLE,
  buildBrandingContext,
  defaultReportTemplate,
  isReportSectionEnabled,
  normalizeHexColor,
  normalizeReportTemplate,
  normalizeSections,
  orderedEnabledSections,
  renderTemplateString,
} from "../../src/reports/reportTemplate.js";
import { emptyReportMeta } from "../../src/reports/reportMeta.js";
import { emptyState } from "../../src/analysis/stateTypes.js";

describe("normalizeHexColor", () => {
  it("accepts #rrggbb and bare rrggbb, lowercasing", () => {
    expect(normalizeHexColor("#AABBCC")).toBe("#aabbcc");
    expect(normalizeHexColor("123abc")).toBe("#123abc");
  });
  it("falls back to the default for junk, 3-digit, named, or non-string", () => {
    expect(normalizeHexColor("#abc")).toBe(DEFAULT_ACCENT);
    expect(normalizeHexColor("red")).toBe(DEFAULT_ACCENT);
    expect(normalizeHexColor("'); DROP")).toBe(DEFAULT_ACCENT);
    expect(normalizeHexColor(42)).toBe(DEFAULT_ACCENT);
    expect(normalizeHexColor(undefined)).toBe(DEFAULT_ACCENT);
  });
});

describe("normalizeSections", () => {
  it("fills full canonical coverage when given nothing", () => {
    const s = normalizeSections(undefined);
    expect(s.map((x) => x.key)).toEqual([...ALL_SECTION_KEYS]);
    expect(s.every((x) => x.enabled)).toBe(true);
  });

  it("preserves provided order and appends missing keys (enabled) at the end", () => {
    const s = normalizeSections([
      { key: "conclusions", enabled: true },
      { key: "executiveSummary", enabled: false },
    ]);
    expect(s[0].key).toBe("conclusions");
    expect(s[1].key).toBe("executiveSummary");
    expect(s[1].enabled).toBe(false);
    // every canonical key is present exactly once
    expect(new Set(s.map((x) => x.key)).size).toBe(ALL_SECTION_KEYS.length);
    expect(s.length).toBe(ALL_SECTION_KEYS.length);
    // an appended (missing) key defaults to enabled
    expect(s.find((x) => x.key === "timeline")?.enabled).toBe(true);
  });

  it("drops unknown and duplicate keys", () => {
    const s = normalizeSections([
      { key: "bogus", enabled: true },
      { key: "glossary", enabled: false },
      { key: "glossary", enabled: true },
    ]);
    expect(s.filter((x) => x.key === "glossary").length).toBe(1);
    expect(s.find((x) => x.key === "glossary")?.enabled).toBe(false); // first wins
    expect(s.some((x) => (x.key as string) === "bogus")).toBe(false);
  });
});

describe("normalizeReportTemplate", () => {
  it("produces a safe default from empty input", () => {
    const t = normalizeReportTemplate({});
    expect(t.accentColor).toBe(DEFAULT_ACCENT);
    expect(t.coverTitle).toBe(DEFAULT_COVER_TITLE);
    expect(t.showLogo).toBe(true);
    expect(t.showCompanyName).toBe(true);
    expect(t.sections.length).toBe(ALL_SECTION_KEYS.length);
  });

  it("normalizes a malformed payload instead of throwing", () => {
    const t = normalizeReportTemplate({ name: "  My T  ", accentColor: "nope", sections: "bad", showLogo: "yes" });
    expect(t.name).toBe("My T");
    expect(t.accentColor).toBe(DEFAULT_ACCENT);
    expect(t.sections.length).toBe(ALL_SECTION_KEYS.length);
    expect(t.showLogo).toBe(true); // lenient .catch → default
  });
});

describe("built-in templates", () => {
  it("ships a byte-stable 'standard' default that mirrors the historical report", () => {
    const std = defaultReportTemplate();
    expect(std.id).toBe("standard");
    expect(std.accentColor).toBe(DEFAULT_ACCENT);
    expect(std.coverTitle).toBe(DEFAULT_COVER_TITLE);
    expect(std.headerText).toBe("");
    expect(std.footerText).toBe("");
    expect(orderedEnabledSections(std)).toEqual([...ALL_SECTION_KEYS]); // all on, canonical order
  });

  it("executive-brief enables only cover, summary, BIA, and conclusions", () => {
    const brief = BUILT_IN_REPORT_TEMPLATES.find((t) => t.id === "executive-brief")!;
    expect(orderedEnabledSections(brief)).toEqual([
      "titlePage",
      "executiveSummary",
      "businessImpact",
      "conclusions",
    ]);
  });
});

describe("isReportSectionEnabled", () => {
  it("is true for every section of the default template", () => {
    const std = defaultReportTemplate();
    for (const key of ALL_SECTION_KEYS) expect(isReportSectionEnabled(std, key)).toBe(true);
  });

  it("is false for a section explicitly disabled, true for an unlisted (defaulted) one", () => {
    const t = normalizeReportTemplate({ sections: [{ key: "executiveSummary", enabled: false }] });
    expect(isReportSectionEnabled(t, "executiveSummary")).toBe(false);
    expect(isReportSectionEnabled(t, "timeline")).toBe(true); // unlisted ⇒ enabled by default
  });

  it("reflects the executive-brief built-in (summary on, timeline off)", () => {
    const brief = BUILT_IN_REPORT_TEMPLATES.find((t) => t.id === "executive-brief")!;
    expect(isReportSectionEnabled(brief, "executiveSummary")).toBe(true);
    expect(isReportSectionEnabled(brief, "timeline")).toBe(false);
  });
});

describe("renderTemplateString", () => {
  const ctx = { organization: "ExampleCorp", incidentId: "INC-42", companyName: "" };

  it("substitutes known keys and blanks unknown ones", () => {
    expect(renderTemplateString("{{organization}} / {{missing}}", ctx)).toBe("ExampleCorp / ");
  });

  it("handles {{#if}} and {{#unless}} on truthiness", () => {
    expect(renderTemplateString("{{#if incidentId}}[{{incidentId}}]{{/if}}", ctx)).toBe("[INC-42]");
    expect(renderTemplateString("{{#if companyName}}X{{/if}}", ctx)).toBe("");
    expect(renderTemplateString("{{#unless companyName}}no firm{{/unless}}", ctx)).toBe("no firm");
  });

  it("supports nested blocks", () => {
    const out = renderTemplateString(
      "{{#if organization}}{{organization}}{{#if incidentId}} ({{incidentId}}){{/if}}{{/if}}",
      ctx,
    );
    expect(out).toBe("ExampleCorp (INC-42)");
  });

  it("does not re-scan substituted values for template syntax (no injection)", () => {
    const out = renderTemplateString("{{organization}}", { organization: "{{incidentId}}", incidentId: "SECRET" });
    expect(out).toBe("{{incidentId}}"); // literal, not expanded to SECRET
  });

  it("returns empty string for an empty template", () => {
    expect(renderTemplateString("", ctx)).toBe("");
  });
});

describe("buildBrandingContext", () => {
  it("derives placeholder values from state + meta", () => {
    const state = emptyState("case-7");
    state.updatedAt = "2026-06-10T08:30:00.000Z";
    const meta = emptyReportMeta();
    meta.organization = "ExampleCorp";
    meta.incidentId = "INC-42";
    meta.restrictions = "TLP:AMBER";
    meta.investigators = ["Jane Doe", "John Roe"];

    const ctx = buildBrandingContext(state, meta);
    expect(ctx.organization).toBe("ExampleCorp");
    expect(ctx.incidentId).toBe("INC-42");
    expect(ctx.tlp).toBe("TLP:AMBER");
    expect(ctx.investigators).toBe("Jane Doe, John Roe");
    expect(ctx.caseId).toBe("case-7");
    expect(ctx.date).toBe("2026-06-10");
  });

  it("treats the epoch default updatedAt as no date", () => {
    const ctx = buildBrandingContext(emptyState("c1"), emptyReportMeta());
    expect(ctx.date).toBe("");
  });
});
