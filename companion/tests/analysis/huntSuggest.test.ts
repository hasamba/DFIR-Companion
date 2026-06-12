import { describe, it, expect } from "vitest";
import { emptyState, type Finding, type IOC } from "../../src/analysis/stateTypes.js";
import {
  huntSuggestionsResponseSchema,
  sanitizeHuntSuggestions,
  renderHuntFindings,
  renderHuntIocs,
  hasHuntMaterial,
  HUNT_SUGGEST_MAX_DEFAULT,
  type HuntSuggestion,
} from "../../src/analysis/huntSuggest.js";

const NOW = "2026-06-10T00:00:00.000Z";

function finding(over: Partial<Finding> = {}): Finding {
  return {
    id: "f1",
    severity: "Critical",
    title: "Webshell dropped in web root",
    description: "ASPX webshell written to C:\\inetpub\\wwwroot\\shell.aspx",
    relatedIocs: [],
    sourceScreenshots: [],
    mitreTechniques: ["T1505.003"],
    firstSeen: NOW,
    lastUpdated: NOW,
    status: "open",
    ...over,
  };
}

function ioc(over: Partial<IOC> = {}): IOC {
  return { id: "i1", type: "file", value: "C:\\inetpub\\wwwroot\\shell.aspx", firstSeen: NOW, ...over };
}

function suggestion(over: Partial<HuntSuggestion> = {}): HuntSuggestion {
  return {
    title: "Hunt for ASPX webshells across web roots",
    rationale: "A webshell was found on one host; sweep the fleet for the same pattern.",
    vql: "SELECT FullPath, Mtime FROM glob(globs='C:/inetpub/wwwroot/**/*.aspx')",
    severity: "High",
    mitreTechniques: ["T1505.003"],
    relatedFindingIds: ["f1"],
    ...over,
  };
}

describe("huntSuggestionsResponseSchema", () => {
  it("parses a well-formed response", () => {
    const parsed = huntSuggestionsResponseSchema.parse({ suggestions: [suggestion()] });
    expect(parsed.suggestions).toHaveLength(1);
    expect(parsed.suggestions[0].vql).toContain("glob");
  });

  it("is lenient: a bad severity maps to the fallback, missing fields default", () => {
    const parsed = huntSuggestionsResponseSchema.parse({
      suggestions: [{ title: "x", vql: "SELECT * FROM pslist()", severity: "Catastrophic" }],
    });
    expect(parsed.suggestions[0].severity).toBe("Medium"); // unknown enum → fallback
    expect(parsed.suggestions[0].rationale).toBe("");        // missing → ""
    expect(parsed.suggestions[0].mitreTechniques).toEqual([]);
  });

  it("defaults suggestions to [] when the field is absent or wrong-typed", () => {
    expect(huntSuggestionsResponseSchema.parse({}).suggestions).toEqual([]);
    expect(huntSuggestionsResponseSchema.parse({ suggestions: "nope" }).suggestions).toEqual([]);
  });
});

describe("sanitizeHuntSuggestions", () => {
  it("drops suggestions with no VQL or no title", () => {
    const out = sanitizeHuntSuggestions([
      suggestion(),
      suggestion({ vql: "   " }),       // empty query → dropped
      suggestion({ title: "" }),         // empty title → dropped
    ]);
    expect(out).toHaveLength(1);
  });

  it("trims fields, dedupes technique/finding ids, and caps lengths", () => {
    const out = sanitizeHuntSuggestions([
      suggestion({
        title: "  Spaced title  ",
        mitreTechniques: ["T1059", "T1059", " T1003 "],
        relatedFindingIds: ["f1", "f1"],
      }),
    ]);
    expect(out[0].title).toBe("Spaced title");
    expect(out[0].mitreTechniques).toEqual(["T1059", "T1003"]);
    expect(out[0].relatedFindingIds).toEqual(["f1"]);
  });

  it("caps the number of suggestions", () => {
    const many = Array.from({ length: 20 }, (_, i) => suggestion({ title: `h${i}` }));
    expect(sanitizeHuntSuggestions(many, 3)).toHaveLength(3);
    expect(sanitizeHuntSuggestions(many)).toHaveLength(HUNT_SUGGEST_MAX_DEFAULT);
  });

  it("handles undefined input", () => {
    expect(sanitizeHuntSuggestions(undefined)).toEqual([]);
  });

  it("truncates a runaway VQL blob", () => {
    const out = sanitizeHuntSuggestions([suggestion({ vql: "SELECT * FROM scope() -- " + "x".repeat(8000) })]);
    expect(out[0].vql.length).toBeLessThanOrEqual(4000);
  });
});

describe("renderHuntFindings", () => {
  it("renders id, severity, MITRE and title for non-dismissed findings", () => {
    const text = renderHuntFindings([finding(), finding({ id: "f2", status: "dismissed", title: "ruled out" })]);
    expect(text).toContain("[f1]");
    expect(text).toContain("T1505.003");
    expect(text).toContain("Webshell");
    expect(text).not.toContain("ruled out"); // dismissed excluded
  });

  it("returns a placeholder when there are no findings", () => {
    expect(renderHuntFindings([])).toBe("(no findings yet)");
  });
});

describe("renderHuntIocs", () => {
  it("groups pivotable IOCs by type and skips non-pivotable ones", () => {
    const text = renderHuntIocs([
      ioc({ id: "i1", type: "hash", value: "abc123" }),
      ioc({ id: "i2", type: "process", value: "evil.exe" }),
      ioc({ id: "i3", type: "other", value: "something" }), // skipped
    ]);
    expect(text).toContain("hash: abc123");
    expect(text).toContain("process: evil.exe");
    expect(text).not.toContain("something");
  });

  it("returns a placeholder when no pivotable IOCs exist", () => {
    expect(renderHuntIocs([ioc({ type: "other" })])).toBe("(no pivotable IOCs)");
  });
});

describe("hasHuntMaterial", () => {
  it("is false on an empty case, true once a finding or event exists", () => {
    const empty = emptyState("c1");
    expect(hasHuntMaterial(empty)).toBe(false);

    const withFinding = { ...empty, findings: [finding()] };
    expect(hasHuntMaterial(withFinding)).toBe(true);

    const onlyDismissed = { ...empty, findings: [finding({ status: "dismissed" })] };
    expect(hasHuntMaterial(onlyDismissed)).toBe(false);

    const withEvent = {
      ...empty,
      forensicTimeline: [{ id: "e1", timestamp: NOW, description: "x", severity: "High" as const, mitreTechniques: [], relatedFindingIds: [], sourceScreenshots: [] }],
    };
    expect(hasHuntMaterial(withEvent)).toBe(true);
  });
});
