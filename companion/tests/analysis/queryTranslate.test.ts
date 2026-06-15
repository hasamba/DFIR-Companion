import { describe, it, expect } from "vitest";
import {
  queryTranslationResponseSchema,
  sanitizeQueryTranslations,
  sanitizeInterpretation,
  renderPlatformGuide,
  renderCaseDataSources,
  PLATFORM_LABELS,
  type RawQueryTranslation,
} from "../../src/analysis/queryTranslate.js";
import { HUNT_PLATFORMS, type HuntPlatform } from "../../src/analysis/huntPlatforms.js";
import type { InvestigationState } from "../../src/analysis/stateTypes.js";

const raw = (over: Partial<RawQueryTranslation>): RawQueryTranslation => ({
  platform: "velociraptor",
  label: "",
  query: "SELECT * FROM pslist()",
  explanation: "lists processes",
  caveats: "",
  notApplicable: false,
  ...over,
});

describe("sanitizeQueryTranslations", () => {
  it("keeps a valid query, falling back to the canonical label when blank", () => {
    const out = sanitizeQueryTranslations([raw({ label: "" })], [...HUNT_PLATFORMS]);
    expect(out).toHaveLength(1);
    expect(out[0].platform).toBe("velociraptor");
    expect(out[0].label).toBe(PLATFORM_LABELS.velociraptor);
    expect(out[0].notApplicable).toBe(false);
  });

  it("normalizes platform aliases to canonical keys (vql/kql/spl)", () => {
    const out = sanitizeQueryTranslations(
      [
        raw({ platform: "vql", query: "SELECT 1" }),
        raw({ platform: "KQL", query: "DeviceProcessEvents" }),
        raw({ platform: "spl", query: "index=*" }),
      ],
      [...HUNT_PLATFORMS],
    );
    expect(out.map((q) => q.platform)).toEqual(["velociraptor", "defender", "splunk"]);
  });

  it("drops platforms outside the allowed/requested set", () => {
    const out = sanitizeQueryTranslations(
      [raw({ platform: "splunk", query: "index=*" }), raw({ platform: "velociraptor", query: "SELECT 1" })],
      ["velociraptor"],
    );
    expect(out.map((q) => q.platform)).toEqual(["velociraptor"]);
  });

  it("dedupes by platform (first wins)", () => {
    const out = sanitizeQueryTranslations(
      [raw({ platform: "velociraptor", query: "FIRST" }), raw({ platform: "vql", query: "SECOND" })],
      [...HUNT_PLATFORMS],
    );
    expect(out).toHaveLength(1);
    expect(out[0].query).toBe("FIRST");
  });

  it("drops an entry that is neither a query nor an explained N/A", () => {
    expect(sanitizeQueryTranslations([raw({ query: "  ", notApplicable: false })], [...HUNT_PLATFORMS])).toHaveLength(0);
    // notApplicable but no explanation → still dropped (nothing useful to show)
    expect(
      sanitizeQueryTranslations([raw({ platform: "yara", query: "", explanation: "", notApplicable: true })], [...HUNT_PLATFORMS]),
    ).toHaveLength(0);
  });

  it("keeps an explained not-applicable entry and forces notApplicable on an empty query", () => {
    const out = sanitizeQueryTranslations(
      [raw({ platform: "yara", query: "", explanation: "YARA matches file content, not process behavior", notApplicable: true })],
      [...HUNT_PLATFORMS],
    );
    expect(out).toHaveLength(1);
    expect(out[0].platform).toBe("yara");
    expect(out[0].notApplicable).toBe(true);
    expect(out[0].query).toBe("");
  });

  it("sorts output into canonical platform display order regardless of input order", () => {
    const out = sanitizeQueryTranslations(
      [raw({ platform: "splunk", query: "a" }), raw({ platform: "velociraptor", query: "b" }), raw({ platform: "defender", query: "c" })],
      [...HUNT_PLATFORMS],
    );
    expect(out.map((q) => q.platform)).toEqual(["velociraptor", "defender", "splunk"]);
  });

  it("clamps over-long fields", () => {
    const out = sanitizeQueryTranslations(
      [raw({ query: "x".repeat(9000), explanation: "y".repeat(5000), caveats: "z".repeat(5000), label: "l".repeat(900) })],
      [...HUNT_PLATFORMS],
    );
    expect(out[0].query.length).toBeLessThanOrEqual(4000);
    expect(out[0].explanation.length).toBeLessThanOrEqual(1200);
    expect(out[0].caveats.length).toBeLessThanOrEqual(800);
    expect(out[0].label.length).toBeLessThanOrEqual(200);
  });

  it("returns [] for undefined / empty input", () => {
    expect(sanitizeQueryTranslations(undefined, [...HUNT_PLATFORMS])).toEqual([]);
    expect(sanitizeQueryTranslations([], [...HUNT_PLATFORMS])).toEqual([]);
  });
});

describe("renderPlatformGuide", () => {
  it("includes only the requested platforms, in canonical order, with label + schema hint", () => {
    const guide = renderPlatformGuide(["splunk", "velociraptor"] as HuntPlatform[]);
    const veloIdx = guide.indexOf("velociraptor");
    const splunkIdx = guide.indexOf("splunk");
    expect(veloIdx).toBeGreaterThanOrEqual(0);
    expect(splunkIdx).toBeGreaterThan(veloIdx); // canonical order: velociraptor before splunk
    expect(guide).toContain(PLATFORM_LABELS.velociraptor);
    expect(guide).toContain("pslist()");        // a velociraptor schema hint
    expect(guide).not.toContain("DeviceProcessEvents"); // defender not requested
  });

  it("falls back to ALL platforms when given an empty list", () => {
    const guide = renderPlatformGuide([]);
    for (const p of HUNT_PLATFORMS) expect(guide).toContain(p);
  });
});

describe("renderCaseDataSources", () => {
  const stateWith = (timeline: Array<{ sources?: string[] }>): InvestigationState =>
    ({ forensicTimeline: timeline } as unknown as InvestigationState);

  it("lists distinct tool sources from the timeline", () => {
    const text = renderCaseDataSources(
      stateWith([{ sources: ["Velociraptor", "Sysmon"] }, { sources: ["Sysmon", "Defender"] }, {}]),
    );
    expect(text).toContain("Velociraptor");
    expect(text).toContain("Sysmon");
    expect(text).toContain("Defender");
    // deduped — "Sysmon" appears once
    expect(text.match(/Sysmon/g)).toHaveLength(1);
  });

  it("returns a generic fallback when no sources are recorded", () => {
    expect(renderCaseDataSources(stateWith([{}, {}]))).toMatch(/no specific tool sources/i);
    expect(renderCaseDataSources(stateWith([]))).toMatch(/no specific tool sources/i);
  });
});

describe("sanitizeInterpretation", () => {
  it("collapses whitespace, trims, and clamps length", () => {
    expect(sanitizeInterpretation("  find   the\n\nthing  ")).toBe("find the thing");
    expect(sanitizeInterpretation("a".repeat(900)).length).toBe(600);
    expect(sanitizeInterpretation(undefined)).toBe("");
  });
});

describe("queryTranslationResponseSchema (lenient parsing)", () => {
  it("parses a well-formed response", () => {
    const parsed = queryTranslationResponseSchema.parse({
      interpretation: "find x",
      queries: [{ platform: "velociraptor", label: "L", query: "SELECT 1", explanation: "e", caveats: "c", notApplicable: false }],
    });
    expect(parsed.queries).toHaveLength(1);
    expect(parsed.interpretation).toBe("find x");
  });

  it("recovers from garbage with catch defaults instead of throwing", () => {
    const parsed = queryTranslationResponseSchema.parse({ interpretation: 42, queries: "nope" });
    expect(parsed.interpretation).toBe("");
    expect(parsed.queries).toEqual([]);
  });

  it("defaults missing per-entry fields", () => {
    const parsed = queryTranslationResponseSchema.parse({ queries: [{ platform: "splunk" }] });
    expect(parsed.queries[0].platform).toBe("splunk");
    expect(parsed.queries[0].query).toBe("");
    expect(parsed.queries[0].notApplicable).toBe(false);
  });
});
